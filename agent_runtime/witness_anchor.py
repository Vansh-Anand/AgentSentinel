"""Optional independent witness for an exported AgentSentinel run receipt.

Run the issuing command on a separately administered host. A local test of
this protocol proves its verification behavior, not independent key custody.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signing import _canonical, load_or_create_signing_key
from .verify_public import verify_public_run


_SCHEMA = "agentsentinel-witness-v1"
_ZERO_HASH = "0" * 64


def _receipt_paths(run_id: str, evidence_dir: Path) -> tuple[Path, Path]:
    safe_id = str(uuid.UUID(run_id))
    return (evidence_dir / "runtime-receipts" / f"{safe_id}.json",
            evidence_dir / "runtime-audit" / f"{safe_id}.jsonl")


def _entry_hash(proof: dict[str, object]) -> str:
    return hashlib.sha256(_canonical({
        "entry": proof["entry"], "signature_hex": proof["signature_hex"],
    })).hexdigest()


def _verify_proof_signature(proof: dict[str, object], pinned_witness_key_hex: str) -> None:
    if not isinstance(proof, dict) or proof.get("schema") != _SCHEMA \
            or proof.get("witness_public_key_hex") != pinned_witness_key_hex:
        raise ValueError("WITNESS_KEY_OR_SCHEMA_MISMATCH")
    entry = proof["entry"]
    if not isinstance(entry, dict) or entry.get("schema") != _SCHEMA:
        raise ValueError("WITNESS_ENTRY_INVALID")
    key_bytes = bytes.fromhex(pinned_witness_key_hex)
    signature = bytes.fromhex(proof["signature_hex"])
    if len(key_bytes) != 32 or len(signature) != 64:
        raise ValueError("WITNESS_SIGNATURE_FORMAT")
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, _canonical(entry))
    except InvalidSignature as exc:
        raise ValueError("WITNESS_SIGNATURE_INVALID") from exc
    if proof.get("entry_hash") != _entry_hash(proof):
        raise ValueError("WITNESS_ENTRY_HASH_MISMATCH")


def _connect_ledger(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("""CREATE TABLE IF NOT EXISTS anchors (
        sequence INTEGER PRIMARY KEY,
        run_id TEXT UNIQUE NOT NULL,
        entry_hash TEXT NOT NULL,
        proof_json TEXT NOT NULL
    )""")
    return connection


def _check_ledger(connection: sqlite3.Connection, pinned_witness_key_hex: str) -> tuple[int, str]:
    previous = _ZERO_HASH
    count = 0
    for sequence, run_id, digest, proof_json in connection.execute(
            "SELECT sequence, run_id, entry_hash, proof_json FROM anchors ORDER BY sequence"):
        proof = json.loads(proof_json)
        _verify_proof_signature(proof, pinned_witness_key_hex)
        entry = proof["entry"]
        if (sequence != count + 1 or entry.get("sequence") != sequence
                or entry.get("previous_hash") != previous
                or entry.get("run_id") != run_id or digest != proof["entry_hash"]):
            raise ValueError("WITNESS_LEDGER_CHAIN_INVALID")
        previous = digest
        count += 1
    return count, previous


def issue_anchor(run_id: str, evidence_dir: Path, pinned_api_key_hex: str,
                 witness_dir: Path, output_path: Path) -> dict[str, object]:
    """Verify exported evidence, then append and sign one witness statement."""
    safe_id = str(uuid.UUID(run_id))
    witness_root = witness_dir.resolve()
    evidence_root = evidence_dir.resolve()
    if witness_root.is_relative_to(evidence_root) or evidence_root.is_relative_to(witness_root):
        raise ValueError("witness state must be outside the exported evidence directory")
    source = verify_public_run(safe_id, evidence_dir, pinned_api_key_hex)
    if source.get("valid") is not True:
        raise ValueError(f"SOURCE_EVIDENCE_INVALID:{source.get('failure', 'unknown')}")
    receipt_path, audit_path = _receipt_paths(safe_id, evidence_dir)
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    audit_digest = hashlib.sha256(audit_path.read_bytes()).hexdigest()
    if receipt["payload"].get("audit_sha256") != audit_digest:
        raise ValueError("AUDIT_DIGEST_MISMATCH")

    key = load_or_create_signing_key(witness_dir / "witness-key.ed25519",
                                     witness_dir / "witness-key.pub")
    public_hex = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    ledger_path = witness_dir / "anchors.sqlite"
    with closing(_connect_ledger(ledger_path)) as ledger:
        with ledger:
            ledger.execute("BEGIN IMMEDIATE")
            count, previous = _check_ledger(ledger, public_hex)
            existing = ledger.execute("SELECT proof_json FROM anchors WHERE run_id=?", (safe_id,)).fetchone()
            if existing:
                proof = json.loads(existing[0])
                entry = proof["entry"]
                if (entry["receipt_sha256"] != hashlib.sha256(receipt_bytes).hexdigest()
                        or entry["audit_sha256"] != audit_digest):
                    raise ValueError("RUN_ALREADY_ANCHORED_WITH_DIFFERENT_EVIDENCE")
            else:
                entry = {
                    "schema": _SCHEMA, "sequence": count + 1,
                    "previous_hash": previous, "run_id": safe_id,
                    "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                    "audit_sha256": audit_digest,
                    "api_key_fingerprint_sha256": source["key_fingerprint_sha256"],
                    "witnessed_at": datetime.now(timezone.utc).isoformat(),
                }
                proof = {
                    "schema": _SCHEMA, "entry": entry,
                    "witness_public_key_hex": public_hex,
                    "signature_hex": key.sign(_canonical(entry)).hex(),
                }
                proof["entry_hash"] = _entry_hash(proof)
                ledger.execute(
                    "INSERT INTO anchors(sequence,run_id,entry_hash,proof_json) VALUES (?,?,?,?)",
                    (entry["sequence"], safe_id, proof["entry_hash"], json.dumps(proof, sort_keys=True)),
                )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as stream:
        stream.write(_canonical(proof) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return proof


def verify_anchor(run_id: str, evidence_dir: Path, proof_path: Path,
                  pinned_api_key_hex: str, pinned_witness_key_hex: str,
                  *, witness_ledger: Path | None = None) -> dict[str, object]:
    """Verify API evidence and a separately pinned witness signature offline."""
    try:
        safe_id = str(uuid.UUID(run_id))
        source = verify_public_run(safe_id, evidence_dir, pinned_api_key_hex)
        if source.get("valid") is not True:
            raise ValueError("SOURCE_EVIDENCE_INVALID")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        _verify_proof_signature(proof, pinned_witness_key_hex)
        entry = proof["entry"]
        receipt_path, audit_path = _receipt_paths(safe_id, evidence_dir)
        if (entry.get("run_id") != safe_id
                or entry.get("receipt_sha256") != hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                or entry.get("audit_sha256") != hashlib.sha256(audit_path.read_bytes()).hexdigest()
                or entry.get("api_key_fingerprint_sha256") != source["key_fingerprint_sha256"]):
            raise ValueError("WITNESS_EVIDENCE_MISMATCH")
        if not isinstance(entry.get("sequence"), int) or entry["sequence"] < 1:
            raise ValueError("WITNESS_SEQUENCE_INVALID")
        timestamp = datetime.fromisoformat(entry["witnessed_at"])
        if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
            raise ValueError("WITNESS_TIMESTAMP_NOT_UTC")
        if witness_ledger is not None:
            if not witness_ledger.is_file():
                raise ValueError("WITNESS_LEDGER_MISSING")
            with closing(_connect_ledger(witness_ledger)) as ledger:
                _check_ledger(ledger, pinned_witness_key_hex)
                row = ledger.execute("SELECT proof_json FROM anchors WHERE run_id=?", (safe_id,)).fetchone()
                if row is None or json.loads(row[0]) != proof:
                    raise ValueError("WITNESS_LEDGER_PROOF_MISMATCH")
        return {"valid": True, "sequence": entry["sequence"],
                "witnessed_at": entry["witnessed_at"], "entry_hash": proof["entry_hash"]}
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return {"valid": False, "failure": str(exc)[:100]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    issue = subcommands.add_parser("issue")
    issue.add_argument("run_id")
    issue.add_argument("--evidence-dir", type=Path, required=True)
    issue.add_argument("--api-key-file", type=Path, required=True)
    issue.add_argument("--witness-dir", type=Path, required=True)
    issue.add_argument("--output", type=Path, required=True)
    check = subcommands.add_parser("verify")
    check.add_argument("run_id")
    check.add_argument("--evidence-dir", type=Path, required=True)
    check.add_argument("--proof", type=Path, required=True)
    check.add_argument("--api-key-file", type=Path, required=True)
    check.add_argument("--witness-key-file", type=Path, required=True)
    check.add_argument("--witness-ledger", type=Path)
    args = parser.parse_args()
    api_key = args.api_key_file.read_text(encoding="ascii").strip()
    if args.action == "issue":
        try:
            proof = issue_anchor(args.run_id, args.evidence_dir, api_key,
                                 args.witness_dir, args.output)
            result = {"valid": True, "sequence": proof["entry"]["sequence"],
                      "entry_hash": proof["entry_hash"]}
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
            result = {"valid": False, "failure": str(exc)[:100]}
    else:
        witness_key = args.witness_key_file.read_text(encoding="ascii").strip()
        result = verify_anchor(args.run_id, args.evidence_dir, args.proof,
                               api_key, witness_key, witness_ledger=args.witness_ledger)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
