"""Locally signed run receipts with a separately shareable public key.

The key is host-owned. A signature proves possession of that key, not TPM
protection, independent timestamping, or an externally trusted identity.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_or_create_signing_key(private_path: Path, public_path: Path) -> Ed25519PrivateKey:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
        with private_path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            private_path.chmod(0o600)
    except FileExistsError:
        raw = private_path.read_bytes()
        if len(raw) != 32:
            raise ValueError("signing key must be 32 bytes")
        key = Ed25519PrivateKey.from_private_bytes(raw)
    public_hex = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    try:
        with public_path.open("x", encoding="ascii") as stream:
            stream.write(public_hex + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if public_path.read_text(encoding="ascii").strip() != public_hex:
            raise ValueError("public key does not match private signing key")
    return key


def build_receipt_payload(*, run_id: str, audit_verification: Mapping[str, object],
                          layers: object, fixture_sha256: str, audit_sha256: str) -> dict[str, object]:
    if audit_verification.get("valid") is not True:
        raise ValueError("cannot sign an invalid audit chain")
    return {
        "schema": 1, "run_id": run_id,
        "audit_head_mac": audit_verification["head_mac"],
        "audit_records": audit_verification["records_checked"],
        "audit_sha256": audit_sha256,
        "layer_report_sha256": hashlib.sha256(_canonical(layers)).hexdigest(),
        "fixture_sha256": fixture_sha256,
    }


def sign_receipt(*, payload: Mapping[str, object], private_path: Path,
                 public_path: Path, receipt_path: Path) -> dict[str, object]:
    key = load_or_create_signing_key(private_path, public_path)
    public_hex = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    receipt = {
        "payload": dict(payload), "public_key_hex": public_hex,
        "key_fingerprint_sha256": hashlib.sha256(bytes.fromhex(public_hex)).hexdigest(),
        "signature_hex": key.sign(_canonical(payload)).hex(),
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt_path.with_suffix(".tmp")
    with temporary.open("wb") as stream:
        stream.write(_canonical(receipt) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, receipt_path)
    return receipt


def verify_signed_receipt(receipt: Mapping[str, object], *,
                          expected_public_key_hex: str | None = None,
                          expected_payload: Mapping[str, object] | None = None) -> dict[str, object]:
    try:
        public_hex = receipt["public_key_hex"]
        signature_hex = receipt["signature_hex"]
        payload = receipt["payload"]
        if not isinstance(public_hex, str) or not isinstance(signature_hex, str) or not isinstance(payload, dict):
            raise ValueError("invalid receipt fields")
        public_raw = bytes.fromhex(public_hex)
        signature = bytes.fromhex(signature_hex)
        if len(public_raw) != 32 or len(signature) != 64 or payload.get("schema") != 1:
            raise ValueError("invalid receipt format")
        if receipt.get("key_fingerprint_sha256") != hashlib.sha256(public_raw).hexdigest():
            raise ValueError("key fingerprint mismatch")
        if expected_public_key_hex is not None and public_hex != expected_public_key_hex:
            raise ValueError("unexpected signing key")
        if expected_payload is not None and payload != dict(expected_payload):
            raise ValueError("receipt payload does not match run evidence")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _canonical(payload))
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return {"valid": False, "failure": "SIGNATURE_OR_PAYLOAD_INVALID"}
    return {"valid": True, "key_fingerprint_sha256": receipt["key_fingerprint_sha256"]}
