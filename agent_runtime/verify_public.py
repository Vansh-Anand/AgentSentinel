"""Verify a run receipt using a pinned public key, without the HMAC secret."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

from .layer_report import matches_current_source
from .signing import _canonical, verify_signed_receipt


def verify_public_run(run_id: str, data_dir: Path, expected_public_key_hex: str,
                      *, check_current_source: bool = False) -> dict[str, object]:
    try:
        safe_id = str(uuid.UUID(run_id))
        receipt_path = data_dir / "runtime-receipts" / f"{safe_id}.json"
        log_path = data_dir / "runtime-audit" / f"{safe_id}.jsonl"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        signature = verify_signed_receipt(receipt,
            expected_public_key_hex=expected_public_key_hex.strip())
        if not signature["valid"]:
            raise ValueError("SIGNATURE_INVALID")
        payload = receipt["payload"]
        audit_bytes = log_path.read_bytes()
        if payload.get("run_id") != safe_id or payload.get("audit_sha256") != hashlib.sha256(audit_bytes).hexdigest():
            raise ValueError("AUDIT_DIGEST_MISMATCH")
        records = [json.loads(line) for line in audit_bytes.splitlines()]
        if not records or len(records) != payload.get("audit_records"):
            raise ValueError("AUDIT_LENGTH_MISMATCH")
        previous = "0" * 64
        for index, record in enumerate(records, 1):
            if record.get("sequence") != index or record.get("previous_mac") != previous:
                raise ValueError("AUDIT_ORDER_MISMATCH")
            previous = record["mac"]
        if previous != payload.get("audit_head_mac"):
            raise ValueError("AUDIT_HEAD_MISMATCH")
        reports = [record["event"] for record in records
                   if record.get("event", {}).get("event") == "LAYER_REPORT"]
        if len(reports) != 1 or reports[0].get("run_id") != safe_id:
            raise ValueError("LAYER_REPORT_MISSING")
        if (payload.get("layer_report_sha256") != hashlib.sha256(_canonical(reports[0]["layers"])).hexdigest()
                or payload.get("fixture_sha256") != reports[0].get("fixture_sha256")):
            raise ValueError("LAYER_OR_FIXTURE_MISMATCH")
        if check_current_source and not matches_current_source(reports[0]["layers"][6]["evidence"]):
            raise ValueError("CURRENT_SOURCE_MISMATCH")
        return {"valid": True, "records_checked": len(records),
                "key_fingerprint_sha256": signature["key_fingerprint_sha256"]}
    except (OSError, UnicodeError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        return {"valid": False, "failure": str(exc)[:80]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--data-dir", type=Path, default=Path(".data"))
    parser.add_argument("--public-key-file", type=Path, required=True,
                        help="public key copied or pinned separately from the receipt")
    parser.add_argument("--check-current-source", action="store_true")
    args = parser.parse_args()
    result = verify_public_run(args.run_id, args.data_dir,
                               args.public_key_file.read_text(encoding="ascii").strip(),
                               check_current_source=args.check_current_source)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
