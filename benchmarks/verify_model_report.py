"""Independently check model-evaluation rows against local HMAC audit evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

from agent_runtime.evidence import verify_chain
from agent_runtime.layer_report import matches_current_source
from agent_runtime.verify_public import verify_public_run


def verify_report(report_path: Path, data_dir: Path,
                  *, check_current_source: bool = False) -> dict[str, object]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    rows = report.get("outcomes", [])
    if report.get("mode") != "REAL_MODEL_GATEWAY" or not isinstance(rows, list):
        raise ValueError("expected a real-model gateway evaluation report")
    key = (data_dir / "runtime-audit-key.bin").read_bytes()
    if len(key) != 32:
        raise ValueError("invalid local audit key")
    failures: list[dict[str, str]] = []
    seen: set[tuple[str, int]] = set()
    verified = 0
    signed_verified = 0
    public_path = data_dir / "runtime-signing-key.pub"
    public_hex = public_path.read_text(encoding="ascii").strip() if public_path.exists() else ""
    for row in rows:
        case_id = str(row.get("case_id", ""))
        repeat = row.get("repeat")
        identity = (case_id, repeat)
        if identity in seen or "error_type" in row:
            failures.append({"case_id": case_id, "reason": "DUPLICATE_OR_PROVIDER_ERROR"})
            continue
        seen.add(identity)
        try:
            run_id = str(uuid.UUID(str(row["run_id"])))
            log_path = data_dir / "runtime-audit" / f"{run_id}.jsonl"
            anchor_path = data_dir / "runtime-anchor" / f"{run_id}.json"
            chain = verify_chain(log_path, anchor_path, key)
            if not chain["valid"]:
                raise ValueError("AUDIT_CHAIN_INVALID")
            events = [json.loads(line)["event"] for line in log_path.read_text(encoding="utf-8").splitlines()]
            decisions = [event for event in events if event.get("event") == "DECISION"]
            executed = {event["request_id"] for event in events
                        if event.get("event") == "EXECUTION_RESULT" and event.get("executed")}
            denied = {event["request_id"] for event in decisions if event.get("decision") == "DENY"}
            reports = [event for event in events if event.get("event") == "LAYER_REPORT"]
            if (len(reports) != 1 or reports[0].get("run_id") != run_id
                    or reports[0].get("fixture_sha256") != row.get("fixture_sha256")):
                raise ValueError("FIXTURE_OR_LAYER_REPORT_MISMATCH")
            if denied & executed or len(denied) != row.get("unsafe_proposals"):
                raise ValueError("DECISION_EXECUTION_MISMATCH")
            if "signed_receipt_valid" in row:
                if (row["signed_receipt_valid"] is not True or not public_hex
                        or not verify_public_run(run_id, data_dir, public_hex)["valid"]):
                    raise ValueError("SIGNED_RECEIPT_INVALID")
                signed_verified += 1
            if check_current_source and not matches_current_source(reports[0]["layers"][6]["evidence"]):
                raise ValueError("CURRENT_SOURCE_MISMATCH")
            verified += 1
        except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            failures.append({"case_id": case_id, "reason": str(exc)[:80]})
    expected = 2 * int(report.get("cases_per_category", 0)) * int(report.get("repeats", 0))
    return {"valid": not failures and len(rows) == expected and verified == expected,
            "expected_rows": expected, "verified_rows": verified,
            "signed_receipts_verified": signed_verified, "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--data-dir", type=Path, default=Path(".data"))
    parser.add_argument("--check-current-source", action="store_true")
    args = parser.parse_args()
    result = verify_report(args.report, args.data_dir,
                           check_current_source=args.check_current_source)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
