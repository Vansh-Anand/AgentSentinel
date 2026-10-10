"""Check model-evaluation claims against versioned fixtures and signed run logs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

from agent_runtime.evidence import verify_chain
from agent_runtime.layer_report import matches_current_source
from agent_runtime.verify_public import verify_public_run
from .model_corpus import answer_assertion, fixture_text, load_corpus


def _expected_rows(corpus: dict[str, object], per_category: int,
                   repeats: int) -> dict[tuple[str, int], tuple[str, str]]:
    expected: dict[tuple[str, int], tuple[str, str]] = {}
    for category, cases in (("attack", corpus["attack_cases"]),
                            ("benign", corpus["benign_cases"])):
        for case in cases[:per_category]:
            digest = hashlib.sha256(fixture_text(corpus, case, category).encode("utf-8")).hexdigest()
            for repeat in range(1, repeats + 1):
                expected[(case["id"], repeat)] = category, digest
    return expected


def verify_report(report_path: Path, data_dir: Path,
                  *, check_current_source: bool = False) -> dict[str, object]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    rows = report.get("outcomes", [])
    schema = report.get("schema")
    if (schema not in {1, 2} or report.get("mode") not in
            {"REAL_MODEL_GATEWAY", "FIXTURE_REPLAY_GATEWAY"} or not isinstance(rows, list)):
        raise ValueError("expected a gateway model-evaluation report")
    corpus, digest = load_corpus(report.get("corpus", ""))
    if digest != report.get("corpus_sha256"):
        raise ValueError("corpus SHA-256 does not match the versioned file")
    if (report.get("provider") == "gemini") != (report.get("mode") == "REAL_MODEL_GATEWAY"):
        raise ValueError("provider and execution mode disagree")
    if schema == 2 and (report.get("split") != corpus.get("split", "development")
                        or report.get("required_answer_terms") != corpus.get("required_answer_terms", [])
                        or report.get("answer_assertion_method") !=
                        ("required_terms_casefold" if corpus.get("required_answer_terms") else "not_scored")):
        raise ValueError("task assertion metadata does not match corpus")
    per_category, repeats = report.get("cases_per_category"), report.get("repeats")
    if (not isinstance(per_category, int) or not isinstance(repeats, int)
            or not 1 <= per_category <= min(len(corpus["attack_cases"]), len(corpus["benign_cases"]))
            or not 1 <= repeats <= 5):
        raise ValueError("invalid report case selection")
    expected = _expected_rows(corpus, per_category, repeats)
    key = (data_dir / "runtime-audit-key.bin").read_bytes()
    if len(key) != 32:
        raise ValueError("invalid local audit key")
    public_path = data_dir / "runtime-signing-key.pub"
    public_hex = public_path.read_text(encoding="ascii").strip() if public_path.exists() else ""
    failures: list[dict[str, str]] = []
    seen: set[tuple[str, int]] = set()
    seen_run_ids: set[str] = set()
    verified = signed_verified = result_bound = 0
    for row in rows:
        case_id, repeat = row.get("case_id"), row.get("repeat")
        identity = (case_id, repeat)
        if identity not in expected or identity in seen or "error_type" in row:
            failures.append({"case_id": str(case_id), "reason": "UNEXPECTED_DUPLICATE_OR_ERROR_ROW"})
            continue
        seen.add(identity)
        category, fixture_hash = expected[identity]
        try:
            if row.get("category") != category or row.get("fixture_sha256") != fixture_hash:
                raise ValueError("CORPUS_FIXTURE_MISMATCH")
            run_id = str(uuid.UUID(str(row["run_id"])))
            if run_id in seen_run_ids:
                raise ValueError("DUPLICATE_RUN_ID")
            seen_run_ids.add(run_id)
            log_path = data_dir / "runtime-audit" / f"{run_id}.jsonl"
            anchor_path = data_dir / "runtime-anchor" / f"{run_id}.json"
            chain = verify_chain(log_path, anchor_path, key)
            if not chain["valid"]:
                raise ValueError("AUDIT_CHAIN_INVALID")
            events = [json.loads(line)["event"] for line in log_path.read_text(encoding="utf-8").splitlines()]
            if any(event.get("run_id") != run_id for event in events):
                raise ValueError("CROSS_RUN_EVENT")
            decisions = [event for event in events if event.get("event") == "DECISION"]
            executions = [event for event in events if event.get("event") == "EXECUTION_RESULT"]
            reports = [event for event in events if event.get("event") == "LAYER_REPORT"]
            if (len(reports) != 1 or reports[0].get("fixture_sha256") != fixture_hash):
                raise ValueError("FIXTURE_OR_LAYER_REPORT_MISMATCH")
            l1_evidence = reports[0]["layers"][0]["evidence"]
            if (row.get("model") != l1_evidence.get("model")
                    or (report["provider"] == "gemini") != (l1_evidence.get("provider") == "gemini")):
                raise ValueError("MODEL_PROVENANCE_MISMATCH")
            decision_by_id = {event.get("request_id"): event for event in decisions}
            execution_by_id = {event.get("request_id"): event for event in executions}
            if (len(decision_by_id) != len(decisions)
                    or len(execution_by_id) != len(executions)
                    or any(event.get("decision") not in {"ALLOW", "DENY"} for event in decisions)):
                raise ValueError("INVALID_DECISION_SEQUENCE")
            allowed_ids = {request_id for request_id, event in decision_by_id.items()
                           if event["decision"] == "ALLOW"}
            denied_ids = set(decision_by_id) - allowed_ids
            if set(execution_by_id) != allowed_ids or denied_ids & set(execution_by_id):
                raise ValueError("DECISION_EXECUTION_MISMATCH")
            allowed_executed = sum(event.get("executed") is True for event in executions)
            if (row.get("unsafe_proposals") != len(denied_ids)
                    or row.get("allowed_executed") != allowed_executed
                    or row.get("denied_executed") != 0):
                raise ValueError("REPORTED_COUNTS_MISMATCH")
            l2_evidence = reports[0]["layers"][1]["evidence"]
            if (l2_evidence.get("denied") != len(denied_ids)
                    or l2_evidence.get("allowed_executed") != allowed_executed
                    or l2_evidence.get("denied_executed") != 0):
                raise ValueError("LAYER_COUNTS_MISMATCH")
            if schema == 2:
                message = row.get("final_message")
                stop_reason = row.get("stop_reason")
                if not isinstance(message, str) or not isinstance(stop_reason, str):
                    raise ValueError("FINAL_RESULT_MISSING")
                message_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
                if (reports[0].get("final_message_sha256") != message_hash
                        or reports[0].get("stop_reason") != stop_reason
                        or row.get("final_message_sha256") != message_hash):
                    raise ValueError("FINAL_RESULT_NOT_BOUND_TO_AUDIT")
                completed = stop_reason == "FINISHED" and allowed_executed > 0 and bool(message)
                assertion = answer_assertion(message, corpus.get("required_answer_terms", []))
                task_success = (completed and assertion is True) if assertion is not None else None
                if (row.get("completed") is not completed
                        or row.get("answer_assertion_passed") is not assertion
                        or row.get("task_success") is not task_success):
                    raise ValueError("TASK_RESULT_MISMATCH")
                result_bound += 1
            if (row.get("signed_receipt_valid") is not True or not public_hex
                    or not verify_public_run(run_id, data_dir, public_hex)["valid"]):
                raise ValueError("SIGNED_RECEIPT_INVALID")
            signed_verified += 1
            source_evidence = reports[0]["layers"][6]["evidence"]
            if row.get("source_digest_sha256") != source_evidence["digest_sha256"]:
                raise ValueError("SOURCE_DIGEST_MISMATCH")
            if check_current_source and not matches_current_source(source_evidence):
                raise ValueError("CURRENT_SOURCE_MISMATCH")
            verified += 1
        except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            failures.append({"case_id": str(case_id), "reason": str(exc)[:80]})
    complete = (len(rows) == len(expected) and seen == set(expected)
                and verified == len(expected) and not failures)
    if complete:
        attack = [row for row in rows if row["category"] == "attack"]
        benign = [row for row in rows if row["category"] == "benign"]
        aggregates = {
            "attempts": len(rows), "provider_errors": 0,
            "attack_attempts": len(attack), "benign_attempts": len(benign),
            "attack_cases_with_denied_proposal": sum(row["unsafe_proposals"] > 0 for row in attack),
            "denied_proposals_executed": 0,
            "benign_completed": sum(row["completed"] is True for row in benign),
            "benign_cases_with_denial": sum(row["unsafe_proposals"] > 0 for row in benign),
            "all_audits_valid": True, "all_signed_receipts_valid": True,
        }
        if schema == 2:
            aggregates["benign_task_success"] = sum(row["task_success"] is True for row in benign)
        for field, value in aggregates.items():
            if report.get(field) != value:
                failures.append({"case_id": "REPORT", "reason": f"AGGREGATE_MISMATCH:{field}"})
        complete = not failures
    return {"valid": complete, "expected_rows": len(expected),
            "verified_rows": verified, "signed_receipts_verified": signed_verified,
            "final_results_bound_to_audit": result_bound, "failures": failures}


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
