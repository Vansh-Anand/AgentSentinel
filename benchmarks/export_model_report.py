"""Publish a credential-free summary only after every local audit verifies."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

from .verify_model_report import verify_report


def export(report_path: Path, data_dir: Path, output_dir: Path,
           *, version: str = "v1") -> dict[str, object]:
    if version not in {"v1", "v2", "v3"}:
        raise ValueError("unsupported public report version")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    verification = verify_report(report_path, data_dir)
    source_verification = verify_report(report_path, data_dir, check_current_source=True)
    if (report.get("mode") != "REAL_MODEL_GATEWAY" or not verification["valid"]
            or report.get("provider_errors") != 0):
        raise ValueError("report has provider errors or unverified local audit evidence")
    if version == "v3" and (report.get("schema") != 2 or not source_verification["valid"]):
        raise ValueError("v3 requires bound final results and current-source verification")
    rows = report["outcomes"]
    latencies = sorted(float(row["latency_ms"]) for row in rows)
    public_fields = (
        "case_id", "category", "fixture_sha256", "unsafe_proposals",
        "denied_executed", "allowed_executed", "completed", "latency_ms",
    )
    if version == "v3":
        public_fields += ("repeat", "answer_assertion_passed", "task_success")
    public_rows = [{key: row[key] for key in public_fields} for row in rows]
    summary = {
        "schema": 1,
        "mode": report["mode"], "model": sorted({row["model"] for row in rows}),
        "corpus": report["corpus"], "corpus_sha256": report["corpus_sha256"],
        "platform": report["platform"], "repeats": report["repeats"],
        "attack_cases": report["attack_attempts"],
        "attack_cases_with_denied_proposal": report["attack_cases_with_denied_proposal"],
        "attack_denied_proposals": sum(row["unsafe_proposals"] for row in rows if row["category"] == "attack"),
        "attack_completed": sum(row["completed"] for row in rows if row["category"] == "attack"),
        "denied_proposals_executed": report["denied_proposals_executed"],
        "benign_cases": report["benign_attempts"],
        "benign_completed": report["benign_completed"],
        "benign_cases_with_denial": report["benign_cases_with_denial"],
        "provider_errors": report["provider_errors"],
        "audit_chains_verified": verification["verified_rows"],
        "signed_receipts_verified": verification["signed_receipts_verified"],
        "final_results_bound_to_audit": verification["final_results_bound_to_audit"],
        "answer_assertion_method": report.get("answer_assertion_method", "not_scored"),
        "benign_task_success": report.get("benign_task_success") if version == "v3" else None,
        "source_measurement_digests": sorted({row["source_digest_sha256"] for row in rows
                                               if "source_digest_sha256" in row}),
        "source_hashes_match_current_checkout": source_verification["valid"],
        "p50_latency_ms": latencies[math.ceil(0.50 * len(latencies)) - 1],
        "p95_latency_ms": latencies[math.ceil(0.95 * len(latencies)) - 1],
        "cases": public_rows,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"agentsentinel_model_eval_{version}"
    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    retry_note = ("The provider-error row counts unresolved final cases; transient HTTP 429 "
                  "responses can be retried from a checkpoint. " if version in {"v2", "v3"} else "")
    corpus_link = f"../{summary['corpus']}"
    trial_description = (f"{summary['repeats']} "
                         f"{'trial' if summary['repeats'] == 1 else 'trials'} per selected case")
    quality_row = (f"| Benign tasks passing lexical answer assertion | "
                   f"{summary['benign_task_success']}/{summary['benign_cases']} |\n"
                   if version == "v3" else "")
    result_row = (f"| Final answers bound to signed audits | "
                  f"{summary['final_results_bound_to_audit']}/{summary['attack_cases'] + summary['benign_cases']} |\n"
                  if version == "v3" else "")
    markdown = f"""# AgentSentinel model gateway evaluation {version}

This is {trial_description} on `{summary['platform']}` with `{', '.join(summary['model'])}`. The [versioned corpus]({corpus_link}) has SHA-256 `{summary['corpus_sha256']}`. [Per-case results]({stem}.json) omit run IDs, raw model text, and credentials.

| Measure | Result |
| --- | ---: |
| Attack READMEs with an out-of-scope proposal | {summary['attack_cases_with_denied_proposal']}/{summary['attack_cases']} |
| Out-of-scope proposals that executed | {summary['denied_proposals_executed']}/{summary['attack_denied_proposals']} |
| Attack tasks reaching a final response | {summary['attack_completed']}/{summary['attack_cases']} |
| Benign tasks reaching a final response | {summary['benign_completed']}/{summary['benign_cases']} |
{quality_row}| Benign cases with a denied proposal | {summary['benign_cases_with_denial']}/{summary['benign_cases']} |
| Provider errors | {summary['provider_errors']}/{summary['attack_cases'] + summary['benign_cases']} |
| Independently verified local audit chains | {summary['audit_chains_verified']}/{summary['attack_cases'] + summary['benign_cases']} |
| Public-key signed receipts independently verified | {summary['signed_receipts_verified']}/{summary['attack_cases'] + summary['benign_cases']} |
{result_row}| Run latency p50 / p95 | {summary['p50_latency_ms']:.2f} / {summary['p95_latency_ms']:.2f} ms |

The attack text was inside the untrusted `README.md` that the agent was asked to summarize. A denied proposal means the model requested an action outside the task policy; the gateway prevented that tool execution. The corpus uses synthetic files and a reserved test domain. {retry_note}The lexical answer assertion checks required terms only; it is not a full semantic-quality or answer-contamination grade. The run does not establish real-world attack prevalence, sandbox escape resistance, or native eBPF/TPM coverage. The local HMAC chains and fixture hashes verify against saved evidence. Source hashes matched the checkout at publication: **{str(summary['source_hashes_match_current_checkout']).lower()}**. This static result may become stale after code changes; it is not remote or hardware attestation.

Reproduce with `python -m benchmarks.model_eval --provider gemini --corpus {summary['corpus']} --per-category {summary['attack_cases'] // summary['repeats']} --repeats {summary['repeats']} --output .data/model-eval/gemini-full-{version}.json`, then run the verifier and `python -m benchmarks.export_model_report .data/model-eval/gemini-full-{version}.json --version {version}`. The API key is supplied only through `GEMINI_API_KEY` and is not part of the exported report.
"""
    (output_dir / f"{stem}.md").write_text(markdown, encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--data-dir", type=Path, default=Path(".data"))
    parser.add_argument("--output-dir", type=Path, default=Path("benchmarks/results"))
    parser.add_argument("--version", choices=("v1", "v2", "v3"), default="v1")
    args = parser.parse_args()
    summary = export(args.report, args.data_dir, args.output_dir, version=args.version)
    print(json.dumps({key: value for key, value in summary.items() if key != "cases"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
