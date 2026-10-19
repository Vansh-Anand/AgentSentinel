"""Recompute saved live rows and publish only against the current source baseline.

This does not call a model or alter individual trial rows. It adds descriptive
intervals and writes the API's current-report file after source verification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluate_live_lab_v2 import summary
from agent_runtime.secure_lab import integrity_status


def publish(source: Path, destination: Path) -> dict:
    report = json.loads(source.read_text(encoding="utf-8"))
    current = integrity_status()
    if not current["valid"] or report.get("source_manifest") != current["manifest_sha256"]:
        raise ValueError("LIVE_REPORT_SOURCE_MISMATCH")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != report.get("case_count", 0) * report.get("repeats_per_case", 0):
        raise ValueError("LIVE_REPORT_ROWS_INCOMPLETE")
    report["measurement"] = summary(rows)
    report["limitations"] = (
        f"Small synthetic corpus with {report['repeats_per_case']} trial(s) per case. "
        "Repeated trials share prompts, so descriptive Wilson intervals are not population guarantees. "
        "A model refusal/no forbidden proposal is separate from a gateway interception. "
        "Benign checks require tool receipts and selected answer/artifact assertions, "
        "but do not establish general answer quality. Latency is end-to-end, not isolated "
        "security overhead. No native eBPF, TPM, trained detector or external Flowise canvas validated."
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = publish(args.input, args.output)
    print(json.dumps({"published": str(args.output), "trials": result["measurement"]["trials"],
                      "source_manifest": result["source_manifest"]}, indent=2))
