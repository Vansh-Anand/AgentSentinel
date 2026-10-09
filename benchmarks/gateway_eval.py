"""Deterministic policy-case evaluation. This is not a model attack benchmark."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import platform
import statistics
import tempfile
import time

from agent_runtime.gateway import AgentToolGateway, JsonlAuditSink
from agent_runtime.policy import TaskPolicy, normalize_relative_path
from agent_runtime.tools import LocalReadOnlyExecutor


CORPUS = Path(__file__).with_name("gateway_cases_v2.json")


def evaluate() -> dict[str, object]:
    raw_corpus = CORPUS.read_bytes()
    corpus = json.loads(raw_corpus)
    if corpus.get("schema") != 2 or corpus.get("mode") != "DETERMINISTIC_POLICY_FIXTURES":
        raise ValueError("unsupported policy corpus")
    cases = corpus["cases"]
    allowed_files = corpus["allowed_files"]
    if len(cases) != len({case["id"] for case in cases}):
        raise ValueError("duplicate corpus case ID")
    if len(allowed_files) != len(set(allowed_files)) or any(
        normalize_relative_path(path) != path for path in allowed_files
    ):
        raise ValueError("invalid or duplicate allowed file")
    if sum(case["category"] == "attack" and case["expected"] == "DENY" for case in cases) != 25:
        raise ValueError("corpus must contain 25 expected-deny attack cases")
    if sum(case["category"] == "benign" and case["expected"] == "ALLOW" for case in cases) != 25:
        raise ValueError("corpus must contain 25 expected-allow benign cases")
    if len(cases) != 50:
        raise ValueError("corpus must contain exactly 50 cases")
    with tempfile.TemporaryDirectory(prefix="agentsentinel-eval-") as directory:
        root = Path(directory)
        for relative in allowed_files:
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"Synthetic allowed file: {relative}\n", encoding="utf-8")
        (root / ".env").write_text("DEMO_SECRET=synthetic-only\n", encoding="utf-8")
        gateway = AgentToolGateway(
            TaskPolicy(root, tuple(allowed_files)),
            LocalReadOnlyExecutor(), JsonlAuditSink(root / "audit.jsonl"),
        )
        outcomes = []
        for case in cases:
            started = time.perf_counter_ns()
            result = gateway.handle(
                run_id="fixture-evaluation", request_id=case["id"],
                tool_name=case["tool"], arguments=case["arguments"],
            )
            elapsed = time.perf_counter_ns() - started
            outcomes.append({
                "id": case["id"], "category": case["category"],
                "expected": case["expected"], "actual": result.decision,
                "reason_code": result.reason_code,
                "executed": result.executed,
                "pass": result.decision == case["expected"]
                and result.executed == (case["expected"] == "ALLOW"),
                "latency_ns": elapsed,
            })
        latencies = sorted(row["latency_ns"] for row in outcomes)
        attacks = [row for row in outcomes if row["category"] == "attack"]
        benign = [row for row in outcomes if row["category"] == "benign"]
        return {
            "corpus": CORPUS.name,
            "corpus_sha256": hashlib.sha256(raw_corpus).hexdigest(),
            "mode": "DETERMINISTIC_POLICY_FIXTURES",
            "platform": platform.platform(),
            "cases": len(outcomes),
            "attack_cases_denied": sum(row["actual"] == "DENY" and not row["executed"] for row in attacks),
            "attack_cases_total": len(attacks),
            "benign_cases_executed": sum(row["actual"] == "ALLOW" and row["executed"] for row in benign),
            "benign_cases_total": len(benign),
            "all_expectations_met": all(row["pass"] for row in outcomes),
            "median_latency_ns": int(statistics.median(latencies)),
            "p95_latency_ns": latencies[max(0, (95 * len(latencies) + 99) // 100 - 1)],
            "outcomes": outcomes,
        }


if __name__ == "__main__":
    report = evaluate()
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["all_expectations_met"] else 1)
