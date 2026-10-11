"""Evaluation claims must agree with signed run evidence and corpus fixtures."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime.agent import AgentTurn, ToolProposal
from benchmarks.export_model_report import export
from benchmarks.model_corpus import answer_assertion, load_corpus
from benchmarks.model_eval import evaluate
from benchmarks.verify_model_report import verify_report


class ModelEvaluationIntegrityTests(unittest.TestCase):
    def test_heldout_corpus_and_narrow_answer_assertion(self):
        corpus, digest = load_corpus("model_cases_v2.json")
        self.assertEqual(len(corpus["attack_cases"]), 25)
        self.assertEqual(len(corpus["benign_cases"]), 25)
        self.assertEqual(len(digest), 64)
        self.assertTrue(answer_assertion("Audit logs are retained for 30 days.",
                                         corpus["required_answer_terms"]))
        self.assertFalse(answer_assertion("The incident intake module works.",
                                          corpus["required_answer_terms"]))

    def test_signed_report_rejects_forged_counts_and_final_answer(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            report = evaluate(provider="fixture", per_category=1, repeats=1,
                              audit_dir=data_dir / "runtime-audit",
                              corpus_name="model_cases_v2.json")
            path = data_dir / "report.json"

            def check(value: dict[str, object]) -> dict[str, object]:
                path.write_text(json.dumps(value), encoding="utf-8")
                return verify_report(path, data_dir)

            valid = check(report)
            self.assertTrue(valid["valid"])
            self.assertEqual(valid["final_results_bound_to_audit"], 2)

            forged = copy.deepcopy(report)
            forged["outcomes"][0]["allowed_executed"] = 0
            self.assertFalse(check(forged)["valid"])

            forged = copy.deepcopy(report)
            forged["outcomes"][0]["final_message"] = "False answer"
            self.assertFalse(check(forged)["valid"])

            forged = copy.deepcopy(report)
            forged["benign_completed"] = 0
            self.assertFalse(check(forged)["valid"])

            forged = copy.deepcopy(report)
            forged["outcomes"][0]["fixture_sha256"] = "0" * 64
            self.assertFalse(check(forged)["valid"])

    def test_public_v3_and_v4_exports_omit_raw_answers_and_run_ids(self):
        class StubModel:
            name = "gemini"
            model = "test-stub"

            def next_turn(self, _task, feedback):
                if not feedback:
                    return AgentTurn("Read task document", ToolProposal("read_file", {"path": "README.md"}))
                return AgentTurn("The module ingests audit logs and retains receipts for 30 days.")

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            with patch("agent_runtime.service.GeminiProvider", StubModel):
                report = evaluate(provider="gemini", per_category=1, repeats=1,
                                  audit_dir=data_dir / "runtime-audit",
                                  corpus_name="model_cases_v2.json")
            path = data_dir / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            self.assertTrue(verify_report(path, data_dir, check_current_source=True)["valid"])
            for version in ("v3", "v4"):
                summary = export(path, data_dir, data_dir / "public", version=version)
                self.assertEqual(summary["benign_task_success"], 1)
                self.assertEqual(summary["wilson_95"]["benign_lexical_success"]["total"], 1)
                self.assertIsNone(summary["wilson_95"]["denied_proposal_executed"]["interval"])
                published = (data_dir / "public" / f"agentsentinel_model_eval_{version}.json").read_text()
                self.assertNotIn("final_message", published)
                self.assertNotIn(report["outcomes"][0]["run_id"], published)
                self.assertNotIn("The module ingests audit logs", published)


if __name__ == "__main__":
    unittest.main()
