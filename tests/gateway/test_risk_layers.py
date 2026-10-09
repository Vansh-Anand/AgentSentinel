"""Real governance state and truthful layer provenance."""

import tempfile
from pathlib import Path
import unittest

from agent_runtime.gateway import GatewayResult
from agent_runtime.layer_report import build_layer_report, matches_current_source
from agent_runtime.policy import TaskPolicy
from agent_runtime.risk import RiskGovernor


class RiskLayerTests(unittest.TestCase):
    def test_allowed_then_denied_then_repeated_deny_stops(self):
        governor = RiskGovernor()
        allowed = GatewayResult("r:0", "ALLOW", "TASK_POLICY_ALLOW", True)
        denied = GatewayResult("r:1", "DENY", "PATH_OUT_OF_SCOPE", False)
        self.assertEqual(governor.observe(allowed).action, "MONITOR")
        review = governor.observe(denied)
        self.assertEqual((review.action, review.denied_calls), ("REVIEW", 1))
        stop = governor.observe(GatewayResult("r:2", "DENY", "NETWORK_EXECUTION_DISABLED", False))
        self.assertEqual((stop.action, stop.denied_calls, stop.score), ("STOP", 2, 100))

    def test_report_does_not_promote_missing_native_telemetry_or_software_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("safe", encoding="utf-8")
            policy = TaskPolicy(root, ("README.md",))
            result = GatewayResult("r:0", "ALLOW", "TASK_POLICY_ALLOW", True)
            report = build_layer_report(
                provider="fixture-replay", model=None, policy=policy,
                results=(result,), risk=RiskGovernor().observe(result),
                effect_verdicts=("INCOMPLETE",),
            )
        self.assertEqual(report[2]["mode"], "UNAVAILABLE")
        self.assertEqual(report[2]["evidence"]["effectseal_verdicts"], ["INCOMPLETE"])
        self.assertEqual(report[3]["evidence"]["trained_model"], False)
        self.assertEqual(report[6]["mode"], "SOFTWARE_MEASUREMENT")
        self.assertIs(report[6]["evidence"]["hardware_attested"], False)
        self.assertEqual(len(report[6]["evidence"]["digest_sha256"]), 64)
        self.assertEqual(report[6]["evidence"]["file_count"], 24)
        self.assertFalse(report[6]["evidence"]["model_active"])
        self.assertEqual(len(report[6]["evidence"]["inactive_research_artifacts"]), 2)
        self.assertTrue(matches_current_source(report[6]["evidence"]))
        changed = {**report[6]["evidence"], "digest_sha256": "0" * 64}
        self.assertFalse(matches_current_source(changed))


if __name__ == "__main__":
    unittest.main()
