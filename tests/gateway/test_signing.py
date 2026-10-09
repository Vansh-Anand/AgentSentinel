"""Public run receipt checks without access to the HMAC key."""

from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime.service import run_container_demo, run_demo_task
from agent_runtime.verify_public import verify_public_run
from agent_runtime.export_evidence import export_public_run


class PublicReceiptTests(unittest.TestCase):
    def test_fixture_run_verifies_with_pinned_public_key_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            result = run_demo_task("Summarize README.md", "fixture",
                                   data_dir / "runtime-audit")
            run_id = result["run_id"]
            public_hex = (data_dir / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
            self.assertTrue(result["signed_receipt"]["valid"])
            self.assertTrue(verify_public_run(run_id, data_dir, public_hex,
                                              check_current_source=True)["valid"])
            self.assertFalse(verify_public_run(run_id, data_dir, "0" * 64)["valid"])

            receipt_path = data_dir / "runtime-receipts" / f"{run_id}.json"
            original_receipt = receipt_path.read_text(encoding="utf-8")
            changed = json.loads(original_receipt)
            changed["signature_hex"] = "0" * 128
            receipt_path.write_text(json.dumps(changed), encoding="utf-8")
            self.assertFalse(verify_public_run(run_id, data_dir, public_hex)["valid"])
            receipt_path.write_text(original_receipt, encoding="utf-8")

            log = data_dir / "runtime-audit" / f"{run_id}.jsonl"
            text = log.read_text(encoding="utf-8")
            log.write_text(text.replace("TASK_POLICY_ALLOW", "ALTERED_POLICY_ALLOW"), encoding="utf-8")
            self.assertFalse(verify_public_run(run_id, data_dir, public_hex)["valid"])

    def test_container_run_produces_a_publicly_verifiable_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            with patch.dict("os.environ", {"AGENTSENTINEL_DOCKER_IMAGE": "sha256:" + "a" * 64}), \
                 patch("agent_runtime.service.DockerCommandExecutor") as executor:
                executor.return_value.execute.return_value = "safe synthetic output"
                result = run_container_demo(False, data_dir / "runtime-audit")
            public_hex = (data_dir / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
            self.assertTrue(result["signed_receipt"]["valid"])
            self.assertTrue(verify_public_run(result["run_id"], data_dir, public_hex)["valid"])

    def test_public_export_excludes_private_keys_and_verifies_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "source"
            result = run_demo_task("Summarize README.md", "fixture",
                                   data_dir / "runtime-audit")
            bundle = Path(directory) / "portable"
            exported = export_public_run(result["run_id"], data_dir, bundle)
            self.assertEqual(exported["records_checked"], 8)
            self.assertEqual(sorted(path.name for path in bundle.iterdir()),
                             ["runtime-audit", "runtime-receipts", "runtime-signing-key.pub"])
            pinned = (data_dir / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
            self.assertTrue(verify_public_run(result["run_id"], bundle, pinned)["valid"])
            self.assertFalse(verify_public_run(result["run_id"], bundle, "0" * 64)["valid"])

    def test_effect_and_risk_are_recorded_before_the_next_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            result = run_demo_task("Summarize README.md", "fixture",
                                   data_dir / "runtime-audit")
            records = [json.loads(line)["event"] for line in
                       (data_dir / "runtime-audit" / f'{result["run_id"]}.jsonl').read_text().splitlines()]
            self.assertEqual([record["event"] for record in records], [
                "DECISION", "EXECUTION_RESULT", "EFFECTSEAL_RECEIPT", "RISK_ASSESSMENT",
                "DECISION", "EFFECTSEAL_RECEIPT", "RISK_ASSESSMENT", "LAYER_REPORT",
            ])
            self.assertEqual(records[2]["verdict"], "INCOMPLETE")
            self.assertEqual(records[3]["action"], "REVIEW")
            self.assertEqual(records[5]["verdict"], "NOT_EXECUTED")
            self.assertEqual(records[6]["denied_calls"], 1)


if __name__ == "__main__":
    unittest.main()
