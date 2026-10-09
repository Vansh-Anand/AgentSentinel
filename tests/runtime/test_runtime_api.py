"""In-process HTTP tests for the isolated gateway endpoint."""

from pathlib import Path
from io import BytesIO
import json
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from fastapi.testclient import TestClient

from dashboard_api.main import app
from dashboard_api.routers import runtime
from agent_runtime.verify_public import verify_public_run


class RuntimeApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch = patch.object(runtime, "AUDIT_DIR", Path(self.temp.name) / "runtime-audit")
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.client = TestClient(app)

    def test_real_gateway_run_and_verification(self):
        response = self.client.post("/api/runtime/run", json={"task": "Summarize README", "provider": "fixture"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["execution_mode"], "FIXTURE_REPLAY")
        self.assertEqual(data["stop_reason"], "FINISHED")
        self.assertIn("validates session tokens", data["final_message"])
        self.assertEqual([step["decision"] for step in data["steps"]], ["ALLOW", "DENY"])
        self.assertEqual(data["steps"][0]["effectseal"]["verdict"], "INCOMPLETE")
        self.assertEqual(data["steps"][1]["effectseal"]["verdict"], "NOT_EXECUTED")
        self.assertEqual([layer["layer"] for layer in data["layers"]],
                         [f"L{index}" for index in range(1, 8)])
        self.assertEqual(data["layers"][2]["mode"], "UNAVAILABLE")
        self.assertFalse(data["layers"][6]["evidence"]["hardware_attested"])
        self.assertEqual(data["steps"][1]["risk"]["action"], "REVIEW")
        self.assertTrue(data["audit_verification"]["valid"])
        self.assertTrue(data["signed_receipt"]["valid"])
        self.assertEqual(len(data["signed_receipt"]["public_key_hex"]), 64)
        verified = self.client.get(f"/api/runtime/runs/{data['run_id']}/verify")
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.json()["valid"])
        self.assertEqual(verified.json()["records_checked"], 8)
        bundle_response = self.client.get(f"/api/runtime/runs/{data['run_id']}/evidence.zip")
        self.assertEqual(bundle_response.status_code, 200)
        exported = Path(self.temp.name) / "exported"
        with ZipFile(BytesIO(bundle_response.content)) as bundle:
            self.assertEqual(set(bundle.namelist()), {
                f"runtime-audit/{data['run_id']}.jsonl",
                f"runtime-receipts/{data['run_id']}.json",
                "runtime-signing-key.pub",
            })
            bundle.extractall(exported)
        pinned = (exported / "runtime-signing-key.pub").read_text(encoding="ascii").strip()
        self.assertTrue(verify_public_run(data["run_id"], exported, pinned)["valid"])
        self.assertFalse(verify_public_run(data["run_id"], exported, "0" * 64)["valid"])
        receipt_path = Path(self.temp.name) / "runtime-receipts" / f"{data['run_id']}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["signature_hex"] = "0" * 128
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        self.assertEqual(self.client.get(f"/api/runtime/runs/{data['run_id']}/evidence.zip").status_code, 409)

    def test_unconfigured_provider_does_not_fallback(self):
        response = self.client.post("/api/runtime/run", json={"task": "Inspect", "provider": "unknown"})
        self.assertEqual(response.status_code, 400)

    def test_verification_rejects_non_uuid_path(self):
        response = self.client.get("/api/runtime/runs/not-a-uuid/verify")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/api/runtime/runs/not-a-uuid/evidence.zip").status_code, 400)

    def test_container_requires_trusted_server_image_configuration(self):
        with patch.dict("os.environ", {"AGENTSENTINEL_DOCKER_IMAGE": ""}):
            response = self.client.post("/api/runtime/container-demo", json={"attack": True})
        self.assertEqual(response.status_code, 503)

    def test_published_evaluation_exposes_summary_only(self):
        path = Path(self.temp.name) / "public-eval.json"
        with patch.object(runtime, "EVALUATION_REPORT", path), \
             patch.object(runtime, "FALLBACK_EVALUATION_REPORT", path):
            self.assertFalse(self.client.get("/api/runtime/evaluation").json()["available"])
            report = {"schema": 1, "mode": "REAL_MODEL_GATEWAY", "cases": [{"run_id": "private"}]}
            report.update({key: 0 for key in (
                "attack_cases", "attack_cases_with_denied_proposal", "attack_denied_proposals",
                "denied_proposals_executed", "benign_cases", "benign_completed",
                "provider_errors", "audit_chains_verified", "signed_receipts_verified",
                "p50_latency_ms", "p95_latency_ms",
            )})
            report.update({"model": ["fixture"], "corpus": "corpus.json",
                           "corpus_sha256": "0" * 64,
                           "source_hashes_match_current_checkout": False})
            path.write_text(json.dumps(report), encoding="utf-8")
            response = self.client.get("/api/runtime/evaluation")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["available"])
        self.assertNotIn("cases", response.json())


if __name__ == "__main__":
    unittest.main()
