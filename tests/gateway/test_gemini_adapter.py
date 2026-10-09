"""Adapter contract tests with a fake SDK response; no API key or network."""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest

try:
    from google.genai.errors import APIError
except ImportError:  # The Gemini SDK is optional for the standard-library gateway tests.
    APIError = None

from agent_runtime.agent import AgentRunner
from agent_runtime.gateway import AgentToolGateway, JsonlAuditSink
from agent_runtime.policy import TaskPolicy
from agent_runtime.providers import GeminiProvider
from agent_runtime.tools import LocalReadOnlyExecutor


class FakeModels:
    def __init__(self, text):
        self.text = text
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(text=self.text)


class GeminiAdapterTests(unittest.TestCase):
    def provider(self, text):
        provider = object.__new__(GeminiProvider)
        models = FakeModels(text)
        provider.client = SimpleNamespace(models=models)
        provider.model = "fake-model"
        return provider, models

    def test_model_proposal_is_still_denied_by_gateway(self):
        provider, models = self.provider(
            '{"message":"Read the secret","tool":{"name":"read_file","arguments":{"path":".env"}}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("safe", encoding="utf-8")
            (root / ".env").write_text("synthetic", encoding="utf-8")
            gateway = AgentToolGateway(TaskPolicy(root, ("README.md",)), LocalReadOnlyExecutor(),
                                       JsonlAuditSink(root / "audit.jsonl"))
            run = AgentRunner(gateway, provider).run(run_id="model", task="Summarize README")
            self.assertEqual(run.steps[0].result.reason_code, "PATH_OUT_OF_SCOPE")
            self.assertFalse(run.steps[0].result.executed)
            self.assertEqual(len(models.calls), 2)
            self.assertEqual(models.calls[0]["config"]["response_mime_type"], "application/json")
            feedback = json.loads(models.calls[1]["contents"])["tool_feedback_untrusted"]
            self.assertEqual(feedback[0]["arguments"], {"path": ".env"})
            self.assertEqual(feedback[0]["reason_code"], "PATH_OUT_OF_SCOPE")

    def test_invalid_structured_turn_fails_closed(self):
        provider, _ = self.provider('{"message":"oops","tool":{"name":42}}')
        with self.assertRaises(RuntimeError):
            provider.next_turn("task", ())

    @unittest.skipIf(APIError is None, "google-genai is not installed")
    def test_provider_error_is_sanitized_for_the_api(self):
        provider, _ = self.provider('{}')

        class FailingModels:
            def generate_content(self, **kwargs):
                raise APIError(503, {"error": {"code": 503,
                    "message": "upstream internal marker", "status": "UNAVAILABLE"}})

        provider.client = SimpleNamespace(models=FailingModels())
        with self.assertRaisesRegex(RuntimeError, r"Gemini service temporarily unavailable \(HTTP 503\)") as error:
            provider.next_turn("task", ())
        self.assertNotIn("upstream internal marker", str(error.exception))


if __name__ == "__main__":
    unittest.main()
