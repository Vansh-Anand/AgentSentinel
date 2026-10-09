"""Audit-chain integrity tests against edited, reordered, and truncated logs."""

import json
from pathlib import Path
import tempfile
import unittest

from agent_runtime.evidence import HmacChainedAuditSink, load_or_create_key, verify_chain
from agent_runtime.gateway import AgentToolGateway
from agent_runtime.policy import TaskPolicy


class CountingExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, tool_name, arguments, policy):
        self.calls += 1
        return "ok"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "README.md").write_text("safe", encoding="utf-8")
        self.key_path = self.root / "trusted" / "key.bin"
        self.log = self.root / "audit" / "run.jsonl"
        self.anchor = self.root / "trusted" / "run.anchor"
        self.key = load_or_create_key(self.key_path)
        self.executor = CountingExecutor()
        self.gateway = AgentToolGateway(
            TaskPolicy(self.root, ("README.md",)), self.executor,
            HmacChainedAuditSink(self.log, self.anchor, self.key),
        )

    def call(self, request_id):
        return self.gateway.handle(run_id="r", request_id=request_id,
                                   tool_name="read_file", arguments={"path": "README.md"})

    def test_persists_and_verifies_after_reopen(self):
        self.assertTrue(self.call("1").executed)
        self.assertTrue(self.call("2").executed)
        reopened_key = load_or_create_key(self.key_path)
        result = verify_chain(self.log, self.anchor, reopened_key)
        self.assertTrue(result["valid"])
        self.assertEqual(result["records_checked"], 4)
        HmacChainedAuditSink(self.log, self.anchor, reopened_key).append({"event": "RESTART"})
        self.assertEqual(verify_chain(self.log, self.anchor, self.key)["records_checked"], 5)

    def test_tampering_is_detected(self):
        self.call("1")
        original = self.log.read_text(encoding="utf-8")
        records = [json.loads(line) for line in original.splitlines()]
        cases = [
            [records[1], records[0]],
            [records[0]],
            [{**records[0], "event": {"decision": "ALLOW"}}, records[1]],
            [{**records[0], "forged_note": "safe"}, records[1]],
        ]
        for case in cases:
            self.log.write_text("\n".join(json.dumps(row) for row in case) + "\n", encoding="utf-8")
            self.assertFalse(verify_chain(self.log, self.anchor, self.key)["valid"])
        self.log.write_text(original, encoding="utf-8")
        self.assertTrue(verify_chain(self.log, self.anchor, self.key)["valid"])

    def test_invalid_chain_fails_closed_before_executor(self):
        self.call("1")
        self.log.write_text("{}\n", encoding="utf-8")
        result = self.call("2")
        self.assertEqual(result.reason_code, "AUDIT_UNAVAILABLE")
        self.assertEqual(self.executor.calls, 1)


if __name__ == "__main__":
    unittest.main()
