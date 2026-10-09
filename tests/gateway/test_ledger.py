import tempfile
from pathlib import Path
import unittest

from agent_runtime.gateway import AgentToolGateway, JsonlAuditSink
from agent_runtime.ledger import DurableRequestLedger
from agent_runtime.policy import TaskPolicy


class CountingExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, tool_name, arguments, policy):
        self.calls += 1
        return "ok"


class LedgerTests(unittest.TestCase):
    def test_duplicate_after_gateway_restart_is_not_dispatched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("safe", encoding="utf-8")
            policy = TaskPolicy(root, ("README.md",))
            executor = CountingExecutor()
            ledger_path = root / "trusted" / "requests.sqlite"
            audit_path = root / "audit.jsonl"

            def gateway():
                return AgentToolGateway(policy, executor, JsonlAuditSink(audit_path),
                                        DurableRequestLedger(ledger_path))

            first = gateway().handle(run_id="run", request_id="id", tool_name="read_file",
                                     arguments={"path": "README.md"})
            self.assertTrue(first.executed)
            repeated = gateway().handle(run_id="run", request_id="id", tool_name="read_file",
                                        arguments={"path": "README.md"})
            self.assertEqual(repeated.reason_code, "REQUEST_ALREADY_SEEN")
            self.assertFalse(repeated.executed)
            self.assertEqual(executor.calls, 1)
            changed = gateway().handle(run_id="run", request_id="id", tool_name="read_file",
                                       arguments={"path": ".env"})
            self.assertEqual(changed.reason_code, "REQUEST_ID_REUSED")
            self.assertEqual(executor.calls, 1)


if __name__ == "__main__":
    unittest.main()
