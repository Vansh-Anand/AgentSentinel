import subprocess
from pathlib import Path
import tempfile
import unittest

from agent_runtime.docker_executor import DockerCommandExecutor
from agent_runtime.gateway import AgentToolGateway, JsonlAuditSink
from agent_runtime.policy import TaskPolicy


PINNED_IMAGE = "sha256:" + "a" * 64


class DockerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "README.md").write_text("safe", encoding="utf-8")
        (self.root / "summary.py").write_text("print('summary')\n", encoding="utf-8")
        (self.root / ".env").write_text("DEMO_SECRET=synthetic", encoding="utf-8")
        self.policy = TaskPolicy(self.root, ("README.md", "summary.py"),
                                 allowed_commands=(("python", "summary.py"),))

    def test_docker_invocation_has_restricted_flags_and_only_allowlisted_snapshot(self):
        captured = []

        def fake_runner(command, **kwargs):
            captured.append(command)
            mount = command[command.index("--mount") + 1]
            source = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
            self.assertTrue((source / "README.md").exists())
            self.assertTrue((source / "summary.py").exists())
            self.assertFalse((source / ".env").exists())
            kwargs["stdout"].write(b"summary\n")
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=fake_runner)
        output = executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertEqual(output, "summary\n")
        command = captured[0]
        for flag, value in (("--network", "none"), ("--cap-drop", "ALL"),
                            ("--user", "65534:65534"), ("--pull", "never")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--read-only", command)
        self.assertEqual(command[-2:], ["python", "summary.py"])

    def test_gateway_rejects_unlisted_commands_before_docker(self):
        calls = []

        def fake_runner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        gateway = AgentToolGateway(
            self.policy, DockerCommandExecutor(PINNED_IMAGE, process_runner=fake_runner),
            JsonlAuditSink(self.root / "audit.jsonl"),
        )
        denied = gateway.handle(run_id="r", request_id="bad", tool_name="execute_command",
                                arguments={"argv": ["sh", "-c", "cat .env"]})
        self.assertEqual(denied.reason_code, "COMMAND_OUT_OF_SCOPE")
        self.assertFalse(denied.executed)
        self.assertEqual(calls, [])

    def test_image_must_be_pinned(self):
        with self.assertRaises(ValueError):
            DockerCommandExecutor("python:latest")

    def test_timeout_removes_container_by_name_even_without_cidfile(self):
        cleaned = []

        def timeout_runner(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        def cleanup(command, **kwargs):
            cleaned.append(command)
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=timeout_runner,
                                         cleanup_runner=cleanup)
        with self.assertRaises(TimeoutError):
            executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0][:3], ["docker", "rm", "-f"])
        self.assertTrue(cleaned[0][3].startswith("agentsentinel-"))

    def test_interruption_also_removes_container(self):
        cleaned = []

        def interrupted_runner(command, **kwargs):
            raise KeyboardInterrupt()

        def cleanup(command, **kwargs):
            cleaned.append(command)
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=interrupted_runner,
                                         cleanup_runner=cleanup)
        with self.assertRaises(KeyboardInterrupt):
            executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertEqual(len(cleaned), 1)


if __name__ == "__main__":
    unittest.main()
