import subprocess
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from agent_runtime.docker_executor import DockerCommandExecutor, OutputLimitExceeded, run_bounded
from agent_runtime.gateway import AgentToolGateway, JsonlAuditSink
from agent_runtime.policy import TaskPolicy


PINNED_IMAGE = "sha256:" + "a" * 64


class DockerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "README.md").write_bytes(b"safe")
        (self.root / "summary.py").write_bytes(b"print('summary')\n")
        (self.root / ".env").write_bytes(b"DEMO_SECRET=synthetic")
        self.policy = TaskPolicy(self.root, ("README.md", "summary.py"),
                                 allowed_commands=(("python", "summary.py"),),
                                 read_content_sha256=(
                                     ("README.md", hashlib.sha256(b"safe").hexdigest()),
                                     ("summary.py", hashlib.sha256(b"print('summary')\n").hexdigest()),
                                 ))

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

    def test_streaming_runner_stops_oversized_host_output(self):
        output_path = self.root / "bounded-output.log"
        command = [sys.executable, "-c", "import sys; sys.stdout.write('X' * 500000)"]
        with output_path.open("wb") as output:
            with self.assertRaises(OutputLimitExceeded):
                run_bounded(command, stdout=output, timeout=5, output_limit=1024)
        self.assertEqual(output_path.stat().st_size, 1024)

    def test_streaming_runner_stops_small_overflow_before_child_timeout(self):
        output_path = self.root / "slow-overflow.log"
        command = [sys.executable, "-c",
                   "import sys,time; sys.stdout.buffer.write(b'X'*1025); "
                   "sys.stdout.flush(); time.sleep(5)"]
        started = time.monotonic()
        with output_path.open("wb") as output:
            with self.assertRaises(OutputLimitExceeded):
                run_bounded(command, stdout=output, timeout=4, output_limit=1024)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(output_path.stat().st_size, 1024)

    def test_hardlink_to_unlisted_secret_is_rejected_before_container_start(self):
        (self.root / "README.md").unlink()
        try:
            (self.root / "README.md").hardlink_to(self.root / ".env")
        except OSError:
            self.skipTest("hardlink creation unavailable")
        calls = []

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=fake_runner)
        with self.assertRaises(PermissionError):
            executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertEqual(calls, [])

    def test_regular_file_swap_to_secret_is_rejected_before_container_start(self):
        # A normal file replacement is not caught by no-follow checks alone.
        (self.root / "README.md").write_bytes((self.root / ".env").read_bytes())
        calls = []

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=fake_runner)
        with self.assertRaisesRegex(PermissionError, "content changed"):
            executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertEqual(calls, [])

    def test_docker_rejects_policy_without_complete_content_manifest(self):
        policy = TaskPolicy(self.root, ("README.md", "summary.py"),
                            allowed_commands=(("python", "summary.py"),))
        executor = DockerCommandExecutor(PINNED_IMAGE,
            process_runner=lambda *_args, **_kwargs: self.fail("Docker must not start"))
        with self.assertRaisesRegex(PermissionError, "digest for every"):
            executor.execute("execute_command", {"argv": ["python", "summary.py"]}, policy)

    def test_concurrent_regular_file_replacement_never_enters_snapshot(self):
        started = threading.Event()
        stop = threading.Event()
        swaps = []
        permitted_snapshots = []

        def replace_readme():
            started.set()
            for index in range(400):
                if stop.is_set():
                    break
                candidate = self.root / f"incoming-{index}.tmp"
                candidate.write_bytes(b"DEMO_SECRET=synthetic" if index % 2 else b"safe")
                try:
                    os.replace(candidate, self.root / "README.md")
                    swaps.append(index)
                    time.sleep(0.001)
                except OSError:
                    candidate.unlink(missing_ok=True)

        def fake_runner(command, **kwargs):
            mount = command[command.index("--mount") + 1]
            source = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
            data = (source / "README.md").read_bytes()
            permitted_snapshots.append(data)
            self.assertEqual(data, b"safe")
            kwargs["stdout"].write(b"ok\n")
            return subprocess.CompletedProcess(command, 0)

        worker = threading.Thread(target=replace_readme)
        worker.start()
        self.assertTrue(started.wait(2))
        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=fake_runner)
        try:
            for _ in range(100):
                try:
                    executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
                except PermissionError:
                    pass
        finally:
            stop.set()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(swaps)
        self.assertTrue(permitted_snapshots)
        self.assertNotIn(b"DEMO_SECRET=synthetic", permitted_snapshots)

    @unittest.skipUnless(sys.platform == "win32", "requires Windows handle path verification")
    def test_windows_swap_to_unlisted_file_is_rejected_before_container_start(self):
        try:
            probe = self.root / "probe-link"
            probe.symlink_to(self.root / ".env")
            probe.unlink()
        except OSError:
            self.skipTest("symlink creation unavailable")
        original_open = open
        swapped = False

        def swap_before_open(path, *args, **kwargs):
            nonlocal swapped
            if Path(path) == self.root / "README.md" and not swapped:
                swapped = True
                (self.root / "README.md").unlink()
                (self.root / "README.md").symlink_to(self.root / ".env")
            return original_open(path, *args, **kwargs)

        calls = []

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=fake_runner)
        with patch("builtins.open", side_effect=swap_before_open):
            with self.assertRaises(PermissionError):
                executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertTrue(swapped)
        self.assertEqual(calls, [])

    def test_output_limit_removes_named_container(self):
        cleaned = []

        def oversized(_command, **_kwargs):
            raise OutputLimitExceeded("container output exceeded task limit")

        def cleanup(command, **_kwargs):
            cleaned.append(command)
            return subprocess.CompletedProcess(command, 0)

        executor = DockerCommandExecutor(PINNED_IMAGE, process_runner=oversized,
                                         cleanup_runner=cleanup)
        with self.assertRaises(OutputLimitExceeded):
            executor.execute("execute_command", {"argv": ["python", "summary.py"]}, self.policy)
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0][:3], ["docker", "rm", "-f"])


if __name__ == "__main__":
    unittest.main()
