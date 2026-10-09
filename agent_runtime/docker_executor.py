"""Opt-in restricted Linux command executor; requires a running Docker daemon."""

from __future__ import annotations

import re
from pathlib import Path
import subprocess
import tempfile
import uuid
from typing import Callable, Mapping

from .policy import TaskPolicy
from .tools import LocalReadOnlyExecutor


_PINNED_IMAGE = re.compile(r"^(?:[a-zA-Z0-9._/-]+@)?sha256:[0-9a-f]{64}$")


class DockerCommandExecutor:
    """Mount only allowlisted file snapshots, with no network or writable root.

    This is enabled only when the API host configures a pinned image ID. The
    Windows Docker Desktop demo verified the fixed safe and attack fixtures;
    broader escape resistance and hostile-workspace races remain unevaluated.
    """

    def __init__(
        self,
        image: str,
        *,
        timeout_seconds: int = 10,
        process_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        cleanup_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        if not _PINNED_IMAGE.fullmatch(image):
            raise ValueError("Docker image must use a pinned sha256 digest")
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be between 1 and 60")
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.process_runner = process_runner
        self.cleanup_runner = cleanup_runner

    def _remove_container(self, name: str) -> None:
        # The fixed unique name works even when Docker did not write its cidfile.
        try:
            self.cleanup_runner(
                ["docker", "rm", "-f", name], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def execute(self, tool_name: str, arguments: Mapping[str, object], policy: TaskPolicy) -> str:
        if tool_name != "execute_command" or not isinstance(arguments.get("argv"), list):
            raise ValueError("Docker executor accepts a validated command argv only")
        argv = arguments["argv"]
        if tuple(argv) not in policy.allowed_commands:
            raise PermissionError("command is not in task policy")
        with tempfile.TemporaryDirectory(prefix="agentsentinel-container-") as directory:
            base = Path(directory)
            input_dir = base / "input"
            input_dir.mkdir()
            local_reader = LocalReadOnlyExecutor()
            for relative in policy.allowed_read_paths:
                # Snapshot only explicitly authorized files. The untrusted
                # repository and its .env are never mounted wholesale.
                target = input_dir.joinpath(*relative.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(local_reader.execute("read_file", {"path": relative}, policy), encoding="utf-8")
            output_path = base / "output.log"
            name = f"agentsentinel-{uuid.uuid4().hex}"
            command = [
                "docker", "run", "--rm", "--pull", "never",
                "--name", name,
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges=true",
                "--pids-limit", "32", "--memory", "128m", "--cpus", "0.5",
                "--user", "65534:65534", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
                "--mount", f"type=bind,source={input_dir},target=/workspace,readonly",
                "--workdir", "/workspace",
                self.image, *argv,
            ]
            with output_path.open("wb") as output:
                try:
                    completed = self.process_runner(
                        command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                        timeout=self.timeout_seconds, check=False,
                    )
                except subprocess.TimeoutExpired:
                    self._remove_container(name)
                    raise TimeoutError("container command exceeded time limit") from None
                except BaseException:
                    self._remove_container(name)
                    raise
            if output_path.stat().st_size > policy.max_read_bytes:
                raise ValueError("container output exceeded task limit")
            output_text = output_path.read_text(encoding="utf-8", errors="replace")
            if completed.returncode != 0:
                self._remove_container(name)
                raise RuntimeError(f"container exited with status {completed.returncode}")
            return output_text
