"""Windows Job Object containment for one gateway-authorized lab action.

The worker is trusted application code. Job limits bound resources and process
lifetime; the gateway and LabPolicy still enforce file and tool permissions.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Callable, Mapping

from .lab_tools import LabPolicy
from .windows_etw import EtwActionObserver
from .windows_etw_broker import BrokerEtwActionObserver, configured as etw_broker_configured


MEMORY_LIMIT_BYTES = 384 * 1024 * 1024
ACTION_TIMEOUT_SECONDS = 10


def required() -> bool:
    return os.environ.get("AGENTSENTINEL_WINDOWS_JOB_REQUIRED") == "1"


def availability() -> dict:
    if sys.platform != "win32":
        return {"available": False, "reason": "WINDOWS_HOST_REQUIRED"}
    try:
        import win32job  # noqa: F401
        import win32api  # noqa: F401
        import win32con  # noqa: F401
    except ImportError:
        return {"available": False, "reason": "PYWIN32_UNAVAILABLE"}
    return {"available": True, "reason": "WINDOWS_JOB_API_READY"}


class WindowsJobError(RuntimeError):
    pass


def _worker_environment() -> dict[str, str]:
    allowed = {"systemroot", "windir", "temp", "tmp", "path", "pathext", "comspec"}
    values = {key: value for key, value in os.environ.items() if key.lower() in allowed}
    values.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    return values


class WindowsJobExecutor:
    def __init__(self, *, run_id: str, workspace: Path, artifacts: Path, profile: str,
                 untrusted_readme: bool, cancelled: threading.Event,
                 memory_limit_bytes: int = MEMORY_LIMIT_BYTES,
                 timeout_seconds: int = ACTION_TIMEOUT_SECONDS,
                 on_event: Callable[[str, dict], None] | None = None):
        self.run_id, self.workspace, self.artifacts = run_id, workspace, artifacts
        self.profile, self.untrusted_readme = profile, untrusted_readme
        self.cancelled = cancelled
        if not 128 * 1024 * 1024 <= memory_limit_bytes <= 1024 * 1024 * 1024:
            raise ValueError("WINDOWS_JOB_MEMORY_LIMIT_INVALID")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("WINDOWS_JOB_TIMEOUT_INVALID")
        self.memory_limit_bytes = memory_limit_bytes
        self.timeout_seconds = timeout_seconds
        self.on_event = on_event
        self.effects: list[dict] = []
        self.request_id: str | None = None
        self.last_windows: dict | None = None

    def begin(self, request_id: str) -> None:
        self.request_id = request_id
        self.last_windows = None

    def _worker_command(self) -> list[str]:
        return [sys.executable, "-m", "agent_runtime.native_worker"]

    def _record(self, event_type: str, **data: object) -> None:
        if self.on_event is not None:
            self.on_event(event_type, data)

    def execute(self, tool_name: str, arguments: Mapping[str, object], policy: LabPolicy) -> str:
        if not self.request_id or not policy.decide(tool_name, arguments).allowed:
            raise PermissionError("WINDOWS_ACTION_NOT_AUTHORIZED")
        if not availability()["available"]:
            raise WindowsJobError("WINDOWS_JOB_API_UNAVAILABLE")
        import win32api
        import win32con
        import win32job

        started = time.monotonic()
        receipt: dict = {"mode": "WINDOWS_JOB_OBJECT", "request_id": self.request_id,
                         "worker_started": False, "job_assigned": False, "action_released": False,
                         "completed": False, "termination_reason": "WORKER_SETUP_FAILED",
                         "limits": {"process_memory_bytes": self.memory_limit_bytes,
                                    "active_processes": 1, "wall_clock_seconds": self.timeout_seconds,
                                    "kill_on_close": True}}
        self.last_windows = receipt
        job = None
        process = None
        process_handle = None
        observer = None
        try:
            job = win32job.CreateJobObject(None, "")
            self._record("windows_job_created")
            info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
            basic = info["BasicLimitInformation"]
            basic["LimitFlags"] = (win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                   win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                                   win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            basic["ActiveProcessLimit"] = 1
            info["ProcessMemoryLimit"] = self.memory_limit_bytes
            win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
            applied = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
            if (applied["BasicLimitInformation"]["ActiveProcessLimit"] != 1 or
                    applied["ProcessMemoryLimit"] != self.memory_limit_bytes or
                    applied["BasicLimitInformation"]["LimitFlags"] & basic["LimitFlags"] != basic["LimitFlags"]):
                raise WindowsJobError("WINDOWS_JOB_LIMITS_NOT_APPLIED")
            self._record("windows_job_limits_applied", **receipt["limits"])

            observer_class = BrokerEtwActionObserver if etw_broker_configured() else EtwActionObserver
            observer = observer_class(self.artifacts.parent / "telemetry", self.request_id)
            receipt["etw"] = observer.start()
            self._record("windows_etw_started", status=receipt["etw"]["status"],
                         reason=receipt["etw"].get("reason"), coverage=receipt["etw"]["coverage"])
            receipt["worker_launch_started_at_ns"] = time.time_ns()
            process = subprocess.Popen(self._worker_command(),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL,
                                       cwd=str(Path(__file__).resolve().parents[1]),
                                       env=_worker_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
            receipt["worker_started"] = True
            receipt["worker_pid"] = process.pid
            receipt["worker_started_at_ns"] = time.time_ns()
            self._record("windows_worker_started", worker_pid=process.pid)
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE |
                win32con.PROCESS_QUERY_INFORMATION, False, process.pid)
            win32job.AssignProcessToJobObject(job, process_handle)
            if not win32job.IsProcessInJob(process_handle, job):
                raise WindowsJobError("WINDOWS_JOB_ASSIGNMENT_UNVERIFIED")
            receipt["job_assigned"] = True
            self._record("windows_worker_assigned", worker_pid=process.pid)

            packet = {"workspace": str(self.workspace), "artifacts": str(self.artifacts),
                      "profile": self.profile, "policy_sha256": policy.policy_hash,
                      "untrusted_readme": self.untrusted_readme,
                      "tool": tool_name, "arguments": dict(arguments)}
            encoded = (json.dumps(packet, separators=(",", ":")) + "\n").encode()
            if len(encoded) > 32768:
                raise WindowsJobError("WORKER_PACKET_TOO_LARGE")
            if self.cancelled.is_set():
                receipt["termination_reason"] = "CANCELLED_BEFORE_ACTION"
                raise WindowsJobError("CANCELLED_BEFORE_ACTION")
            assert process.stdin is not None
            process.stdin.write(encoded)
            process.stdin.close()
            process.stdin = None
            receipt["action_released"] = True
            self._record("windows_action_released", worker_pid=process.pid, tool=tool_name)
            deadline = started + self.timeout_seconds
            while True:
                if self.cancelled.is_set():
                    receipt["termination_reason"] = "CANCELLED"
                    raise WindowsJobError("WINDOWS_WORKER_CANCELLED")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    receipt["termination_reason"] = "TIMEOUT_TERMINATED"
                    raise WindowsJobError("WINDOWS_WORKER_TIMEOUT")
                try:
                    output, _ = process.communicate(timeout=min(0.2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            receipt["exit_code"] = process.returncode
            if len(output) > 65536 or process.returncode != 0:
                receipt["termination_reason"] = "WORKER_EXITED_WITH_ERROR"
                raise WindowsJobError("WINDOWS_WORKER_FAILED")
            reply = json.loads(output)
            if (not reply.get("ok") or not isinstance(reply.get("effects"), list)
                    or not isinstance(reply.get("output"), str)):
                receipt["termination_reason"] = "WORKER_REJECTED_ACTION"
                raise WindowsJobError("WINDOWS_WORKER_REJECTED_ACTION")
            self.effects.extend(reply["effects"])
            receipt["completed"] = True
            receipt["termination_reason"] = "COMPLETED"
            return reply["output"]
        except (OSError, ValueError) as exc:
            raise WindowsJobError(type(exc).__name__) from None
        finally:
            if process is not None and process.poll() is None:
                if job is not None and receipt["job_assigned"]:
                    win32job.TerminateJobObject(job, 1)
                else:
                    process.kill()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            if observer is not None:
                receipt["etw"] = observer.stop(process.pid if process is not None else None,
                                                receipt.get("worker_launch_started_at_ns"))
                self._record("windows_etw_finalized", status=receipt["etw"]["status"],
                             reason=receipt["etw"].get("reason"),
                             coverage=receipt["etw"]["coverage"],
                             correlated=receipt["etw"].get("correlated", False))
            if job is not None:
                try:
                    usage = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
                    receipt["peak_process_memory_bytes"] = usage.get("PeakProcessMemoryUsed")
                except Exception:
                    receipt["peak_process_memory_bytes"] = None
            if process_handle is not None:
                process_handle.Close()
            if job is not None:
                job.Close()
            receipt["duration_ms"] = round((time.monotonic() - started) * 1000)
            self._record("windows_worker_finished", worker_pid=receipt.get("worker_pid"),
                         job_assigned=receipt["job_assigned"],
                         action_released=receipt["action_released"],
                         completed=receipt["completed"],
                         termination_reason=receipt["termination_reason"],
                         duration_ms=receipt["duration_ms"])
