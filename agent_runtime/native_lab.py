"""Opt-in per-action Linux cgroup and eBPF observation for the lab.

This observes three syscall entry probes, so it records attempts and partial
coverage. It never turns an absence of events into proof of no effects.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid

from .lab_tools import LabPolicy


def required() -> bool:
    return os.environ.get("AGENTSENTINEL_NATIVE_L3_REQUIRED") == "1"


def availability() -> dict:
    if sys.platform != "linux":
        return {"available": False, "reason": "LINUX_EBPF_HOST_REQUIRED"}
    parent = Path(os.environ.get("AGENTSENTINEL_CGROUP_PARENT", "/sys/fs/cgroup/agentsentinel"))
    if not (Path("/sys/fs/cgroup/cgroup.controllers").is_file() and parent.is_dir()
            and os.access(parent, os.W_OK)):
        return {"available": False, "reason": "DELEGATED_CGROUP_UNAVAILABLE"}
    kernel = Path(__file__).resolve().parents[1] / "l3_ebpf" / "kernel"
    if not ((kernel / "execve.bpf.o").is_file() and (kernel / "libnative_loader.so").is_file()):
        return {"available": False, "reason": "EBPF_COLLECTOR_NOT_BUILT"}
    return {"available": True, "reason": "NATIVE_COLLECTOR_FILES_READY"}


class NativeExecutionError(RuntimeError):
    pass


class NativeLabExecutor:
    """Trusted lab tools in a single-use child; event scope is a unique cgroup."""

    def __init__(self, *, run_id: str, workspace: Path, artifacts: Path,
                 profile: str, untrusted_readme: bool):
        self.run_id = run_id
        self.workspace = workspace
        self.artifacts = artifacts
        self.profile = profile
        self.untrusted_readme = untrusted_readme
        self.effects: list[dict] = []
        self.last_native: dict | None = None
        self.request_id: str | None = None

    def begin(self, request_id: str) -> None:
        self.request_id = request_id
        self.last_native = None

    def execute(self, tool_name: str, arguments: dict, policy: LabPolicy) -> str:
        if not self.request_id or not policy.decide(tool_name, arguments).allowed:
            raise PermissionError("NATIVE_ACTION_NOT_AUTHORIZED")
        available = availability()
        if not available["available"]:
            raise NativeExecutionError(available["reason"])
        # Imports are intentionally delayed so portable Windows runs need no BPF stack.
        from l3_ebpf.namespace.scope import AgentScopeManager
        from l3_ebpf.userspace.collector import NativeL3Collector
        from l3_ebpf.userspace.health import TelemetryHealthMonitor

        parent = Path(os.environ.get("AGENTSENTINEL_CGROUP_PARENT", "/sys/fs/cgroup/agentsentinel"))
        group = parent / f"lab-{uuid.uuid4().hex}"
        collector = NativeL3Collector(AgentScopeManager(), TelemetryHealthMonitor())
        events = []
        collector.register_callback(events.append)
        process = None
        polling = None
        stop = threading.Event()
        poll_errors: list[str] = []
        registered = False
        attached = False
        group.mkdir(mode=0o700)
        try:
            collector.start()
            attached = True
            process = subprocess.Popen([sys.executable, "-m", "agent_runtime.native_worker"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL,
                                       cwd=str(Path(__file__).resolve().parents[1]))
            # The worker is blocked reading stdin. Move it before supplying work.
            (group / "cgroup.procs").write_text(str(process.pid), encoding="ascii")
            cgroup_id = group.stat().st_ino
            collector.register_agent(self.request_id, cgroup_id, process.pid)
            registered = True

            def poll() -> None:
                while not stop.is_set():
                    try:
                        collector.poll(50)
                    except Exception as exc:
                        poll_errors.append(type(exc).__name__)
                        stop.set()

            polling = threading.Thread(target=poll, name="agentsentinel-native-poll", daemon=True)
            polling.start()
            packet = {"workspace": str(self.workspace), "artifacts": str(self.artifacts),
                      "profile": self.profile, "policy_sha256": policy.policy_hash,
                      "untrusted_readme": self.untrusted_readme,
                      "tool": tool_name, "arguments": arguments}
            encoded = (json.dumps(packet, separators=(",", ":")) + "\n").encode()
            if len(encoded) > 32768:
                raise NativeExecutionError("WORKER_PACKET_TOO_LARGE")
            try:
                output, _ = process.communicate(encoded, timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise NativeExecutionError("NATIVE_WORKER_TIMEOUT") from None
            # Drain buffered events before detaching. A poll fault remains visible.
            time.sleep(0.1)
            stop.set()
            polling.join(timeout=2)
            if polling.is_alive() or poll_errors:
                raise NativeExecutionError("NATIVE_COLLECTOR_POLL_FAILED")
            health = collector.health_monitor
            attempts = []
            for event in events[:64]:
                target = event.executable or ""
                if target.startswith(str(self.workspace)):
                    target = "workspace/" + target[len(str(self.workspace)):].lstrip("/")
                elif target.startswith(str(self.artifacts)):
                    target = "artifacts/" + target[len(str(self.artifacts)):].lstrip("/")
                elif event.syscall_name == "connect" and event.destination_ip:
                    target = f"{event.destination_ip}:{event.destination_port}"
                else:
                    target = "<host-runtime-or-relative-path>"
                attempts.append({"syscall": event.syscall_name, "target": target[:200],
                                 "outcome": "ATTEMPTED", "pid": event.pid})
            self.last_native = {"mode": "EBPF_CGROUP_ENTRY_PROBES", "attached": attached,
                                "request_id": self.request_id, "cgroup_id": cgroup_id,
                                "attempt_count": len(events), "attempts": attempts,
                                "dropped_events": health.ringbuf_overflows,
                                "decode_errors": health.decode_errors,
                                "coverage": "PARTIAL_ENTRY_PROBES",
                                "valid": bool(events) and not health.ringbuf_overflows and not health.decode_errors}
            if not self.last_native["valid"]:
                raise NativeExecutionError("NATIVE_TELEMETRY_INCOMPLETE")
            if len(output) > 65536 or process.returncode != 0:
                raise NativeExecutionError("NATIVE_WORKER_FAILED")
            reply = json.loads(output)
            if not reply.get("ok") or not isinstance(reply.get("effects"), list) or not isinstance(reply.get("output"), str):
                raise NativeExecutionError("NATIVE_WORKER_REJECTED_ACTION")
            self.effects.extend(reply["effects"])
            return reply["output"]
        finally:
            stop.set()
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            if polling is not None:
                polling.join(timeout=2)
            if registered:
                collector.unregister_agent(self.request_id)
            if attached:
                collector.stop()
            # Never remove a populated cgroup. Report cleanup failures to the
            # operator; the service must not reuse its identity for another run.
            group.rmdir()
