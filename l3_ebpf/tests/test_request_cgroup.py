"""Controlled request-cgroup isolation in a privileged disposable Linux VM.

This proves one child and its /bin/echo descendant are attributed to the
registered cgroup while a simultaneous sibling cgroup is not. It does not
establish full process-tree coverage for arbitrary agents or syscall outcomes.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from l3_ebpf.namespace.scope import AgentScopeManager
from l3_ebpf.userspace.collector import NativeL3Collector
from l3_ebpf.userspace.health import TelemetryHealthMonitor


CHILD = """
import os
from pathlib import Path
import socket
import subprocess
import sys

sys.stdin.buffer.read(1)
Path(sys.argv[1], 'cgroup.procs').write_text(str(os.getpid()))
subprocess.run(['/bin/echo', 'synthetic-request'], check=True, stdout=subprocess.DEVNULL)
with Path(sys.argv[2]).open('rb') as stream:
    assert stream.read() == b'synthetic-only\\n'
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(0.2)
    client.connect_ex(('127.0.0.1', 9))
"""


def current_cgroup_dir() -> Path:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            relative = line.partition("0::")[2].lstrip("/")
            return Path("/sys/fs/cgroup") / relative
    raise RuntimeError("cgroups v2 membership could not be found")


def main() -> None:
    if sys.platform != "linux":
        raise RuntimeError("request cgroup validation requires Linux")
    base = current_cgroup_dir()
    registered_dir = base / f"agentsentinel-request-{uuid.uuid4().hex}"
    control_dir = base / f"agentsentinel-control-{uuid.uuid4().hex}"
    collector = NativeL3Collector(AgentScopeManager(), TelemetryHealthMonitor())
    observed = []
    collector.register_callback(observed.append)
    children: list[subprocess.Popen] = []
    registered = False
    try:
        registered_dir.mkdir(mode=0o700)
        control_dir.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="agentsentinel-request-scope-") as directory:
            source = Path(directory) / "approved.txt"
            source.write_text("synthetic-only\n", encoding="utf-8")
            collector.start()
            children = [
                subprocess.Popen([sys.executable, "-c", CHILD, str(group), str(source)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=False)
                for group in (registered_dir, control_dir)
            ]
            request, control = children
            expected_cgroup = registered_dir.stat().st_ino
            control_cgroup = control_dir.stat().st_ino
            collector.register_agent("synthetic-request", expected_cgroup, request.pid)
            registered = True
            for child in children:
                assert child.stdin is not None
                child.stdin.write(b"1")
                child.stdin.close()
            for child in children:
                child.wait(timeout=10)
                if child.returncode != 0:
                    raise AssertionError(
                        f"synthetic child exited {child.returncode}: "
                        f"{child.stderr.read().decode('utf-8', 'replace') if child.stderr else ''}"
                    )
            for _ in range(30):
                collector.poll(timeout_ms=100)
                if (any(e.syscall_name == "execve" and e.executable == "/bin/echo"
                        for e in observed)
                        and any(e.syscall_name == "openat" and e.executable == str(source)
                                for e in observed)
                        and any(e.syscall_name == "connect" and e.destination_ip == "127.0.0.1"
                                and e.destination_port == 9 for e in observed)):
                    break
            assert observed, "registered request produced no native events"
            assert all(e.agent_id == "synthetic-request" and e.cgroup_id == expected_cgroup
                       for e in observed), "event crossed the request cgroup boundary"
            assert all(e.cgroup_id != control_cgroup and e.pid != control.pid
                       for e in observed), "unregistered control process was attributed"
            # BPF ppid is in the host PID namespace while request.pid is in
            # this container's PID namespace. Cgroup attribution is checked;
            # cross-namespace process-tree correlation remains a separate gate.
            assert any(e.syscall_name == "execve" and e.executable == "/bin/echo"
                       for e in observed), "request child exec was not observed"
            assert any(e.syscall_name == "openat" and e.executable == str(source)
                       for e in observed), "request file open was not observed"
            assert any(e.syscall_name == "connect" and e.destination_ip == "127.0.0.1"
                       and e.destination_port == 9 for e in observed), "request connect was not observed"
            assert collector.health_monitor.ringbuf_overflows == 0, "native ring buffer lost events"
            assert collector.health_monitor.decode_errors == 0, "native event decode failed"
            print("[PASS] Unique cgroup captured a request child and descendant; sibling excluded")
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        if registered:
            collector.unregister_agent("synthetic-request")
        collector.stop()
        for group in (control_dir, registered_dir):
            if group.exists():
                group.rmdir()


if __name__ == "__main__":
    main()
