import pytest
import sys
import os
import time
import subprocess
import threading
import socket
import tempfile
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from l3_ebpf.namespace.scope import AgentScopeManager
from l3_ebpf.userspace.health import TelemetryHealthMonitor
from l3_ebpf.userspace.collector import NativeL3Collector
from agent_runtime.effectseal import EffectEnvelope
from agent_runtime.native_effects import seal_native_attempts


def current_cgroup_id() -> int:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            relative = line.partition("0::")[2].lstrip("/")
            return (Path("/sys/fs/cgroup") / relative).stat().st_ino
    raise RuntimeError("cgroups v2 membership could not be found")

def test_native_linux_execve():
    print("\n--- L3 Native eBPF Vertical Slice Test ---")
    
    # 1. Platform enforcement
    if sys.platform != 'linux':
        print("[SKIP] Host is not Linux. Native eBPF testing gracefully skipped.")
        return
        
    print("[PASS] Running on Linux.")

    # 2. Check for BTF (vmlinux) availability
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        print("[FAIL] /sys/kernel/btf/vmlinux not found. Kernel BTF is required for CO-RE.")
        sys.exit(1)
    print("[PASS] BTF vmlinux found.")

    # 3. Build the BPF object and loader library
    kernel_dir = os.path.join(os.path.dirname(__file__), "..", "kernel")
    print(f"Building artifacts in {kernel_dir}...")
    build_res = subprocess.run(["make"], cwd=kernel_dir, capture_output=True, text=True)
    if build_res.returncode != 0:
        print(f"[FAIL] Make failed:\n{build_res.stderr}")
        sys.exit(1)
    print("[PASS] Build successful (execve.bpf.o and libnative_loader.so generated).")

    # 4. Start the NativeL3Collector
    sm = AgentScopeManager()
    
    hm = TelemetryHealthMonitor()
    collector = NativeL3Collector(sm, hm)
    
    events = []
    collector.register_callback(lambda e: events.append(e))

    try:
        print("Starting Native Collector...")
        collector.start()
        cgroup_id = current_cgroup_id()
        collector.register_agent("native-validation", cgroup_id, os.getpid())
        print(f"[PASS] Collector attached and cgroup {cgroup_id} registered.")
        try:
            collector.register_agent("other-run", cgroup_id, os.getpid())
        except ValueError:
            pass
        else:
            raise AssertionError("occupied cgroup was accepted for a second run")
        assert sm.resolve_cgroup(cgroup_id) == "native-validation", "duplicate registration changed attribution"
        
        # 5. Trigger a harmless execve
        print("Triggering execve (/bin/echo academiq_native_test)...")
        subprocess.run(["/bin/echo", "academiq_native_test"], capture_output=True)
        
        with tempfile.TemporaryDirectory(prefix="agentsentinel-l3-") as directory:
            test_file = Path(directory) / "approved.txt"
            test_file.write_text("synthetic-only\n", encoding="utf-8")
            with test_file.open("rb") as stream:
                assert stream.read() == b"synthetic-only\n"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(0.2)
                client.connect_ex(("127.0.0.1", 9))

            # All three probes must produce a correlated event. Polling only
            # until the first execve would miss file/network probe failures.
            for _ in range(20):
                collector.poll(timeout_ms=100)
                if (any(e.syscall_name == "execve" and e.executable == "/bin/echo" for e in events)
                        and any(e.syscall_name == "openat" and e.executable == str(test_file)
                                for e in events)
                        and any(e.syscall_name == "connect" and e.destination_ip == "127.0.0.1"
                                and e.destination_port == 9 for e in events)):
                    break
            matching_open = [e for e in events if e.agent_id == "native-validation"
                             and e.cgroup_id == cgroup_id and e.syscall_name == "openat"
                             and e.executable == str(test_file)]
            matching_connect = [e for e in events if e.agent_id == "native-validation"
                                and e.cgroup_id == cgroup_id and e.syscall_name == "connect"
                                and e.destination_ip == "127.0.0.1"
                                and e.destination_port == 9]
        matching = [e for e in events if e.agent_id == "native-validation"
                    and e.cgroup_id == cgroup_id and e.syscall_name == "execve"
                    and e.executable == "/bin/echo"]
        assert matching, "No correlated /bin/echo execve attempt was observed"
        assert matching_open, "No correlated synthetic-file openat attempt was observed"
        assert matching_connect, "No correlated loopback connect attempt was observed"
        assert hm.ringbuf_overflows == 0, "Kernel ring buffer dropped events"
        assert hm.decode_errors == 0, "Native event decode failed"
        envelope = EffectEnvelope(
            "native-validation-run", "native-validation", "native-validation-sandbox",
            "native-validation-policy", frozenset({("exec", "/bin/echo"),
                                                    ("file_read", "approved.txt")}),
        )
        sample = sorted((matching[0], matching_open[0], matching_connect[0]),
                        key=lambda event: event.monotonic_timestamp_ns or 0)
        bridged = seal_native_attempts(
            envelope, sample, expected_cgroup_id=cgroup_id,
            sandbox_root=str(test_file.parent), attached=True,
            process_tree_correlated=False, dropped_events=hm.ringbuf_overflows,
            decode_errors=hm.decode_errors, authorized=True, executed=True,
        )
        assert any(item.kind == "network_connect" and item.target == "127.0.0.1:9"
                   for item in bridged.observations), "Native connect was not normalized"
        assert bridged.receipt.verdict == "VIOLATION", "Unexpected native connect was not flagged"
        print(f"[PASS] Correlated execve/openat/connect attempts with zero measured drops.")
        print("\nRESULT: PASS (native three-probe vertical slice)")
        
    finally:
        collector.unregister_agent("native-validation")
        collector.stop()

if __name__ == "__main__":
    test_native_linux_execve()
