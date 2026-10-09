"""Contract tests for the native map/health bridge; no kernel claim on Windows."""

import unittest
import ctypes
import socket

from l3_ebpf.namespace.scope import AgentScopeManager
from l3_ebpf.userspace.collector import CSyscallEvent, NativeL3Collector
from l3_ebpf.userspace.health import TelemetryHealthMonitor


class FakeNativeLibrary:
    def __init__(self):
        self.updates = []
        self.drops = 0
        self.poll_result = 0

    def update_cgroup_filter(self, handle, cgroup_id, enabled):
        self.updates.append((cgroup_id, enabled))
        return 0

    def poll_ringbuffer(self, handle, timeout_ms):
        return self.poll_result

    def read_dropped_events(self, handle):
        return self.drops


class CollectorBridgeTests(unittest.TestCase):
    def setUp(self):
        self.scope = AgentScopeManager()
        self.health = TelemetryHealthMonitor()
        self.collector = NativeL3Collector(self.scope, self.health)
        self.lib = FakeNativeLibrary()
        self.collector._lib = self.lib
        self.collector._handle = object()

    def test_cgroup_scope_is_installed_before_registration_and_removed(self):
        self.collector.register_agent("run-1", 123, 42)
        self.assertEqual(self.scope.resolve_cgroup(123), "run-1")
        self.collector.unregister_agent("run-1")
        self.assertIsNone(self.scope.resolve_cgroup(123))
        self.assertEqual(self.lib.updates, [(123, 1), (123, 0)])

    def test_kernel_drop_counter_is_reflected_in_health(self):
        self.lib.drops = 2
        self.collector.poll()
        self.collector.poll()
        self.assertEqual(self.health.ringbuf_overflows, 2)
        self.lib.drops = 3
        self.collector.poll()
        self.assertEqual(self.health.ringbuf_overflows, 3)

    def test_poll_error_does_not_appear_healthy(self):
        self.lib.poll_result = -5
        with self.assertRaises(RuntimeError):
            self.collector.poll()
        self.assertEqual(self.health.decode_errors, 1)

    def test_decodes_file_and_ipv4_network_attempts(self):
        self.collector.register_agent("run-1", 123, 42)
        observed = []
        self.collector.register_callback(observed.append)
        opened = CSyscallEvent()
        opened.type = 2
        opened.timestamp_ns = 100
        opened.pid = 42
        opened.tid = 42
        opened.cgroup_id = 123
        opened.executable = b"/workspace/README.md"
        opened.dirfd = -100
        opened.open_flags = 0
        self.collector._event_handler(ctypes.pointer(opened), ctypes.sizeof(opened))
        connected = CSyscallEvent()
        connected.type = 3
        connected.timestamp_ns = 101
        connected.pid = 42
        connected.tid = 42
        connected.cgroup_id = 123
        connected.addr_family = socket.AF_INET
        connected.port_be = socket.htons(443)
        connected.address[:4] = (192, 0, 2, 1)
        connected.address_valid = 1
        self.collector._event_handler(ctypes.pointer(connected), ctypes.sizeof(connected))
        self.assertEqual([item.syscall_name for item in observed], ["openat", "connect"])
        self.assertEqual(observed[0].executable, "/workspace/README.md")
        self.assertIsNone(observed[0].return_value)
        self.assertEqual(observed[1].destination_ip, "192.0.2.1")
        self.assertEqual(observed[1].destination_port, 443)
        self.assertEqual(observed[1].agent_id, "run-1")
        self.assertEqual(self.health.decode_errors, 0)

    def test_rejects_wrong_native_struct_size(self):
        event = CSyscallEvent()
        self.collector._event_handler(ctypes.pointer(event), ctypes.sizeof(event) - 1)
        self.assertEqual(self.health.decode_errors, 1)


if __name__ == "__main__":
    unittest.main()
