"""Synthetic bridge contracts; these do not validate a host eBPF attachment."""

import unittest

from common.events.schemas import SyscallEvent

from agent_runtime.effectseal import EffectEnvelope
from agent_runtime.native_effects import seal_native_attempts


class NativeEffectBridgeTests(unittest.TestCase):
    def setUp(self):
        self.envelope = EffectEnvelope(
            "run", "request", "sandbox", "policy",
            frozenset({("file_read", "README.md"), ("exec", "/bin/echo")}),
        )
        self.options = dict(expected_cgroup_id=123, sandbox_root="/workspace",
                            attached=True, process_tree_correlated=True,
                            dropped_events=0, decode_errors=0,
                            authorized=True, executed=True)

    def event(self, syscall: str, **changes):
        values = dict(event_id="event", timestamp_ns=1, layer="L3",
                      trace_id="trace", agent_id="request", pid=42,
                      cgroup_id=123, syscall_name=syscall,
                      monotonic_timestamp_ns=100, telemetry_source="EBPF",
                      executable="/workspace/README.md", flags=0)
        values.update(changes)
        return SyscallEvent(**values)

    def test_allowed_absolute_read_remains_incomplete_with_entry_only_probes(self):
        result = seal_native_attempts(self.envelope, [self.event("openat")], **self.options)
        self.assertEqual(result.receipt.verdict, "INCOMPLETE")
        self.assertIn("NATIVE_PROBE_COVERAGE_PARTIAL", result.receipt.reason_codes)
        self.assertEqual(result.observations[0].target, "README.md")
        self.assertEqual(result.observations[0].outcome, "ATTEMPTED")
        incomplete = seal_native_attempts(self.envelope, [self.event("openat")],
                                          **{**self.options, "process_tree_correlated": False})
        self.assertEqual(incomplete.receipt.verdict, "INCOMPLETE")

    def test_forbidden_file_and_network_attempts_are_violations(self):
        secret = self.event("openat", executable="/workspace/.env")
        network = self.event("connect", executable=None,
                             destination_ip="192.0.2.1", destination_port=443)
        result = seal_native_attempts(self.envelope, [secret, network], **self.options)
        self.assertEqual(result.receipt.verdict, "VIOLATION")
        self.assertEqual([item.target for item in result.observations],
                         [".env", "192.0.2.1:443"])

    def test_outside_absolute_path_is_a_violation(self):
        result = seal_native_attempts(self.envelope,
                                      [self.event("openat", executable="/etc/passwd")],
                                      **self.options)
        self.assertEqual(result.receipt.verdict, "VIOLATION")

    def test_relative_path_cannot_claim_coverage(self):
        result = seal_native_attempts(self.envelope,
                                      [self.event("openat", executable="README.md")],
                                      **self.options)
        self.assertEqual(result.receipt.verdict, "INCOMPLETE")
        self.assertIn("NATIVE_TARGET_UNRESOLVED", result.receipt.reason_codes)

    def test_mismatched_scope_and_loss_fail_closed(self):
        wrong = seal_native_attempts(self.envelope,
                                     [self.event("openat", cgroup_id=456)], **self.options)
        self.assertEqual(wrong.receipt.verdict, "INCOMPLETE")
        self.assertIn("NATIVE_CORRELATION_FAILED", wrong.receipt.reason_codes)
        lost = seal_native_attempts(self.envelope, [self.event("openat")],
                                    **{**self.options, "dropped_events": 1})
        self.assertEqual(lost.receipt.verdict, "INCOMPLETE")
        self.assertIn("EVENTS_DROPPED", lost.receipt.reason_codes)

    def test_write_attempt_cannot_match_read_permission(self):
        result = seal_native_attempts(self.envelope,
                                      [self.event("openat", flags=1)], **self.options)
        self.assertEqual(result.receipt.verdict, "VIOLATION")
        self.assertEqual(result.observations[0].kind, "file_write")


if __name__ == "__main__":
    unittest.main()
