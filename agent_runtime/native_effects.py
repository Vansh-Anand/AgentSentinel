"""Translate native syscall attempts into fail-closed EffectSeal evidence.

This bridge does not attach eBPF. Callers must supply events from an attached
NativeL3Collector and explicitly establish process-tree coverage. In particular,
a cgroup match alone is not proof that every child process was observed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Iterable

from common.events.schemas import SyscallEvent

from .effectseal import CollectorCoverage, EffectEnvelope, EffectReceipt, Observation, reconcile


@dataclass(frozen=True)
class NativeSealResult:
    receipt: EffectReceipt
    observations: tuple[Observation, ...]
    coverage: CollectorCoverage


def _workspace_path(path: str | None, sandbox_root: str) -> str | None:
    if not path or not path.startswith("/") or "\x00" in path:
        return None
    root = PurePosixPath(sandbox_root)
    target = PurePosixPath(path)
    if not root.is_absolute() or ".." in target.parts:
        return None
    if not target.is_relative_to(root):
        return target.as_posix()
    relative = target.relative_to(root).as_posix()
    return relative if relative != "." else None


def seal_native_attempts(
    envelope: EffectEnvelope,
    events: Iterable[SyscallEvent],
    *,
    expected_cgroup_id: int,
    sandbox_root: str,
    attached: bool,
    process_tree_correlated: bool,
    dropped_events: int,
    decode_errors: int,
    authorized: bool,
    executed: bool,
) -> NativeSealResult:
    """Map entry tracepoints to attempted effects; never infer syscall success."""
    if expected_cgroup_id <= 0 or dropped_events < 0 or decode_errors < 0:
        raise ValueError("invalid native collector health or cgroup")
    observations: list[Observation] = []
    # Three entry probes cannot establish full file/network coverage or syscall
    # outcomes. They may prove a violation, but never a clean MATCH.
    reasons: set[str] = {"NATIVE_PROBE_COVERAGE_PARTIAL"}
    previous_timestamp = -1
    for event in events:
        if (event.telemetry_source != "EBPF" or event.agent_id != envelope.request_id
                or event.cgroup_id != expected_cgroup_id):
            reasons.add("NATIVE_CORRELATION_FAILED")
            continue
        timestamp = event.monotonic_timestamp_ns
        if timestamp is None or timestamp < previous_timestamp:
            reasons.add("NATIVE_EVENT_ORDER_UNKNOWN")
        if timestamp is not None:
            previous_timestamp = timestamp
        targets: list[tuple[str, str]] = []
        if event.syscall_name == "execve":
            if event.executable and event.executable.startswith("/"):
                targets.append(("exec", event.executable))
            else:
                reasons.add("NATIVE_TARGET_UNRESOLVED")
        elif event.syscall_name == "openat":
            relative = _workspace_path(event.executable, sandbox_root)
            if relative is None:
                # Relative dirfd paths and host runtime paths need separate
                # resolution/allowlists; do not silently claim a complete match.
                reasons.add("NATIVE_TARGET_UNRESOLVED")
            elif event.flags is None:
                reasons.add("NATIVE_ACCESS_MODE_UNKNOWN")
            else:
                access = event.flags & 3
                if access in (0, 2):
                    targets.append(("file_read", relative))
                if access in (1, 2) or event.flags & (0o100 | 0o1000 | 0o2000):
                    targets.append(("file_write", relative))
        elif event.syscall_name == "connect":
            if event.destination_ip is None or event.destination_port is None:
                reasons.add("NATIVE_TARGET_UNRESOLVED")
            else:
                host = f"[{event.destination_ip}]" if ":" in event.destination_ip else event.destination_ip
                targets.append(("network_connect", f"{host}:{event.destination_port}"))
        else:
            reasons.add("NATIVE_EVENT_UNSUPPORTED")
        for kind, target in targets:
            observations.append(Observation(envelope.run_id, envelope.request_id,
                                            envelope.sandbox_id, kind, target,
                                            "ATTEMPTED", len(observations) + 1))
    coverage = CollectorCoverage(
        "native_linux", attached, process_tree_correlated, dropped_events,
        False,
    )
    receipt = reconcile(envelope, tuple(observations), coverage,
                        authorized=authorized, executed=executed)
    extra = set(receipt.reason_codes) | reasons
    if decode_errors:
        extra.add("NATIVE_DECODE_ERRORS")
    if receipt.verdict == "MATCH" and extra:
        # Defensive against a future reconciler change.
        receipt = replace(receipt, verdict="INCOMPLETE")
    receipt = replace(receipt, reason_codes=tuple(sorted(extra)))
    return NativeSealResult(receipt, tuple(observations), coverage)
