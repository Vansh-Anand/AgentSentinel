"""EffectSeal's deterministic reconciliation core.

Only a collector that really observed the process tree may claim native MATCH.
The local read-only demo has no OS collector and therefore reports INCOMPLETE.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


EffectKind = Literal["file_read", "file_write", "exec", "network_connect"]
Verdict = Literal["MATCH", "VIOLATION", "INCOMPLETE", "NOT_EXECUTED"]


@dataclass(frozen=True)
class EffectEnvelope:
    run_id: str
    request_id: str
    sandbox_id: str
    policy_sha256: str
    allowed_effects: frozenset[tuple[EffectKind, str]]


@dataclass(frozen=True)
class Observation:
    run_id: str
    request_id: str
    sandbox_id: str
    kind: EffectKind
    target: str
    outcome: Literal["ATTEMPTED", "COMPLETED", "DENIED"]
    sequence: int = 0


@dataclass(frozen=True)
class CollectorCoverage:
    source: Literal["fixture", "native_linux", "none"]
    attached: bool
    process_tree_correlated: bool
    dropped_events: int
    complete: bool


@dataclass(frozen=True)
class EffectReceipt:
    verdict: Verdict
    reason_codes: tuple[str, ...]
    observation_count: int
    telemetry_source: str


def reconcile(
    envelope: EffectEnvelope,
    observations: tuple[Observation, ...],
    coverage: CollectorCoverage,
    *,
    authorized: bool,
    executed: bool,
) -> EffectReceipt:
    """Unexpected attempts are violations even when the sandbox denied them.

    Missing coverage wins over MATCH. An observed violation is still reported
    even when other events may have been lost; reasons include telemetry loss.
    """
    if not authorized:
        if observations:
            return EffectReceipt("VIOLATION", ("DENIED_ACTION_OBSERVED",),
                                 len(observations), coverage.source)
        return EffectReceipt("NOT_EXECUTED", (), 0, coverage.source)
    reasons: set[str] = set()
    if not executed:
        reasons.add("EXECUTION_OUTCOME_UNKNOWN")
    if not observations:
        reasons.add("NO_OBSERVATIONS")
    ordered = [event.sequence for event in observations]
    if len(ordered) > 1 and (any(value <= 0 for value in ordered) or ordered != sorted(set(ordered))):
        reasons.add("EVENT_ORDER_INVALID")
    for event in observations:
        if (event.run_id, event.request_id, event.sandbox_id) != (
            envelope.run_id, envelope.request_id, envelope.sandbox_id
        ):
            reasons.add("CORRELATION_MISMATCH")
            continue
        if (event.kind, event.target) not in envelope.allowed_effects:
            reasons.add("EFFECT_OUT_OF_SCOPE")
    if not coverage.attached or not coverage.complete or not coverage.process_tree_correlated:
        reasons.add("TELEMETRY_INCOMPLETE")
    if coverage.dropped_events > 0:
        reasons.add("EVENTS_DROPPED")
    if coverage.dropped_events < 0:
        raise ValueError("dropped_events cannot be negative")
    if "EFFECT_OUT_OF_SCOPE" in reasons:
        verdict: Verdict = "VIOLATION"
    elif reasons:
        verdict = "INCOMPLETE"
    else:
        verdict = "MATCH"
    return EffectReceipt(verdict, tuple(sorted(reasons)), len(observations), coverage.source)
