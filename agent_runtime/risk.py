"""Bounded governance driven by real gateway outcomes.

This deterministic signal is not the research L4 machine-learning model.
L2 remains authoritative: a score can stop future proposals, never allow a
request that policy denied.
"""

from __future__ import annotations

from dataclasses import dataclass

from .gateway import GatewayResult
from .effectseal import EffectReceipt


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    action: str
    denied_calls: int
    incidents: int
    signals: tuple[str, ...]


class RiskGovernor:
    def __init__(self) -> None:
        self.denied_calls = 0
        self.incidents = 0
        self.score = 0
        self.signals: list[str] = []
        self.effect_violation = False

    def _assessment(self) -> RiskAssessment:
        action = ("STOP" if self.effect_violation or self.incidents >= 2 else
                  "REVIEW" if self.score >= 50 else "MONITOR")
        return RiskAssessment(self.score, action, self.denied_calls, self.incidents,
                              tuple(self.signals))

    def observe(self, result: GatewayResult) -> RiskAssessment:
        if result.decision == "DENY":
            self.denied_calls += 1
            self.incidents += 1
            weight = {
                "PATH_OUT_OF_SCOPE": 60,
                "NETWORK_EXECUTION_DISABLED": 80,
                "COMMAND_EXECUTION_DISABLED": 70,
                "COMMAND_OUT_OF_SCOPE": 70,
                "UNKNOWN_TOOL": 50,
            }.get(result.reason_code, 35)
            self.score = min(100, self.score + weight)
            self.signals.append(result.reason_code)
        elif not result.executed:
            self.incidents += 1
            self.score = min(100, self.score + 30)
            self.signals.append("EXECUTION_FAILED")
        return self._assessment()

    def observe_effect(self, receipt: EffectReceipt) -> RiskAssessment:
        """Stop subsequent calls after a verified out-of-scope effect attempt."""
        if receipt.verdict == "VIOLATION":
            self.effect_violation = True
            self.incidents += 1
            self.score = 100
            self.signals.append("EFFECTSEAL_VIOLATION")
        elif receipt.verdict == "INCOMPLETE":
            self.score = max(50, self.score)
            self.signals.append("TELEMETRY_INCOMPLETE")
        return self._assessment()
