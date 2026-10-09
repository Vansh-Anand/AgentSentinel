"""Bounded agent loop. All model-proposed actions pass through AgentToolGateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from .gateway import AgentToolGateway, GatewayResult
from .risk import RiskAssessment, RiskGovernor
from .effectseal import EffectReceipt


@dataclass(frozen=True)
class ToolProposal:
    name: str
    arguments: Mapping[str, object]


@dataclass(frozen=True)
class AgentTurn:
    message: str
    tool: ToolProposal | None = None


@dataclass(frozen=True)
class ToolFeedback:
    name: str
    arguments: Mapping[str, object]
    decision: str
    reason_code: str
    output: str | None


class AgentProvider(Protocol):
    name: str

    def next_turn(self, task: str, feedback: tuple[ToolFeedback, ...]) -> AgentTurn: ...


@dataclass(frozen=True)
class RunStep:
    proposal: ToolProposal
    result: GatewayResult
    risk: RiskAssessment
    effect: EffectReceipt | None = None


@dataclass(frozen=True)
class AgentRun:
    run_id: str
    provider: str
    final_message: str
    steps: tuple[RunStep, ...]
    stop_reason: str


class AgentRunner:
    """Execute bounded proposals, allowing one denied call to be corrected."""

    def __init__(self, gateway: AgentToolGateway, provider: AgentProvider, max_tool_calls: int = 4,
                 effect_observer: Callable[[GatewayResult], EffectReceipt] | None = None):
        if not 1 <= max_tool_calls <= 20:
            raise ValueError("max_tool_calls must be between 1 and 20")
        self.gateway = gateway
        self.provider = provider
        self.max_tool_calls = max_tool_calls
        self.effect_observer = effect_observer

    def run(self, *, run_id: str, task: str) -> AgentRun:
        if not run_id or not task or len(task) > 4000:
            raise ValueError("run_id and a task of at most 4000 characters are required")
        feedback: list[ToolFeedback] = []
        steps: list[RunStep] = []
        governor = RiskGovernor()
        for index in range(self.max_tool_calls + 1):
            turn = self.provider.next_turn(task, tuple(feedback))
            if turn.tool is None:
                return AgentRun(run_id, self.provider.name, turn.message, tuple(steps), "FINISHED")
            if index == self.max_tool_calls:
                return AgentRun(run_id, self.provider.name, "Tool-call limit reached.", tuple(steps), "LIMIT")
            proposal = turn.tool
            result = self.gateway.handle(
                run_id=run_id,
                request_id=f"{run_id}:{index}",
                tool_name=proposal.name,
                arguments=proposal.arguments,
            )
            assessment = governor.observe(result)
            effect = None
            if self.effect_observer is not None:
                try:
                    effect = self.effect_observer(result)
                    if not isinstance(effect, EffectReceipt):
                        raise TypeError("observer did not return an EffectReceipt")
                    if result.decision == "ALLOW" or effect.verdict == "VIOLATION":
                        assessment = governor.observe_effect(effect)
                except Exception:
                    steps.append(RunStep(proposal, result, assessment))
                    return AgentRun(run_id, self.provider.name,
                                    "Stopped because effect observation failed.",
                                    tuple(steps), "TELEMETRY_UNAVAILABLE")
            steps.append(RunStep(proposal, result, assessment, effect))
            try:
                self.gateway.audit.append({
                    "event": "RISK_ASSESSMENT",
                    "run_id": run_id,
                    "request_id": result.request_id,
                    "score": assessment.score,
                    "action": assessment.action,
                    "denied_calls": assessment.denied_calls,
                    "incidents": assessment.incidents,
                    "signals": list(assessment.signals),
                    "effect_verdict": effect.verdict if effect else None,
                })
            except Exception:
                return AgentRun(run_id, self.provider.name,
                                "Stopped because risk evidence could not be recorded.",
                                tuple(steps), "AUDIT_UNAVAILABLE")
            feedback.append(ToolFeedback(proposal.name, proposal.arguments, result.decision,
                                         result.reason_code, result.output))
            if assessment.action == "STOP":
                cause = ("an observed out-of-scope effect" if governor.effect_violation
                         else "repeated denied or failed tool calls")
                return AgentRun(
                    run_id, self.provider.name,
                    f"Stopped after {cause}.",
                    tuple(steps), "EFFECT_VIOLATION" if governor.effect_violation else "DENIED_OR_FAILED",
                )
        raise AssertionError("unreachable")
