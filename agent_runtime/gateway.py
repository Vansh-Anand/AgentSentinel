"""Pre-execution gateway. No tool runs before policy and audit acceptance."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping, Protocol

from .policy import TaskPolicy


class Executor(Protocol):
    def execute(self, tool_name: str, arguments: Mapping[str, object], policy: TaskPolicy) -> str: ...


class AuditSink(Protocol):
    def append(self, record: Mapping[str, object]) -> None: ...


class RequestLedger(Protocol):
    def claim(self, request_id: str, fingerprint: str) -> str: ...
    def complete(self, request_id: str) -> None: ...


class JsonlAuditSink:
    """Durable local audit sink; request arguments and tool output are omitted."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, record: Mapping[str, object]) -> None:
        line = json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())


@dataclass(frozen=True)
class GatewayResult:
    request_id: str
    decision: str
    reason_code: str
    executed: bool
    output: str | None = None
    error: str | None = None


class AgentToolGateway:
    def __init__(self, policy: TaskPolicy, executor: Executor, audit: AuditSink,
                 ledger: RequestLedger | None = None):
        self.policy = policy
        self.executor = executor
        self.audit = audit
        self.ledger = ledger
        self._lock = threading.Lock()
        self._completed: dict[str, tuple[str, GatewayResult]] = {}

    def handle(
        self,
        *,
        run_id: str,
        request_id: str,
        tool_name: object,
        arguments: object,
    ) -> GatewayResult:
        """Evaluate and possibly execute one proposed call.

        Request IDs are idempotent within this gateway process. Durable retries
        across restarts remain a later milestone.
        """
        if not run_id or not request_id or not isinstance(run_id, str) or not isinstance(request_id, str):
            return GatewayResult(str(request_id), "DENY", "INVALID_REQUEST_ID", False)
        with self._lock:
            # JSON round-trip makes a deep, primitive-only snapshot. A shallow
            # dict copy would leave a mutable argv list shared with the caller.
            try:
                checked_arguments = json.loads(json.dumps(dict(arguments), allow_nan=False)) if isinstance(arguments, Mapping) else None
                if not isinstance(checked_arguments, dict):
                    checked_arguments = None
            except (TypeError, ValueError, OverflowError):
                checked_arguments = None
            decision = self.policy.decide(tool_name, checked_arguments)
            valid_args = checked_arguments is not None and all(isinstance(k, str) for k in checked_arguments)
            argument_digest = self._digest(checked_arguments) if valid_args else "invalid"
            fingerprint = self._digest([run_id, tool_name, argument_digest])
            previous = self._completed.get(request_id)
            if previous:
                if previous[0] == fingerprint:
                    return previous[1]
                return GatewayResult(request_id, "DENY", "REQUEST_ID_REUSED", False)

            if self.ledger is not None:
                try:
                    claim = self.ledger.claim(request_id, fingerprint)
                except Exception:
                    return GatewayResult(request_id, "DENY", "LEDGER_UNAVAILABLE", False)
                if claim != "NEW":
                    return GatewayResult(request_id, "DENY",
                                         "REQUEST_ALREADY_SEEN" if claim == "DUPLICATE" else "REQUEST_ID_REUSED",
                                         False)

            name = tool_name if isinstance(tool_name, str) else "invalid"
            record = {
                "event": "DECISION",
                "timestamp_ns": time.time_ns(),
                "run_id": run_id,
                "request_id": request_id,
                "tool_name": name,
                "arguments_sha256": argument_digest,
                "policy_sha256": self.policy.policy_hash,
                "decision": "ALLOW" if decision.allowed else "DENY",
                "reason_code": decision.reason_code,
                "execution_mode": "LOCAL_READ_ONLY",
            }
            try:
                self.audit.append(record)
            except Exception:
                return GatewayResult(request_id, "DENY", "AUDIT_UNAVAILABLE", False)

            if not decision.allowed:
                result = GatewayResult(request_id, "DENY", decision.reason_code, False)
                self._completed[request_id] = (fingerprint, result)
                return result

            try:
                output = self.executor.execute(name, checked_arguments, self.policy)  # type: ignore[arg-type]
                result = GatewayResult(request_id, "ALLOW", decision.reason_code, True, output=output)
            except Exception as exc:
                result = GatewayResult(request_id, "ALLOW", "EXECUTION_FAILED", False, error=type(exc).__name__)
            try:
                self.audit.append({
                    "event": "EXECUTION_RESULT",
                    "timestamp_ns": time.time_ns(),
                    "run_id": run_id,
                    "request_id": request_id,
                    "executed": result.executed,
                    "reason_code": result.reason_code,
                    "error_type": result.error,
                })
            except Exception:
                # The decision was already durably recorded. Do not retry a
                # possibly executed side effect merely because logging failed.
                result = GatewayResult(request_id, "ALLOW", "AUDIT_RESULT_UNAVAILABLE", result.executed, error="AuditError")
            if self.ledger is not None:
                try:
                    self.ledger.complete(request_id)
                except Exception:
                    result = GatewayResult(request_id, result.decision, "LEDGER_RESULT_UNAVAILABLE",
                                           result.executed, error="LedgerError")
            self._completed[request_id] = (fingerprint, result)
            return result

    @staticmethod
    def _digest(value: Any) -> str:
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
        except Exception:
            encoded = repr(type(value)).encode()
        return hashlib.sha256(encoded).hexdigest()
