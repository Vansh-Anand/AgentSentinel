"""Bounded seven-layer teaching challenges with explicit evidence boundaries."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, Field

from agent_runtime.agent import ToolProposal
from agent_runtime.evidence import HmacChainedAuditSink, verify_chain
from agent_runtime.service import run_demo_task


Layer = Literal["L1", "L2", "L3", "L4", "L5", "L6", "L7"]
Action = Literal["read_file", "execute_command", "http_post"]
AUDIT_DIR = Path(__file__).resolve().parents[2] / ".data" / "runtime-audit"


class ChallengeRequest(BaseModel):
    layer: Layer
    payload: str = Field(min_length=1, max_length=2000)
    action: Action = "read_file"


class ChallengeResponse(BaseModel):
    layer: Layer
    verdict: Literal["BLOCK", "ALLOW", "SIMULATED_BLOCK", "SIMULATED_ALLOW", "UNAVAILABLE"]
    mode: Literal["SCHEMA_CHECK", "LIVE_GATEWAY", "SIMULATION", "LIVE_INTEGRITY_CHECK", "UNAVAILABLE"]
    reason_code: str
    explanation: str
    rule: str
    executed: bool = False
    run_id: str | None = None
    audit_valid: bool | None = None
    receipt_valid: bool | None = None


def run_challenge(request: ChallengeRequest) -> ChallengeResponse:
    payload = request.payload.strip()
    if not payload:
        raise ValueError("payload cannot be blank")
    layer = request.layer
    if layer == "L1":
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            return ChallengeResponse(layer=layer, verdict="BLOCK", mode="SCHEMA_CHECK",
                                     reason_code="INVALID_PROPOSAL_JSON",
                                     explanation="The submitted proposal is not valid JSON, so it cannot become a tool call.",
                                     rule="A proposal must be JSON with exactly tool and arguments fields.")
        if (not isinstance(value, dict) or set(value) != {"tool", "arguments"}
                or not isinstance(value["tool"], str) or not isinstance(value["arguments"], dict)):
            return ChallengeResponse(layer=layer, verdict="BLOCK", mode="SCHEMA_CHECK",
                                     reason_code="INVALID_PROPOSAL_SHAPE",
                                     explanation="The proposal does not have the required tool and arguments structure.",
                                     rule="A proposal must be JSON with exactly tool and arguments fields.")
        if value["tool"] not in {"read_file", "execute_command", "http_post"}:
            return ChallengeResponse(layer=layer, verdict="BLOCK", mode="SCHEMA_CHECK",
                                     reason_code="UNKNOWN_TOOL",
                                     explanation=f"Tool {value['tool']!r} is outside the allowed tool vocabulary.",
                                     rule="Tool must be read_file, execute_command, or http_post.")
        return ChallengeResponse(layer=layer, verdict="ALLOW", mode="SCHEMA_CHECK",
                                 reason_code="SCHEMA_VALID",
                                 explanation="The proposal passed the shape check. L2 still decides whether it is authorized.",
                                 rule="Shape validation is not authorization.")

    if layer == "L2":
        if request.action == "read_file":
            arguments = {"path": payload}
        elif request.action == "execute_command":
            try:
                arguments = {"argv": shlex.split(payload)}
            except ValueError as exc:
                raise ValueError("command quoting is invalid") from exc
        else:
            arguments = {"url": payload, "data": "synthetic-only"}
        result = run_demo_task("Evaluate one faculty challenge proposal.", "probe", AUDIT_DIR,
                               readme_text="# Synthetic challenge workspace\n",
                               proposal=ToolProposal(request.action, arguments))
        step = result["steps"][0]
        code = str(step["reason_code"])
        explanations = {
            "INVALID_PATH": "The file path is absolute, traverses folders, or has ambiguous syntax.",
            "PATH_OUT_OF_SCOPE": "Only README.md is authorized in this disposable workspace.",
            "COMMAND_EXECUTION_DISABLED": "The task policy does not authorize command execution.",
            "NETWORK_EXECUTION_DISABLED": "The task policy does not authorize outbound HTTP.",
            "TASK_POLICY_ALLOW": "The requested README read is within the explicit task policy.",
        }
        return ChallengeResponse(layer=layer, verdict="ALLOW" if step["decision"] == "ALLOW" else "BLOCK",
                                 mode="LIVE_GATEWAY", reason_code=code,
                                 explanation=explanations.get(code, "The gateway applied its task policy before execution."),
                                 rule="Exact allowlist: read_file README.md only; commands and network disabled.",
                                 executed=bool(step["executed"]), run_id=str(result["run_id"]),
                                 audit_valid=bool(result["audit_verification"]["valid"]),
                                 receipt_valid=bool(result["signed_receipt"]["valid"]))

    if layer in {"L3", "L4", "L5"}:
        lowered = payload.lower()
        if layer == "L3":
            matched = bool(re.search(r"(?:/etc/(?:shadow|passwd)|\.env|kernel_mem|ptrace|sys_open)", lowered))
            rule = "Replay rule: sensitive file or kernel access marker in a supplied event."
            reason = "SENSITIVE_KERNEL_EVENT" if matched else "NO_REPLAY_MARKER"
            explanation = ("A replay rule matched the supplied event. No kernel event was collected on this Windows host."
                           if matched else "No replay rule matched. This is not proof that a live syscall is safe.")
        elif layer == "L4":
            matched = bool(re.search(r"(?:sudo|escalat|privilege|kernel|credential|exfil)", lowered))
            rule = "Replay rule: privilege or credential behavior marker in a supplied action sequence."
            reason = "BEHAVIOR_SEQUENCE_MARKER" if matched else "NO_SEQUENCE_MARKER"
            explanation = ("The supplied sequence matched a replay rule. No trained live baseline made this decision."
                           if matched else "No replay rule matched. A trained live detector was not run.")
        else:
            risky = re.findall(r"(?:deny|fail|retry|escalat|exfil|secret|sudo)", lowered)
            matched = len(risky) >= 2
            rule = "Replay rule: two or more risk markers in one submitted sequence."
            reason = "SEQUENCE_RISK_THRESHOLD" if matched else "BELOW_REPLAY_THRESHOLD"
            explanation = (f"The supplied sequence contained {len(risky)} risk markers. This is a replay heuristic, not live cross-session governance."
                           if matched else "The replay threshold was not reached. No live cross-session inference ran.")
        return ChallengeResponse(layer=layer,
                                 verdict="SIMULATED_BLOCK" if matched else "SIMULATED_ALLOW",
                                 mode="SIMULATION", reason_code=reason,
                                 explanation=explanation, rule=rule)

    if layer == "L6":
        # The submitted value is represented only by a digest. Deliberately mutate
        # a COPY of a synthetic record and verify against its separate anchor.
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with TemporaryDirectory(prefix="agentsentinel-integrity-") as directory:
            root = Path(directory)
            log, anchor = root / "audit.jsonl", root / "anchor.json"
            key = os.urandom(32)
            HmacChainedAuditSink(log, anchor, key).append({"event": "FACULTY_CHALLENGE", "payload_sha256": digest})
            record = json.loads(log.read_text(encoding="utf-8"))
            record["event"]["payload_sha256"] = hashlib.sha256((payload + "-tampered").encode()).hexdigest()
            log.write_text(json.dumps(record) + "\n", encoding="utf-8")
            verification = verify_chain(log, anchor, key)
        return ChallengeResponse(layer=layer, verdict="BLOCK" if not verification["valid"] else "ALLOW",
                                 mode="LIVE_INTEGRITY_CHECK", reason_code=str(verification.get("failure", "CHAIN_VALID")),
                                 explanation="A copy of a synthetic audit record was changed; HMAC verification detected the changed content against its anchor.",
                                 rule="Verify every record MAC and the final anchored chain head.",
                                 audit_valid=bool(verification["valid"]))

    return ChallengeResponse(layer=layer, verdict="UNAVAILABLE", mode="UNAVAILABLE",
                             reason_code="TPM_HOST_UNAVAILABLE",
                             explanation="This Windows demo has no TPM-backed attestation path. The input was not intercepted by hardware.",
                             rule="A Linux/TPM validation host is required for a real attestation decision.")
