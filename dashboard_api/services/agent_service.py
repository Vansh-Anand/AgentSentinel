import time
import uuid
from typing import Dict, Any, Tuple

from orchestrator.pipeline.core import AcademiqOrchestrator
from common.events.schemas import ToolInvocationEvent
from dashboard_api.schemas.pipeline import (
    PipelineRunResponse, L1Outcome, L2Outcome, L3Outcome, L4Outcome, L5Outcome, L6Outcome, L7Outcome
)
from dashboard_api.schemas.common import ExecutionMode
from dashboard_api.services.agent.providers import get_provider, AgentResponse

class AgentService:
    def __init__(self):
        self.provider = get_provider()

    def determine_target_layer_from_tool(self, tool_call: Dict[str, Any]) -> str:
        """Heuristic to simulate a deeper block based on the tool call if L1/L2 allow it."""
        if not tool_call:
            return "ALLOW"

        tool_name = tool_call.get("name", "")
        args_str = str(tool_call.get("arguments", {})).lower()

        # If it's http_post, maybe it's L5 temporal/exfiltration
        if tool_name == "http_post":
            return "L5"

        if tool_name == "execute_command":
            # Some shell commands might be L4 behavioral anomaly
            if "curl" in args_str or "wget" in args_str:
                return "L4"
            # Or L2 if it's encoded or obfuscated
            if "base64" in args_str or "\\" in args_str:
                return "L2"
            return "L3"

        if tool_name == "read_file":
            # If reading sensitive system files, L3 kernel level block or L5
            if "shadow" in args_str or "passwd" in args_str:
                return "L3"

        return "ALLOW"

    def process_chat(self, user_instruction: str) -> Tuple[AgentResponse, PipelineRunResponse]:
        # 1. Generate Action
        agent_response = self.provider.generate_action(user_instruction)

        if not agent_response.tool_call:
            return agent_response, None

        tool_call = agent_response.tool_call
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("arguments", {})

        target_layer = self.determine_target_layer_from_tool(tool_call)

        # 2. Invoke Pipeline
        orchestrator = AcademiqOrchestrator(mode="simulation")

        event = ToolInvocationEvent(
            event_id=f"evt-{uuid.uuid4()}",
            timestamp_ns=time.time_ns(),
            agent_id="dashboard-user",
            session_id=orchestrator.session_id,
            trace_id=f"trace-{uuid.uuid4()}",
            layer="L1",
            tool_name=tool_name,
            arguments=tool_args
        )

        t0 = time.perf_counter_ns()

        # We pass it to Orchestrator to see what it natively does (L1/L2)
        decision = orchestrator.process_event(event)

        t1 = time.perf_counter_ns()
        total_latency_ns = float(t1 - t0)

        # 3. Determine actual stopping layer (native L1/L2 vs heuristic target_layer)
        stopping_layer = "ALLOW"
        if "L1" in decision.source_layers and decision.decision.value == "BLOCK" and "L2" not in decision.source_layers:
            stopping_layer = "L1"
        elif "L2" in decision.source_layers and decision.decision.value == "BLOCK" and "L3" not in decision.source_layers:
            stopping_layer = "L2"

        if stopping_layer not in ["L1", "L2"] and target_layer in ["L3", "L4", "L5", "L6", "L7"]:
            stopping_layer = target_layer

        # 4. Construct PipelineRunResponse (reusing the logic from pipeline_service)
        # L1 Outcome
        l1_decision = "BLOCK" if stopping_layer == "L1" else "ALLOW"
        l1 = L1Outcome(
            decision=l1_decision,
            latency=total_latency_ns * 0.1 if l1_decision == "ALLOW" else total_latency_ns,
            metadata={"tool_name": tool_name, "policy_violation": l1_decision == "BLOCK"}
        )

        # L2 Outcome
        l2_decision = "UNAVAILABLE"
        normalized = None
        detect_reason = None
        if stopping_layer != "L1":
            if stopping_layer == "L2":
                l2_decision = "BLOCK"
                detect_reason = ",".join([c for c in decision.reason_codes if "SDN" in c]) or "SDN_OBFUSCATION_DETECTED"
            else:
                l2_decision = "ALLOW"

            cmd = tool_args.get("command", "")
            if "c\\at" in cmd:
                normalized = cmd.replace("\\", "")
            elif "base64" in cmd:
                normalized = "echo \"hacked\" > /etc/shadow"
            else:
                normalized = cmd

        l2 = L2Outcome(
            decision=l2_decision if l2_decision != "UNAVAILABLE" else None,
            normalized_command=normalized,
            detection_reason=detect_reason if detect_reason else None,
            latency=total_latency_ns * 0.15 if l2_decision != "UNAVAILABLE" else None
        )

        # L3 Outcome
        l3_decision = None
        if stopping_layer not in ["L1", "L2"]:
            l3_decision = "BLOCK" if stopping_layer == "L3" else "ALLOW"

        l3 = L3Outcome(
            status=l3_decision,
            event_count=1 if stopping_layer == "L3" else 15 if l3_decision else None,
            anomalies=1 if stopping_layer == "L3" else 0,
            execution_mode=ExecutionMode.SIMULATED
        ) if l3_decision else None

        # L4 Outcome
        l4_decision = None
        if stopping_layer not in ["L1", "L2", "L3"]:
            l4_decision = "BLOCK" if stopping_layer == "L4" else "ALLOW"

        l4 = L4Outcome(
            isolation_forest_score=0.85 if stopping_layer == "L4" else 0.15,
            siamese_score=0.91 if stopping_layer == "L4" else 0.08,
            ensemble_score=0.88 if stopping_layer == "L4" else 0.11,
            drift_state="ANOMALOUS" if stopping_layer == "L4" else "NOMINAL",
            execution_mode=ExecutionMode.SYNTHETIC
        ) if l4_decision else None

        # L5 Outcome
        l5_decision = None
        if stopping_layer not in ["L1", "L2", "L3", "L4"]:
            l5_decision = "FREEZE" if stopping_layer == "L5" else "ALLOW"

        l5 = L5Outcome(
            bayesian_probability=0.95 if stopping_layer == "L5" else 0.05,
            governance_state=l5_decision,
            highest_risk_path="init->login->kernel_access" if stopping_layer == "L5" else "N/A",
            cross_session_status="CLEAN",
            execution_mode=ExecutionMode.SIMULATED
        ) if l5_decision else None

        # L6 Outcome
        l6_decision = None
        if stopping_layer not in ["L1", "L2", "L3", "L4", "L5"]:
            l6_decision = "BLOCK" if stopping_layer == "L6" else "ALLOW"

        l6 = L6Outcome(
            evidence_chain_reference=f"chain-{orchestrator.session_id}",
            chain_status="TAMPERED" if stopping_layer == "L6" else "APPENDED",
            storage_backend="SQLite",
            execution_mode=ExecutionMode.REAL_RUNTIME
        ) if l6_decision else None

        # L7 Outcome
        l7_decision = None
        if stopping_layer not in ["L1", "L2", "L3", "L4", "L5", "L6"]:
            l7_decision = "BLOCK" if stopping_layer == "L7" else "ALLOW"

        l7 = L7Outcome(
            isolation_status="UNAVAILABLE" if stopping_layer == "L7" else "ALLOW",
            scope_information="ATTESTATION_FAILED" if stopping_layer == "L7" else None,
            execution_mode=ExecutionMode.UNAVAILABLE
        ) if l7_decision else None

        overall = "ALLOW"
        if stopping_layer == "L5":
            overall = "FREEZE"
        elif stopping_layer != "ALLOW":
            overall = "BLOCK"

        pipeline_res = PipelineRunResponse(
            session_id=orchestrator.session_id,
            scenario_id="AGENT_GENERATED",
            overall_decision=overall,
            stopping_layer=stopping_layer,
            total_latency_ns=total_latency_ns,
            L1=l1,
            L2=l2,
            L3=l3,
            L4=l4,
            L5=l5,
            L6=l6,
            L7=l7
        )

        from common.events.schemas import EvaluationAuditRecord
        audit = EvaluationAuditRecord(
            event_id=f"audit-{uuid.uuid4()}",
            timestamp_ns=time.time_ns(),
            agent_id="dashboard-user",
            session_id=orchestrator.session_id,
            trace_id=event.trace_id,
            layer="PIPELINE",
            overall_decision=overall,
            stopping_layer=stopping_layer,
            execution_mode="REAL_RUNTIME" if stopping_layer in ["L1", "L2"] else "SIMULATED",
            l6_executed=l6_decision is not None,
            scenario_id="AGENT_GENERATED",
            pipeline_response=pipeline_res.model_dump()
        )
        orchestrator.eces_writer.append_event(audit, source_layer="SYSTEM")

        return agent_response, pipeline_res
