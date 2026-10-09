from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from .base import BaseEvent

class ToolInvocationEvent(BaseEvent):
    event_type: str = Field(default="ToolInvocation")
    tool_name: str
    arguments: Dict[str, Any]

class ShellCommandEvent(BaseEvent):
    event_type: str = Field(default="ShellCommand")
    raw_command: str

class NormalizedCommandEvent(BaseEvent):
    event_type: str = Field(default="NormalizedCommand")
    normalized_command: str
    passes_applied: int

class PathResolutionEvent(BaseEvent):
    event_type: str = Field(default="PathResolution")
    requested_path: str
    resolved_path: str
    inode_id: Optional[int] = None
    device_id: Optional[int] = None

class SyscallEvent(BaseEvent):
    event_type: str = Field(default="Syscall")
    schema_version: str = "1.0"
    monotonic_timestamp_ns: Optional[int] = None
    agent_id: str = "unknown"
    session_id: str = "unknown"
    task_id: str = "unknown"
    pid: int
    tid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    cgroup_id: Optional[int] = None
    process_name: Optional[str] = None
    executable: Optional[str] = None
    syscall_name: str
    syscall_number: Optional[int] = None
    return_value: Optional[int] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    path_hash: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    flags: Optional[int] = None
    cpu_id: Optional[int] = None
    comm: Optional[str] = None
    parent_event_id: Optional[str] = None
    telemetry_source: str = "SIMULATION" # EBPF or SIMULATION

class AgentIdentity(BaseEvent):
    event_type: str = Field(default="AgentIdentity")
    agent_id: str
    cgroup_id: int
    container_id: Optional[str] = None
    namespace_identifiers: Dict[str, int] = Field(default_factory=dict)
    root_pid: int
    start_time_ns: int
    policy_version: str

class ProcessIdentity(BaseEvent):
    event_type: str = Field(default="ProcessIdentity")
    pid: int
    tid: int
    ppid: int
    cgroup_id: int
    comm: str
    executable: str
    start_time_ns: int

class TelemetryHealthEvent(BaseEvent):
    event_type: str = Field(default="TelemetryHealth")
    events_received: int
    events_dropped: int
    ringbuf_overflow: int
    decode_errors: int
    collector_latency_ms: float
    last_event_timestamp_ns: int

class EnforcementEvent(BaseEvent):
    event_type: str = Field(default="Enforcement")
    event_id: str
    agent_id: str
    cgroup_id: int
    action: str
    reason: str
    risk_score: float
    trigger_event_ids: List[str] = Field(default_factory=list)
    timestamp: int
    success: bool
    error: Optional[str] = None
    operator_source: str = "SYSTEM"

class HardwarePerformanceEvent(BaseEvent):
    event_type: str = Field(default="HardwarePerformance")
    agent_id: str
    simulation: bool = False
    timestamp_ns: int
    cycles: Optional[int] = None
    instructions: Optional[int] = None
    ipc: Optional[float] = None
    cache_references: Optional[int] = None
    cache_misses: Optional[int] = None
    branch_instructions: Optional[int] = None
    branch_misses: Optional[int] = None

class WindowQuality(BaseModel):
    event_count: int
    expected_count: int
    dropped_events: int
    ordering_valid: bool
    timestamp_quality: float
    hpc_coverage: float
    quality_score: float

class DivergenceResult(BaseModel):
    score: float
    confidence: float
    siamese_score: float
    isolation_score: float
    ece_threshold: float
    above_threshold: bool
    window_quality: WindowQuality
    hpc_available: bool
    model_version: str
    ece_version: str
    reason_codes: List[str]

# ============================================================
# PHASE 6 (L5 RISKCHAIN) SCHEMAS
# ============================================================

class RiskNode(BaseModel):
    node_id: str
    event_id: str
    event_type: str
    timestamp_ns: int
    agent_id: str
    session_id: str
    trace_id: str
    risk_contribution: float
    severity: str
    confidence: float
    resource_class: Optional[str] = None
    process_class: Optional[str] = None
    network_class: Optional[str] = None
    source_layer: str
    metadata_hash: Optional[str] = None

class RiskEdge(BaseModel):
    edge_id: str
    source_node: str
    target_node: str
    edge_type: str
    timestamp_delta: int
    weight: float
    confidence: float
    rule_id: Optional[str] = None

class RuleMatch(BaseModel):
    rule_id: str
    matched_event_ids: List[str]
    timestamp: int
    risk_contribution: str # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    explanation: str

class BayesianRiskResult(BaseModel):
    attack_probability: float
    prior: float
    evidence: Dict[str, bool]
    model_version: str
    confidence: float
    contributing_variables: List[str]

class GovernanceDecision(BaseModel):
    decision: str # ALLOW, WARN, THROTTLE, FREEZE
    risk_probability: float
    divergence_score: float
    chain_score: float
    telemetry_confidence: float
    fuzzy_activation: Dict[str, float]
    rule_ids: List[str]
    explanation: str
    policy_version: str
    timestamp_ns: int

class SecurityIncident(BaseModel):
    incident_id: str
    agent_id: str
    session_id: str
    created_at: int
    updated_at: int
    status: str # OPEN, ACKNOWLEDGED, CONTAINED, RESOLVED, FALSE_POSITIVE
    risk_probability: float
    divergence_score: float
    chain_score: float
    severity: str
    triggered_rules: List[str]
    event_ids: List[str]
    graph_snapshot_hash: str
    governance_decision: str
    explanation: str

class EnforcementEvent(BaseEvent):
    incident_id: str
    cgroup_id: str
    action: str
    reason: str
    risk_score: float
    trigger_event_ids: List[str]
    success: bool
    error: Optional[str] = None
    authorization_id: Optional[str] = None

class ResumeAuthorization(BaseModel):
    incident_id: str
    agent_id: str
    cgroup_id: str
    authorized_by: str
    issued_at: int
    expires_at: int
    nonce: str
    signature: str

class RiskChainEvent(BaseEvent):
    schema_version: str = "1.0"
    incident_id: Optional[str] = None
    node_count: int
    edge_count: int
    triggered_rules: List[str]
    risk_probability: float
    chain_score: float
    divergence_score: float
    governance_decision: str
    confidence: float
    explanation_hash: str
    policy_version: str
    model_version: str
    simulation: bool = False
    parent_event_id: Optional[str] = None

class DivergenceEvent(BaseEvent):
    event_type: str = Field(default="Divergence")
    schema_version: str = "1.0"
    agent_id: str
    session_id: str
    window_id: str
    window_start: int
    window_end: int
    syscall_count: int
    result: DivergenceResult
    decision: str
    simulation: bool = False

class TEEAttestationEvent(BaseEvent):
    event_type: str = Field(default="TEEAttestation")
    provider_name: str
    quote_data: str
    verified: bool

from enum import Enum

class DetectionState(str, Enum):
    NEW_PATTERN = "NEW_PATTERN"
    REPEATED_PATTERN = "REPEATED_PATTERN"
    COORDINATED_PATTERN = "COORDINATED_PATTERN"
    LEGITIMATE_REPEAT = "LEGITIMATE_REPEAT"
    REPLAY_ALERT = "REPLAY_ALERT"

class CrossSessionEvent(BaseEvent):
    event_type: str = Field(default="CrossSessionReplay")
    schema_version: str = "1.0"
    layer: str = Field(default="L5_CROSS_SESSION")
    current_session_id: str
    matching_session_ids: List[str]
    attack_chain_fingerprint: str
    attack_chain_signature: str
    detection_state: str
    repeat_count: int
    temporal_window_seconds: int
    path_risk_score: float
    bayesian_probability: float
    simulation: bool = False
    parent_event_id: Optional[str] = None

class EvaluationAuditRecord(BaseEvent):
    event_type: str = Field(default="EvaluationAudit")
    schema_version: str = "1.0"
    overall_decision: str
    stopping_layer: str
    execution_mode: str
    l6_executed: bool
    scenario_id: Optional[str] = None
    pipeline_response: Dict[str, Any]
