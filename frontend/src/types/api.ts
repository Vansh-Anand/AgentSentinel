export interface HealthComponent {
  status: string;
  latency?: number;
  message?: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
  components: {
    orchestrator?: HealthComponent;
    database?: HealthComponent;
    model?: HealthComponent;
    ebpf?: HealthComponent;
    experiment_results?: HealthComponent;
    eces_sqlite?: HealthComponent;
    [key: string]: HealthComponent | undefined;
  };
}

export interface ExperimentSummary {
  experiment_id: string;
  title: string;
  category: string;
  description: string;
  execution_mode: ExecutionModeType;
  model_name?: string | null;
  primary_metric?: {
    name: string;
    value: number;
    suffix: string;
  } | null;
}

export interface ExperimentListResponse {
  experiments: ExperimentSummary[];
}

export interface ExperimentNormalized {
  experiment_id: string;
  title: string;
  category: string;
  description: string;
  execution_mode: ExecutionModeType;
  model_name?: string | null;
  sample_size?: number | null;
  baseline_metrics?: Record<string, any> | null;
  protected_metrics?: Record<string, any> | null;
  detection_rate?: number | null;
  attack_success_rate?: number | null;
  false_positive_rate?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1_score?: number | null;
  latency_metrics?: Record<string, any> | null;
  key_findings?: string | null;
  known_limitations?: string[] | null;
  raw_artifact?: Record<string, any> | null;
}

export type ExecutionModeType = 'REAL_RUNTIME' | 'SIMULATED' | 'BENCHMARK' | 'SYNTHETIC' | 'UNAVAILABLE';

export const ExecutionMode = {
  REAL_RUNTIME: 'REAL_RUNTIME' as ExecutionModeType,
  SIMULATED: 'SIMULATED' as ExecutionModeType,
  BENCHMARK: 'BENCHMARK' as ExecutionModeType,
  SYNTHETIC: 'SYNTHETIC' as ExecutionModeType,
  UNAVAILABLE: 'UNAVAILABLE' as ExecutionModeType
} as const;

export type ExecutionMode = typeof ExecutionMode[keyof typeof ExecutionMode];

export interface MetricSeries {
  timestamp: string;
  value: number;
}

export interface MetricQueryResponse {
  query: string;
  series: MetricSeries[];
  execution_mode: ExecutionMode;
}

export interface ChatResponse {
  assistant_message: string;
  tool_call?: {
    name: string;
    arguments: Record<string, any>;
  } | null;
  pipeline_result?: PipelineRunResponse | null;
  provider?: string;
}

export interface L1Outcome {
  decision: string;
  latency?: number;
  metadata?: Record<string, any>;
}

export interface L2Outcome {
  decision?: string;
  normalized_command?: string;
  detection_reason?: string;
  latency?: number;
}

export interface L3Outcome {
  status: string;
  event_count?: number;
  anomalies?: number;
  execution_mode: ExecutionMode;
}

export interface L4Outcome {
  isolation_forest_score?: number;
  siamese_score?: number;
  ensemble_score?: number;
  drift_state: string;
  execution_mode: ExecutionMode;
}

export interface L5Outcome {
  bayesian_probability?: number;
  governance_state?: string;
  highest_risk_path: string;
  cross_session_status: string;
  execution_mode?: ExecutionMode;
}

export interface L6Outcome {
  evidence_chain_reference: string;
  chain_status: string;
  storage_backend: string;
  execution_mode?: ExecutionMode;
}

export interface L7Outcome {
  isolation_status: string;
  scope_information?: string;
  execution_mode?: ExecutionMode;
}

export interface PipelineRunResponse {
  session_id: string;
  scenario_id: string;
  overall_decision: string;
  stopping_layer: string;
  total_latency_ns: number;
  L1?: L1Outcome;
  L2?: L2Outcome;
  L3?: L3Outcome;
  L4?: L4Outcome;
  L5?: L5Outcome;
  L6?: L6Outcome;
  L7?: L7Outcome;
}

// Phase E4.2 - Evidence Types
export interface SessionListItem {
  session_id: string;
  event_count: number;
  start_time_ns: number;
  execution_mode: ExecutionMode;
}

export interface SessionListResponse {
  sessions: SessionListItem[];
}

export interface ChainRecord {
  sequence_number: number;
  timestamp_ns: number;
  event_type: string;
  source_layer: string;
  event_id: string;
  previous_hash: string;
  event_hash: string;
  payload: Record<string, any>;
}

export interface SessionDetailResponse {
  session_id: string;
  execution_mode: ExecutionMode;
  chain: ChainRecord[];
}

export interface VerifyResponse {
  session_id: string;
  valid: boolean;
  hash_chain_valid?: boolean;
  signature_status?: string;
  records_checked: number;
  failure?: string;
  execution_mode: ExecutionMode;
}

// Phase E4.4 - System Status Types
export interface LayerSystemStatus {
  layer_id: string;
  name: string;
  operational_status: string; // OPERATIONAL, PARTIAL, SIMULATED, UNAVAILABLE, ERROR
  execution_mode: ExecutionMode;
  description: string;
  capabilities: string[];
  limitations: string[];
}

export interface CapabilityStatus {
  name: string;
  status: string;
  validation_level: string;
  execution_mode: ExecutionMode;
}

export interface InfrastructureStatus {
  name: string;
  status: string;
  execution_mode: ExecutionMode;
  description: string;
}

export interface SystemStatusResponse {
  api_version: string;
  backend_status: string;
  database_status: string;
  overall_status: string;
  overall_description: string;
  infrastructure: InfrastructureStatus[];
  layers: LayerSystemStatus[];
  capabilities: CapabilityStatus[];
}
