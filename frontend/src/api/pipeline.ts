import { apiClient } from './client';
import type { PipelineRunResponse } from '../types/api';

export type ChallengeLayer = 'L1' | 'L2' | 'L3' | 'L4' | 'L5' | 'L6' | 'L7';
export type ChallengeAction = 'read_file' | 'execute_command' | 'http_post';
export interface ChallengeResult {
  layer: ChallengeLayer;
  verdict: 'BLOCK' | 'ALLOW' | 'SIMULATED_BLOCK' | 'SIMULATED_ALLOW' | 'UNAVAILABLE';
  mode: 'SCHEMA_CHECK' | 'LIVE_GATEWAY' | 'SIMULATION' | 'LIVE_INTEGRITY_CHECK' | 'UNAVAILABLE';
  reason_code: string;
  explanation: string;
  rule: string;
  executed: boolean;
  run_id: string | null;
  audit_valid: boolean | null;
  receipt_valid: boolean | null;
}

export const runChallenge = async (layer: ChallengeLayer, payload: string, action: ChallengeAction): Promise<ChallengeResult> => {
  const response = await apiClient.post<ChallengeResult>('/api/pipeline/challenge', { layer, payload, action });
  return response.data;
};

export const runPipelineScenario = async (scenarioId: string): Promise<PipelineRunResponse> => {
  const response = await apiClient.post<PipelineRunResponse>('/api/pipeline/run', { scenario_id: scenarioId });
  return response.data;
};
