import { apiClient } from './client';
import type { PipelineRunResponse } from '../types/api';

export interface ChatRequest {
  message: string;
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

export const sendChatMessage = async (message: string): Promise<ChatResponse> => {
  const response = await apiClient.post<ChatResponse>('/api/agent/chat', { message });
  return response.data;
};
