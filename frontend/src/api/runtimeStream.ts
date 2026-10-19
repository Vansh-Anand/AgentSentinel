import { apiClient } from './client';

export type LiveEventName =
  | 'run_started' | 'model_request' | 'model_turn' | 'orchestrator_step' | 'orchestrator_turn' | 'tool_proposed'
  | 'policy_decision' | 'effect_receipt' | 'risk_assessment'
  | 'run_completed' | 'run_error';

export type LiveEvent = {
  event: LiveEventName;
  sequence: number;
  at: string;
  data: Record<string, unknown>;
};

export type LiveRunInput = {
  task: string;
  readme_text: string;
  provider: 'gemini' | 'ollama' | 'fixture';
};

export async function streamRuntimeRun(
  input: LiveRunInput,
  onEvent: (event: LiveEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${apiClient.defaults.baseURL}/api/runtime/run/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
    body: JSON.stringify(input),
    signal,
  });
  if (!response.ok) {
    throw new Error(`The API rejected the run (HTTP ${response.status}).`);
  }
  if (!response.body) throw new Error('The API did not provide a live event stream.');

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let terminal = false;

  function parseFrame(frame: string) {
    if (!frame || frame.startsWith(':')) return;
    const name = frame.split('\n').find(line => line.startsWith('event: '))?.slice(7) as LiveEventName | undefined;
    const payload = frame.split('\n').find(line => line.startsWith('data: '))?.slice(6);
    if (!name || !payload) return;
    const parsed = JSON.parse(payload) as { sequence: number; at: string; data: Record<string, unknown> };
    onEvent({ event: name, ...parsed });
    if (name === 'run_completed' || name === 'run_error') terminal = true;
  }

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n/g, '\n');
      const frames = buffer.split('\n\n');
      buffer = frames.pop() ?? '';
      frames.forEach(parseFrame);
    }
    buffer += decoder.decode();
    if (buffer.trim()) parseFrame(buffer.trim());
  } finally {
    reader.releaseLock();
  }
  if (!terminal && !signal?.aborted) throw new Error('The live stream ended before a signed result was returned.');
}
