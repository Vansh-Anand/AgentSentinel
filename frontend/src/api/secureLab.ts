import { apiClient } from './client';

export type Layer = { id: string; name: string; state: string; decision: string | null; reason: string; detail: string; mode: string };
export type LabEvent = { schema_version: number; run_id: string; sequence: number; timestamp: string; elapsed_ms: number; type: string; layer: string | null; action_id?: string | null; phase?: string; data: Record<string, unknown> };
export type LabStep = { request_id: string; tool: string; arguments: Record<string, unknown>; decision: string; reason: string; executor_invoked: boolean; completed: boolean; effects: { kind: string; target: string; bytes: number; source_id?: string; classification?: string; sha256?: string }[]; windows?: { mode: string; worker_pid?: number; job_assigned: boolean; action_released: boolean; completed: boolean; termination_reason: string; duration_ms?: number; limits?: { process_memory_bytes: number; active_processes: number; wall_clock_seconds: number; kill_on_close: boolean }; etw?: { status: string; reason?: string; coverage: string; correlated: boolean; process_start_observed?: boolean; correlation_clock?: string; events_scanned?: number; matched_events?: { kind: string; pid: number; event_id: string; time: string; process_created_utc: string }[]; lost_events?: number | null } }; native?: { valid: boolean; mode?: string; reason?: string; attempt_count?: number; coverage?: string } };
export type LabProvenance = { schema_version: number; derivation: string; sha256: string;
  sources: { source_id: string; path: string; classification: string; sha256: string }[];
  artifacts: { artifact_id: string; kind: string; target: string; classification: string; sha256: string; source_ids: string[] }[];
  edges: { source_id: string; artifact_id: string }[];
  exports: { tool: string; destination: string; decision: string; reason: string; source_ids: string[]; classification: string }[] };
export type LabResult = { workspace_documents?: Record<string, { name: string; sha256: string; source_id: string; bytes: number }>; run_id: string; status: string; enforcing_layer: string | null; reason: string; answer: string; layers?: Layer[]; steps?: LabStep[]; duration_ms?: number; provider: string; profile?: string; evidence_mode?: string; windows_job_enforced?: boolean; etw_process_correlated?: boolean; native_telemetry?: boolean; hardware_attested?: boolean; attestation?: { valid: boolean; reason: string; mode?: string }; provenance?: LabProvenance; verification?: { valid: boolean; key_fingerprint_sha256?: string } };
export type SavedRun = { id: string; status: string; created: string; config: { provider: string; profile: string; mode?: string; challenge?: string }; result: LabResult | null; events?: LabEvent[] };
export type LabCapabilities = { profiles: Record<string, { tools: string[]; max_calls: number; strict_input: boolean; approval: boolean }>; challenges: Record<string, string>; layers: { id: string; name: string }[]; integrity: { valid: boolean; reason: string }; providers: { ollama_available: boolean; gemini_key_configured: boolean; gemini_sdk_installed: boolean }; issuer_fingerprint: string | null; windows_job?: { required: boolean; available: boolean; reason: string }; etw_process?: { available: boolean; reason: string }; native_l3?: { required: boolean; available: boolean; reason: string }; tpm_l7?: { required: boolean; available: boolean; reason: string } };
export type ConversationMessage = { id: string; conversation_id: string; run_id: string; task: string; context: string; mode: string; created: string; status: string; result: LabResult | null };
export type Conversation = { id: string; title: string; created: string; updated: string; messages?: ConversationMessage[] };
const base = () => `${apiClient.defaults.baseURL}/api/lab`;
let sessionPromise: Promise<string> | null = null;

async function session(): Promise<string> {
  const saved = localStorage.getItem('sentinel-lab-session-v2');
  if (saved && /^[a-f0-9]{64}$/.test(saved)) return saved;
  if (!sessionPromise) sessionPromise = fetch(`${base()}/session`, { method: 'POST' }).then(async response => {
    if (!response.ok) throw new Error('Could not initialize a local session.');
    const value = await response.json();
    localStorage.setItem('sentinel-lab-session-v2', value.token);
    return value.token as string;
  }).finally(() => { sessionPromise = null; });
  return sessionPromise;
}

export async function labRequest<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const token = await session();
  const response = await fetch(`${base()}${path}`, { method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Lab-Session': token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body), signal });
  if (!response.ok) {
    let detail = `Request failed (HTTP ${response.status}).`;
    try { const data = await response.json(); if (typeof data.detail === 'string') detail = data.detail; } catch { /* No error body. */ }
    throw new Error(detail);
  }
  return response.json();
}

export async function labDelete<T>(path: string): Promise<T> {
  const token = await session();
  const response = await fetch(`${base()}${path}`, { method: 'DELETE', headers: { 'X-Lab-Session': token } });
  if (!response.ok) {
    let detail = `Delete failed (HTTP ${response.status}).`;
    try { const data = await response.json(); if (typeof data.detail === 'string') detail = data.detail; } catch { /* No JSON body. */ }
    throw new Error(detail);
  }
  return response.json();
}

export async function downloadLabFile(runId: string, kind: 'export' | 'artifact' | 'ticket') {
  const token = await session();
  const response = await fetch(`${base()}/runs/${runId}/${kind}`, { headers: { 'X-Lab-Session': token } });
  if (!response.ok) throw new Error('This verified download is unavailable.');
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = kind === 'export' ? `agentsentinel-${runId}.json` : kind === 'ticket' ? 'ticket.json' : 'report.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function streamLab(runId: string, after: number, onEvent: (event: LabEvent) => void, signal: AbortSignal) {
  const token = await session();
  const response = await fetch(`${base()}/runs/${runId}/events?after=${after}`, { headers: { 'X-Lab-Session': token }, signal });
  if (!response.ok || !response.body) throw new Error('Live event connection unavailable. Your run continues on the server.');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const frames = buffer.replace(/\r\n/g, '\n').split('\n\n');
      buffer = frames.pop() ?? '';
      for (const frame of frames) {
        const raw = frame.split('\n').find(line => line.startsWith('data: '));
        if (raw) onEvent(JSON.parse(raw.slice(6)) as LabEvent);
      }
    }
  } finally { reader.releaseLock(); }
}
