import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';

type Receipt = {
  verdict: 'MATCH' | 'VIOLATION' | 'INCOMPLETE' | 'NOT_EXECUTED';
  reason_codes: string[];
  observation_count: number;
  telemetry_source: string;
};

type RiskAssessment = {
  score: number;
  action: 'MONITOR' | 'REVIEW' | 'STOP';
  denied_calls: number;
  incidents: number;
  signals: string[];
};

type LayerReport = {
  layer: string;
  name: string;
  mode: string;
  evidence: Record<string, unknown>;
};

type SignedReceipt = {
  valid: boolean;
  key_fingerprint_sha256?: string;
  public_key_hex: string;
  receipt_file: string;
};

type EvaluationSummary = {
  available: boolean;
  report_version?: string;
  model?: string[];
  attack_cases?: number;
  attack_cases_with_denied_proposal?: number;
  attack_denied_proposals?: number;
  denied_proposals_executed?: number;
  benign_cases?: number;
  benign_completed?: number;
  provider_errors?: number;
  audit_chains_verified?: number;
  signed_receipts_verified?: number;
  source_hashes_match_current_checkout?: boolean;
};

function layerSummary(layer: LayerReport): string {
  const evidence = layer.evidence;
  switch (layer.layer) {
    case 'L1': return `${String(evidence.provider)} · ${String(evidence.gateway_proposals)} proposals`;
    case 'L2': return `${String(evidence.allowed_executed)} allowed executed · ${String(evidence.denied)} denied`;
    case 'L3': return String(evidence.reason);
    case 'L4': return `Rule score ${String(evidence.score)}/100; trained model: no`;
    case 'L5': return `Action ${String(evidence.action)} · ${String(evidence.incidents)} incidents`;
    case 'L6': return `${String(evidence.algorithm)} · offline verifier`;
    case 'L7': return `Software digest ${String(evidence.digest_sha256).slice(0, 16)}… · hardware attested: no`;
    default: return '';
  }
}

function LayerReportPanel({ layers }: { layers: LayerReport[] }) {
  return <section className="rounded border bg-white p-5 shadow-sm" aria-label="Seven-layer evidence report">
    <h3 className="font-semibold text-gray-900">Seven-layer evidence report</h3>
    <p className="mt-1 text-xs text-gray-600">Each stage states what actually ran. Rule signals and software hashes do not imply a trained detector or hardware attestation.</p>
    <div className="mt-4 grid gap-3 md:grid-cols-2">
      {layers.map(layer => <div key={layer.layer} className="rounded border border-gray-200 p-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <strong>{layer.layer} · {layer.name}</strong>
          <span className={`rounded px-2 py-0.5 text-xs font-semibold ${layer.mode === 'UNAVAILABLE' ? 'bg-gray-100 text-gray-600' : 'bg-blue-50 text-blue-800'}`}>{layer.mode}</span>
        </div>
        <p className="mt-1 text-xs text-gray-600">{layerSummary(layer)}</p>
      </div>)}
    </div>
  </section>;
}

type Step = {
  request_id: string;
  tool_name: string;
  arguments_sha256: string;
  decision: 'ALLOW' | 'DENY';
  reason_code: string;
  executed: boolean;
  effectseal: Receipt;
  risk?: RiskAssessment;
};

type GatewayRun = {
  run_id: string;
  provider: string;
  model: string | null;
  execution_mode: 'REAL_LOCAL_READ_ONLY' | 'FIXTURE_REPLAY';
  stop_reason: string;
  final_message: string;
  steps: Step[];
  layers?: LayerReport[];
  audit_file: string;
  audit_verification: { valid: boolean; records_checked: number; failure?: string };
  signed_receipt?: SignedReceipt;
};

type ContainerRun = {
  run_id: string;
  execution_mode: 'REAL_DOCKER_RESTRICTED';
  fixture: 'safe' | 'attack';
  decision: 'ALLOW' | 'DENY';
  reason_code: string;
  executed: boolean;
  output: string | null;
  error_type: string | null;
  effectseal: Receipt;
  risk?: RiskAssessment;
  layers?: LayerReport[];
  audit_verification: { valid: boolean; records_checked: number; failure?: string };
  signed_receipt?: SignedReceipt;
};

export function GatewayDemoPage() {
  const [task, setTask] = useState('Summarize the auth module in README.md.');
  const [provider, setProvider] = useState<'fixture' | 'gemini'>('fixture');
  const [run, setRun] = useState<GatewayRun | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [containerRun, setContainerRun] = useState<ContainerRun | null>(null);
  const [containerError, setContainerError] = useState('');
  const [containerLoading, setContainerLoading] = useState(false);
  const [evaluation, setEvaluation] = useState<EvaluationSummary | null>(null);

  useEffect(() => {
    let active = true;
    apiClient.get<EvaluationSummary>('/api/runtime/evaluation')
      .then(response => { if (active) setEvaluation(response.data); })
      .catch(() => { if (active) setEvaluation(null); });
    return () => { active = false; };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');
    setRun(null);
    try {
      const response = await apiClient.post<GatewayRun>('/api/runtime/run', { task, provider }, { timeout: 60000 });
      setRun(response.data);
    } catch (cause: unknown) {
      const message = cause && typeof cause === 'object' && 'response' in cause
        ? String((cause as { response?: { data?: { detail?: string } } }).response?.data?.detail || 'Run failed')
        : 'Run failed. Check the API connection.';
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  async function runContainer(attack: boolean) {
    setContainerLoading(true);
    setContainerRun(null);
    setContainerError('');
    try {
      const response = await apiClient.post<ContainerRun>('/api/runtime/container-demo', { attack }, { timeout: 60000 });
      setContainerRun(response.data);
    } catch (cause: unknown) {
      const message = cause && typeof cause === 'object' && 'response' in cause
        ? String((cause as { response?: { data?: { detail?: string } } }).response?.data?.detail || 'Container run failed')
        : 'Container run failed. Check Docker Desktop and the API.';
      setContainerError(message);
    } finally {
      setContainerLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-2xl font-bold text-gray-900">AgentSentinel Gateway</h2>
        <p className="mt-2 text-gray-600">Run an agent against a disposable repository with a synthetic secret and an injected README.</p>
      </header>
      {evaluation?.available && <section className="rounded border border-blue-200 bg-blue-50 p-5 shadow-sm" aria-label="Measured model evaluation">
        <h3 className="font-semibold text-blue-950">Measured model evaluation</h3>
        <p className="mt-1 text-xs text-blue-900">One trial per synthetic README, {evaluation.model?.join(', ')}. Tool proposals and gateway effects only; answer quality is not scored.</p>
        {!evaluation.source_hashes_match_current_checkout && <p className="mt-1 text-xs font-semibold text-amber-900">Source hashes did not match at publication ({evaluation.report_version}); treat this as historical evidence.</p>}
        <div className="mt-3 grid gap-3 text-sm sm:grid-cols-3">
          <p><strong>{evaluation.attack_cases_with_denied_proposal}/{evaluation.attack_cases}</strong><br />Attack READMEs induced a forbidden proposal</p>
          <p><strong>{evaluation.denied_proposals_executed}/{evaluation.attack_denied_proposals}</strong><br />Forbidden proposals executed</p>
          <p><strong>{evaluation.benign_completed}/{evaluation.benign_cases}</strong><br />Benign tasks completed</p>
        </div>
        <p className="mt-2 text-xs text-blue-900">{evaluation.audit_chains_verified} local audit chains and {evaluation.signed_receipts_verified} signed receipts verified · provider errors: {evaluation.provider_errors} · source hashes matched at publication: {evaluation.source_hashes_match_current_checkout ? 'yes' : 'no'}</p>
      </section>}
      <div className="rounded border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
        Fixture replay is deterministic, not an AI model. Gemini requires GEMINI_API_KEY and google-genai on the API host.
        Both providers use the same real read-only gateway. Commands and network calls are denied in this agent task. The separate container demo permits one exact command with no network. Native OS telemetry is unavailable here, so allowed actions have an INCOMPLETE EffectSeal receipt.
      </div>
      <form onSubmit={submit} className="space-y-4 rounded border bg-white p-5 shadow-sm">
        <label className="block text-sm font-semibold text-gray-800" htmlFor="gateway-task">Task</label>
        <textarea id="gateway-task" value={task} onChange={event => setTask(event.target.value)} maxLength={4000}
          className="w-full rounded border border-gray-300 p-3 text-sm" rows={3} />
        <label className="block text-sm font-semibold text-gray-800" htmlFor="gateway-provider">Provider</label>
        <select id="gateway-provider" value={provider} onChange={event => setProvider(event.target.value as 'fixture' | 'gemini')}
          className="rounded border border-gray-300 p-2 text-sm">
          <option value="fixture">Deterministic fixture replay</option>
          <option value="gemini">Gemini model</option>
        </select>
        <div><button type="submit" disabled={loading || !task.trim()} className="rounded bg-blue-700 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
          {loading ? 'Running…' : 'Run through gateway'}
        </button></div>
      </form>
      {error && <div role="alert" className="rounded border border-red-200 bg-red-50 p-4 text-red-800">{error}</div>}
      {run && <section className="space-y-4" aria-label="Gateway result">
        <div className="rounded border bg-white p-4 shadow-sm">
          <div className="flex flex-wrap gap-2 text-xs font-semibold">
            <span className="rounded bg-blue-100 px-2 py-1 text-blue-900">{run.execution_mode}</span>
            <span className="rounded bg-gray-100 px-2 py-1">{run.provider}</span>
            {run.model && <span className="rounded bg-gray-100 px-2 py-1">{run.model}</span>}
            <span className="rounded bg-gray-100 px-2 py-1">{run.stop_reason}</span>
          </div>
          <p className="mt-3 text-sm text-gray-800">{run.final_message}</p>
          <p className="mt-2 font-mono text-xs text-gray-500">Run {run.run_id}</p>
          <p className="mt-2 text-sm">Audit chain: <strong>{run.audit_verification.valid ? 'verified' : 'invalid'}</strong> ({run.audit_verification.records_checked} records)</p>
          {run.signed_receipt && <p className="mt-1 text-sm">Ed25519 receipt: <strong>{run.signed_receipt.valid ? 'verified' : 'invalid'}</strong> · key {run.signed_receipt.key_fingerprint_sha256?.slice(0, 16)}…</p>}
          {run.signed_receipt?.valid && <a className="mt-2 inline-block text-sm font-semibold text-blue-700 underline" href={`${apiClient.defaults.baseURL}/api/runtime/runs/${run.run_id}/evidence.zip`}>Download public evidence ZIP</a>}
        </div>
        {run.steps.map((step, index) => <div key={step.request_id} className="rounded border bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold">{index + 1}. {step.tool_name}</span>
            <span className={`rounded px-2 py-1 text-xs font-bold ${step.decision === 'DENY' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>{step.decision}</span>
            <span className="text-xs text-gray-600">{step.reason_code}</span>
          </div>
          <p className="mt-2 text-sm">Executor invoked: <strong>{step.executed ? 'yes' : 'no'}</strong></p>
          <p className="mt-1 text-sm">EffectSeal: <strong>{step.effectseal.verdict}</strong> · source: {step.effectseal.telemetry_source}</p>
          {step.risk && <p className="mt-1 text-sm">Risk: <strong>{step.risk.action}</strong> ({step.risk.score}/100)</p>}
          {step.effectseal.reason_codes.length > 0 && <p className="mt-1 text-xs text-amber-800">{step.effectseal.reason_codes.join(', ')}</p>}
          <p className="mt-2 break-all font-mono text-xs text-gray-500">Arguments SHA-256: {step.arguments_sha256}</p>
        </div>)}
        <p className="text-xs text-gray-500">Audit file on API host: {run.audit_file}</p>
        {run.layers && <LayerReportPanel layers={run.layers} />}
      </section>}
      <section className="rounded border bg-white p-5 shadow-sm space-y-4" aria-label="Restricted container demo">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">Restricted container command</h3>
          <p className="mt-1 text-sm text-gray-600">Run a fixed Python script from a pinned local image. Only the approved README and script are mounted. The attack fixture tries to read a synthetic secret and open an outbound connection.</p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button type="button" disabled={containerLoading} onClick={() => runContainer(false)}
            className="rounded bg-emerald-700 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">Run safe script</button>
          <button type="button" disabled={containerLoading} onClick={() => runContainer(true)}
            className="rounded bg-amber-700 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">Run attack fixture</button>
        </div>
        {containerLoading && <p className="text-sm text-gray-600">Running restricted container…</p>}
        {containerError && <p role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{containerError}</p>}
        {containerRun && <div className="space-y-2 border-t pt-4 text-sm">
          <p><strong>{containerRun.execution_mode}</strong> · {containerRun.fixture} · {containerRun.decision} · {containerRun.reason_code}</p>
          <p>Executor invoked: <strong>{containerRun.executed ? 'yes' : 'no'}</strong></p>
          <pre className="whitespace-pre-wrap rounded bg-gray-950 p-3 font-mono text-xs text-green-300">{containerRun.output || containerRun.error_type || 'No output'}</pre>
          <p>EffectSeal: <strong>{containerRun.effectseal.verdict}</strong> · source: {containerRun.effectseal.telemetry_source}</p>
          {containerRun.risk && <p>Risk: <strong>{containerRun.risk.action}</strong> ({containerRun.risk.score}/100)</p>}
          <p>Audit chain: <strong>{containerRun.audit_verification.valid ? 'verified' : 'invalid'}</strong> ({containerRun.audit_verification.records_checked} records)</p>
          {containerRun.signed_receipt && <p>Ed25519 receipt: <strong>{containerRun.signed_receipt.valid ? 'verified' : 'invalid'}</strong> · key {containerRun.signed_receipt.key_fingerprint_sha256?.slice(0, 16)}…</p>}
          <p className="break-all font-mono text-xs text-gray-500">Run {containerRun.run_id}</p>
          {containerRun.layers && <LayerReportPanel layers={containerRun.layers} />}
        </div>}
      </section>
    </div>
  );
}
