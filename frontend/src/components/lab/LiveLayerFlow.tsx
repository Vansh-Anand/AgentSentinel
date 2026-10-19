import { useEffect, useState } from 'react';
import { ArrowDown, RotateCcw } from 'lucide-react';
import type { LiveEvent } from '../../api/runtimeStream';

type Tone = 'idle' | 'active' | 'good' | 'bad' | 'limited';
type LayerState = { id: string; name: string; status: string; detail: string; tone: Tone };

const definitions = [
  ['L1', 'Proposal', 'Structured action from the agent or fixture'],
  ['L2', 'Task policy', 'Pre-execution allow or deny'],
  ['L3', 'Native effects', 'Effect receipt; no collector on this host'],
  ['L4', 'Behavior signal', 'Gateway-derived rule, not a trained detector'],
  ['L5', 'Risk governance', 'Score and continue or stop decision'],
  ['L6', 'Signed evidence', 'Local audit chain and receipt'],
  ['L7', 'Runtime trust', 'Software hashes; no TPM attestation'],
] as const;

function field(data: Record<string, unknown>, name: string): string {
  return typeof data[name] === 'string' ? data[name] as string : '';
}

export function buildLayerFlow(events: LiveEvent[]): { layers: LayerState[]; active: string | null } {
  const proposals = events.filter(event => event.event === 'tool_proposed');
  const decisions = events.filter(event => event.event === 'policy_decision');
  const effects = events.filter(event => event.event === 'effect_receipt');
  const risks = events.filter(event => event.event === 'risk_assessment');
  const last = events.at(-1);
  const completed = events.find(event => event.event === 'run_completed');
  const result = completed?.data.result as {
    audit_verification?: { valid?: boolean };
    signed_receipt?: { valid?: boolean };
    layers?: { layer: string; mode: string }[];
  } | undefined;
  const denied = decisions.filter(event => event.data.decision === 'DENY');
  const latestDecision = decisions.at(-1);
  const latestEffect = effects.at(-1);
  const latestRisk = risks.at(-1);
  const active = last?.event === 'run_started' || last?.event === 'model_request'
    || last?.event === 'model_turn' || last?.event === 'orchestrator_step'
    || last?.event === 'orchestrator_turn' || last?.event === 'tool_proposed' ? 'L1'
    : last?.event === 'policy_decision' ? 'L2'
      : last?.event === 'effect_receipt' ? 'L3'
        : last?.event === 'risk_assessment' ? 'L5' : null;

  const layers: LayerState[] = definitions.map(([id, name, initial]) => ({
    id, name, status: 'Waiting', detail: initial, tone: 'idle',
  }));
  if (last) layers[0] = { ...layers[0], status: 'Waiting for a proposal', tone: 'active' };
  if (proposals.length) {
    const recent = proposals.at(-1)!;
    layers[0] = { ...layers[0], status: `${proposals.length} proposal${proposals.length === 1 ? '' : 's'} received`,
      detail: `${field(recent.data, 'tool_name')} · ${field(recent.data, 'source') || 'agent'}`, tone: 'good' };
  } else if (completed) {
    layers[0] = { ...layers[0], status: 'No tool proposal', tone: 'limited' };
  }
  if (latestDecision) {
    layers[1] = { ...layers[1], status: denied.length ? `${denied.length} denied` : 'Allowed',
      detail: `${field(latestDecision.data, 'reason_code')} · executor ${latestDecision.data.executed ? 'invoked' : 'not invoked'}`,
      tone: denied.length ? 'bad' : 'good' };
  } else if (completed) {
    layers[1] = { ...layers[1], status: 'No policy call', tone: 'limited' };
  }
  if (latestEffect) {
    const verdict = field(latestEffect.data, 'verdict');
    layers[2] = { ...layers[2], status: verdict === 'NOT_EXECUTED' ? 'No effect attempted'
      : verdict === 'VIOLATION' ? 'Effect violation' : 'No native collector',
      detail: `${verdict} · telemetry ${field(latestEffect.data, 'telemetry_source') || 'none'}`,
      tone: verdict === 'VIOLATION' ? 'bad' : 'limited' };
  }
  if (latestRisk) {
    layers[3] = { ...layers[3], status: 'Rule signal recorded',
      detail: `Score ${String(latestRisk.data.score ?? '—')}/100 · no trained model`, tone: 'limited' };
    layers[4] = { ...layers[4], status: field(latestRisk.data, 'action') || 'Recorded',
      detail: `Gateway outcome and effect receipt assessed`,
      tone: latestRisk.data.action === 'STOP' ? 'bad' : 'good' };
  }
  if (completed) {
    const verified = result?.audit_verification?.valid === true && result?.signed_receipt?.valid === true;
    layers[5] = { ...layers[5], status: verified ? 'Verified' : 'Verification failed',
      detail: 'Local HMAC chain + Ed25519 receipt', tone: verified ? 'good' : 'bad' };
    layers[6] = { ...layers[6], status: 'Software measurement',
      detail: `${result?.layers?.find(layer => layer.layer === 'L7')?.mode ?? 'Software hashes'} · no TPM quote`,
      tone: 'limited' };
  }
  if (active) {
    const index = layers.findIndex(layer => layer.id === active);
    if (index >= 0 && layers[index].tone !== 'bad') layers[index] = { ...layers[index], tone: 'active' };
  }
  return { layers, active };
}

const toneClass: Record<Tone, string> = {
  idle: 'border-slate-200 bg-slate-50 text-slate-500',
  active: 'border-blue-500 bg-blue-50 text-blue-950 ring-2 ring-blue-100',
  good: 'border-emerald-300 bg-emerald-50 text-emerald-950',
  bad: 'border-rose-400 bg-rose-50 text-rose-950',
  limited: 'border-amber-300 bg-amber-50 text-amber-950',
};

export function LiveLayerFlow({ events }: { events: LiveEvent[] }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (events.length === 0) { setShown(0); return; }
    if (shown >= events.length) return;
    if (typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setShown(events.length);
      return;
    }
    const timer = window.setTimeout(() => setShown(current => Math.min(current + 1, events.length)), 280);
    return () => window.clearTimeout(timer);
  }, [events.length, shown]);

  const visible = events.slice(0, shown);
  const { layers, active } = buildLayerFlow(visible);
  const finished = events.some(event => event.event === 'run_completed' || event.event === 'run_error');
  return <section aria-label="Live layer flow" className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div><h2 className="text-xl font-bold text-slate-950">Seven-layer flow</h2><p className="mt-1 text-xs leading-5 text-slate-600">Paced view of received checkpoints. The trace below shows actual backend timestamps.</p></div>
      {finished && <button type="button" onClick={() => setShown(0)} className="inline-flex items-center gap-1 rounded-lg border border-slate-300 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50"><RotateCcw className="h-3.5 w-3.5" /> Replay flow</button>}
    </div>
    <p className="mt-3 text-xs font-semibold text-slate-600" aria-live="polite">{events.length ? `Showing ${shown} of ${events.length} real checkpoints${active ? ` · ${active} active` : ''}` : 'Start a run to light up the stages it actually reaches.'}</p>
    <ol className="mt-4" aria-label="Security stages">{layers.map((layer, index) => <li key={layer.id}>
      <div className={`rounded-xl border px-3 py-2.5 transition-colors duration-300 ${toneClass[layer.tone]}`}>
        <div className="flex flex-wrap items-center justify-between gap-2"><strong className="text-sm">{layer.id} · {layer.name}</strong><span className="text-xs font-bold">{layer.status}</span></div>
        <p className="mt-0.5 text-xs leading-5 opacity-80">{layer.detail}</p>
      </div>
      {index < layers.length - 1 && <div className="flex h-4 items-center justify-center" aria-hidden="true"><ArrowDown className={`h-4 w-4 transition-colors duration-300 ${layers[index + 1].tone === 'idle' ? 'text-slate-300' : 'text-blue-500'} ${active === layer.id ? 'motion-safe:animate-bounce' : ''}`} /></div>}
    </li>)}</ol>
    <p className="mt-3 text-xs leading-5 text-slate-500">A denial stops the proposed tool at L2. L3 can still record “not executed”; amber stages describe limited evidence, not passed native defenses.</p>
  </section>;
}
