import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Pause, Play, RotateCcw, ShieldCheck } from 'lucide-react';
import type { LabEvent, Layer, LabResult } from '../../api/secureLab';

export const layerNames: Record<string, string> = {
  L1: 'Input & schema', L2: 'Task authorization', L3: 'Bounded execution',
  L4: 'Behavior rules', L5: 'Run governance', L6: 'Evidence integrity', L7: 'Runtime integrity',
};
const admission = ['L7', 'L1'];
const action = ['L4', 'L5', 'L2', 'L6', 'L3'];

export function deriveLayers(events: LabEvent[], result?: LabResult | null, definitions?: { id: string; name: string }[]): Layer[] {
  const layers = (definitions ?? Object.entries(layerNames).map(([id, name]) => ({ id, name })))
    .map(({ id, name }) => ({ id, name, state: 'WAITING', decision: null as string | null,
      reason: 'NOT_REACHED', detail: 'This check has not received an event.', mode: 'LIVE_APPLICATION' }));
  for (const event of events) {
    const layer = layers.find(value => value.id === event.layer);
    if (!layer) continue;
    if (event.type === 'layer_started') layer.state = 'RUNNING';
    if (event.type === 'layer_completed') Object.assign(layer, event.data, { state: 'COMPLETED' });
  }
  if (!result?.layers) return layers;
  const authoritative = result.layers.map(layer => ({ ...layer }));
  const latestProposal = events.filter(event => event.type === 'tool_proposed').at(-1);
  const dispatched = latestProposal && events.some(event => event.type === 'execution_finished'
    && event.data.request_id === latestProposal.data.request_id);
  if (result.enforcing_layer && latestProposal && !dispatched) {
    const execution = authoritative.find(layer => layer.id === 'L3');
    if (execution) Object.assign(execution, { state: 'NOT_REACHED', decision: null,
      reason: 'LATEST_PROPOSAL_NOT_DISPATCHED',
      detail: 'The stopped action did not reach its executor. Earlier permitted actions remain in the receipts.' });
  }
  return authoritative;
}

function tone(layer: Layer, active: boolean) {
  if (layer.decision === 'DENY' || layer.decision === 'STOP') return 'border-rose-300 bg-rose-50 text-rose-950';
  if (layer.decision === 'REVIEW') return 'border-amber-300 bg-amber-50 text-amber-950';
  if (active) return 'border-cyan-500 bg-cyan-50 text-cyan-950 sentinel-layer-active';
  if (layer.decision === 'ALLOW') return 'border-emerald-200 bg-emerald-50/70 text-emerald-900';
  return 'border-slate-200 bg-white text-slate-500';
}

function caption(event: LabEvent | undefined, names: Record<string, string>): string {
  if (!event) return 'Start a run to watch each real checkpoint.';
  if (event.type === 'tool_proposed') return `Agent proposed ${String(event.data.tool)}.`;
  if (event.type === 'layer_started') return `Checking ${names[event.layer ?? ''] ?? 'the action'}…`;
  if (event.type === 'layer_completed') return `${event.layer} ${names[event.layer ?? ''] ?? ''}: ${String(event.data.reason ?? event.data.decision)}.`;
  if (event.type === 'execution_finished') return event.data.executor_invoked ? `Executor ${event.data.completed ? 'completed' : 'stopped'} ${String(event.data.tool)}.` : 'Tool executor was not invoked.';
  if (event.type === 'approval_required') return 'Waiting for the owner to review this exact action.';
  if (event.type === 'run_terminal') return `Run ended: ${String((event.data.result as LabResult)?.status ?? 'finished')}.`;
  return event.type.replaceAll('_', ' ');
}

export function SecurityGraph({ events, result, definitions }: {
  events: LabEvent[]; result: LabResult | null; definitions?: { id: string; name: string }[];
}) {
  const [replay, setReplay] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => { setReplay(null); setPlaying(false); setSelected(null); }, [events[0]?.run_id]);
  useEffect(() => {
    if (!playing || replay === null) return;
    if (replay >= events.length) { setPlaying(false); return; }
    const timer = window.setTimeout(() => setReplay(value => Math.min(events.length, (value ?? 0) + 1)), 230 / speed);
    return () => clearTimeout(timer);
  }, [playing, replay, events.length, speed]);
  const visible = replay === null ? events : events.slice(0, replay);
  const terminal = visible.some(event => event.type === 'run_terminal');
  const names = Object.fromEntries((definitions ?? Object.entries(layerNames).map(([id, name]) => ({ id, name }))).map(value => [value.id, value.name]));
  const layers = deriveLayers(visible, replay === null || terminal ? result : null, definitions);
  const lastEvent = visible.at(-1);
  const active = replay === null && result || terminal ? null : lastEvent?.layer;
  const focused = layers.find(layer => layer.id === (selected ?? active ?? (replay === null || terminal ? result?.enforcing_layer : null) ?? 'L7')) ?? layers[0];
  const checkpoints = visible.filter(event => event.type === 'layer_completed' && event.layer);
  const latestTransition = checkpoints.length > 1 ? [checkpoints.at(-2)!.layer, checkpoints.at(-1)!.layer] : null;
  const latestTool = visible.filter(event => event.type === 'tool_proposed').at(-1);
  const renderNode = (id: string) => {
    const layer = layers.find(value => value.id === id);
    if (!layer) return null;
    return <button key={id} type="button" onClick={() => setSelected(id)}
      className={`min-w-0 rounded-xl border p-3 text-left transition-colors focus-visible:outline-2 focus-visible:outline-cyan-700 ${tone(layer, active === id)}`}
      aria-label={`${id} ${layer.name}: ${layer.decision ?? layer.state}`}>
      <span className="text-[10px] font-extrabold tracking-wider">{id}</span>
      <span className="mt-1 block text-xs font-bold">{layer.name}</span>
      <span className="mt-1 block text-[10px] font-semibold">{layer.decision ?? layer.state.replaceAll('_', ' ')}</span>
    </button>;
  };
  return <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm" aria-label="Seven-layer security graph">
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 p-4">
      <div><h2 className="font-bold text-slate-950">Live security path</h2><p className="mt-1 text-xs text-slate-500">{replay === null ? 'Real checkpoints' : `Recorded replay · ${replay}/${events.length}`}</p></div>
      {result && <button type="button" aria-label="Replay recorded trace" onClick={() => { setReplay(0); setPlaying(true); setSelected(null); }} className="rounded-lg border p-2 text-slate-600 hover:bg-slate-50"><RotateCcw size={15} /></button>}
    </div>
    <div className="border-b border-slate-100 bg-slate-950 px-4 py-3 text-white" aria-live="polite">
      <div className="flex items-center gap-2"><ShieldCheck size={17} className="shrink-0 text-cyan-300" /><strong className="text-sm">{caption(lastEvent, names)}</strong></div>
      <p className="mt-1 pl-6 text-[11px] text-slate-300">{latestTool ? `Action ${String(latestTool.data.request_id).split(':').at(-1)} · ${String(latestTool.data.tool)}` : 'Admission checks begin before any tool action.'}{latestTransition ? ` · ${latestTransition[0]} → ${latestTransition[1]}` : ''}</p>
    </div>
    <div className="space-y-4 bg-slate-50/70 p-4">
      <div><p className="mb-2 text-[10px] font-extrabold uppercase tracking-wider text-slate-500">Run admission</p><div className="grid grid-cols-2 gap-2">{admission.map(renderNode)}</div></div>
      <div><p className="mb-2 text-[10px] font-extrabold uppercase tracking-wider text-slate-500">For each proposed tool action</p><div className="grid grid-cols-2 gap-2 sm:grid-cols-3">{action.map(renderNode)}</div></div>
      {latestTransition && <div className="flex items-center gap-2 text-[11px] font-semibold text-cyan-800"><span className="sentinel-flow-packet inline-block h-2 w-2 rounded-full bg-cyan-500" /> Latest observed transition: {latestTransition[0]} → {latestTransition[1]}</div>}
    </div>
    <div className="border-t border-slate-100 px-4 py-3" aria-live="polite"><strong className="text-sm text-slate-950">{focused.id} · {focused.name}</strong><span className="ml-2 text-[10px] text-slate-500">{focused.mode}</span><p className="mt-1 text-xs font-semibold text-cyan-800">{focused.reason}</p><p className="mt-1 text-xs leading-5 text-slate-600">{focused.detail || 'No decision yet.'}</p></div>
    {replay !== null && <div className="flex flex-wrap items-center gap-2 border-t border-slate-100 p-3"><button type="button" onClick={() => { setPlaying(false); setReplay(Math.max(0, replay-1)); }} aria-label="Previous event" className="rounded border p-1"><ChevronLeft size={16} /></button><button type="button" onClick={() => setPlaying(value => !value)} aria-label={playing ? 'Pause replay' : 'Resume replay'} className="rounded border p-1">{playing ? <Pause size={16} /> : <Play size={16} />}</button><button type="button" onClick={() => { setPlaying(false); setReplay(Math.min(events.length, replay+1)); }} aria-label="Next event" className="rounded border p-1"><ChevronRight size={16} /></button><input aria-label="Replay position" type="range" min={0} max={events.length} value={replay} onChange={event => { setPlaying(false); setReplay(Number(event.target.value)); }} className="min-w-24 flex-1" /><select aria-label="Replay speed" value={speed} onChange={event => setSpeed(Number(event.target.value))} className="rounded border p-1 text-xs"><option value={0.5}>0.5×</option><option value={1}>1×</option><option value={2}>2×</option></select></div>}
  </section>;
}
