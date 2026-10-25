import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, CheckCircle2, ChevronRight, Download, Pause, Play, RotateCcw, ShieldAlert } from 'lucide-react';
import { downloadLabFile, labRequest, streamLab, type LabEvent, type LabResult, type SavedRun } from '../api/secureLab';
import { LayerResponsibilities } from '../components/lab/LayerResponsibilities';
import { ActionStory, policyExplanation } from '../components/lab/ActionStory';
import { ProvenanceGraph } from '../components/lab/ProvenanceGraph';

const terminal = new Set(['COMPLETED', 'BLOCKED', 'STOPPED', 'CANCELLED', 'ERROR']);
const layerNames: Record<string, string> = { L1: 'Input & schema', L2: 'Task authorization', L3: 'Bounded execution', L4: 'Behavior rules', L5: 'Run governance', L6: 'Evidence integrity', L7: 'Runtime integrity' };

function useSavedRun(runId?: string) {
  const [run, setRun] = useState<SavedRun | null>(null);
  const [events, setEvents] = useState<LabEvent[]>([]);
  const [error, setError] = useState('');
  const [connection, setConnection] = useState('');
  useEffect(() => {
    if (!runId) return;
    const controller = new AbortController();
    let last = 0;
    async function load() {
      try {
        const saved = await labRequest<SavedRun>(`/runs/${runId}`, undefined, controller.signal);
        setRun(saved); setEvents(saved.events ?? []);
        last = saved.events?.at(-1)?.sequence ?? 0;
        if (terminal.has(saved.status)) return;
        for (let attempt = 0; attempt < 3 && !controller.signal.aborted; attempt++) {
          try {
            setConnection(attempt ? `Reconnecting (${attempt + 1}/3)…` : 'Receiving live checkpoints');
            await streamLab(runId!, last, event => {
              if (event.sequence <= last) return;
              last = event.sequence;
              setEvents(previous => [...previous, event]);
              if (event.type === 'run_terminal') setRun(current => current ? { ...current, status: (event.data.result as LabResult).status, result: event.data.result as LabResult } : current);
            }, controller.signal);
          } catch (cause) { if (attempt === 2 && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Live trace disconnected.'); }
          if (controller.signal.aborted) return;
          const latest = await labRequest<SavedRun>(`/runs/${runId}`, undefined, controller.signal);
          setRun(latest); setEvents(latest.events ?? []);
          last = latest.events?.at(-1)?.sequence ?? last;
          if (terminal.has(latest.status)) { setConnection(''); return; }
          await new Promise(resolve => setTimeout(resolve, 500 * 2 ** attempt));
        }
        setConnection('Live updates paused. Reload this run to reconnect.');
      } catch (cause) { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not open this run.'); }
    }
    void load();
    return () => controller.abort();
  }, [runId]);
  return { run, events, error, connection };
}

function Breadcrumb({ run, view }: { run: SavedRun; view: string }) {
  const conversationId = (run.config as SavedRun['config'] & { conversation_id?: string }).conversation_id;
  return <nav aria-label="Run navigation" className="flex flex-wrap items-center gap-2 text-xs text-slate-400"><Link to={conversationId ? `/playground/${conversationId}` : '/lab'} className="hover:text-cyan-300">Chat</Link><ChevronRight size={13} /><Link to="/evidence" className="hover:text-cyan-300">Run details</Link><ChevronRight size={13} /><span className="text-cyan-200">{view}</span></nav>;
}

function badge(decision?: string | null) {
  if (decision === 'DENY' || decision === 'STOP' || decision === 'BLOCKED') return 'product-badge-deny';
  if (decision === 'REVIEW' || decision === 'ERROR') return 'product-badge-review';
  if (decision === 'ALLOW' || decision === 'COMPLETED') return 'product-badge-allow';
  return 'product-badge-wait';
}

export function RunTracePage() {
  const { runId } = useParams();
  const { run, events, error, connection } = useSavedRun(runId);
  const [actionId, setActionId] = useState('');
  const [replay, setReplay] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [selectedLayer, setSelectedLayer] = useState('');
  const actions = useMemo(() => events.filter(event => event.type === 'tool_proposed').map(event => ({ id: event.action_id ?? String(event.data.request_id), sequence: event.sequence, tool: String(event.data.tool), source: String(event.data.source ?? 'agent') })), [events]);
  const deniedAction = run?.result?.steps?.find(step => step.decision === 'DENY');
  const chosen = actionId || deniedAction?.request_id || actions.at(-1)?.id || '';
  const visible = replay === null ? events : events.slice(0, replay);
  const chosenIndex = actions.findIndex(item => item.id === chosen);
  const actionStart = chosenIndex >= 0 ? actions[chosenIndex].sequence : Infinity;
  const actionEnd = chosenIndex >= 0 ? actions[chosenIndex + 1]?.sequence ?? Infinity : Infinity;
  const focused = chosen ? visible.filter(event => event.action_id === chosen ||
    (!event.phase && event.sequence >= actionStart && event.sequence < actionEnd &&
      !(event.layer === 'L6' && event.data.reason === 'AUDIT_CHAIN_VERIFIED'))) : [];
  const admission = visible.filter(event => (event.phase === 'admission' ||
    (!event.phase && event.sequence < (actions[0]?.sequence ?? Infinity))) && event.type === 'layer_completed');
  const finalization = visible.filter(event => (event.phase === 'finalization' ||
    (!event.phase && event.layer === 'L6' && event.data.reason === 'AUDIT_CHAIN_VERIFIED')) && event.type === 'layer_completed');
  const actionEvents = focused.filter(event => event.type === 'layer_completed');
  const step = run?.result?.steps?.find(value => value.request_id === chosen);
  const latest = focused.at(-1);
  const intercepted = actionEvents.find(event => event.data.decision === 'DENY' || event.data.decision === 'STOP');
  const lastLayer = selectedLayer ? [...focused, ...admission, ...finalization].reverse().find(event => event.type === 'layer_completed' && event.layer === selectedLayer) : undefined;
  useEffect(() => {
    if (!playing || replay === null) return;
    if (replay >= events.length) { setPlaying(false); return; }
    const timer = window.setTimeout(() => setReplay(value => Math.min(events.length, (value ?? 0) + 1)), 240);
    return () => window.clearTimeout(timer);
  }, [playing, replay, events.length]);

  return <div className="product-page sentinel-workbench space-y-5 pb-10">
    {run && <Breadcrumb run={run} view="Layer trace" />}
    <header className="product-card flex flex-wrap items-start justify-between gap-4 p-6"><div><p className="product-eyebrow">RECORDED SECURITY TRACE</p><h2 className="mt-2 text-2xl font-bold text-white">Follow the decision</h2><p className="mt-2 text-sm text-slate-300">Each checkpoint below came from this run. Select an action to see its own checks and effects.</p></div>{runId && <Link to={`/runs/${runId}/results`} className="product-primary">Results <ArrowRight size={16} /></Link>}</header>
    {error && <p role="alert" className="product-alert">{error}</p>}{connection && <p role="status" className="text-xs text-cyan-200">{connection}</p>}
    {!run && !error && <p className="text-sm text-slate-300">Loading run trace…</p>}
    {run && <div className="grid gap-5 xl:grid-cols-[minmax(0,1.45fr)_minmax(280px,.75fr)]"><div className="space-y-5">
      <section className="product-card p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="product-eyebrow">RUN ADMISSION</p><h3 className="mt-1 text-lg font-semibold text-white">Before the first tool action</h3></div><span className={badge(run.status)}>{run.status}</span></div><div className="mt-4 grid gap-3 sm:grid-cols-2">{['L7', 'L1'].map(id => { const check = admission.filter(event => event.layer === id).at(-1); return <button type="button" key={id} onClick={() => setSelectedLayer(id)} className="product-layer text-left"><span className="text-xs font-bold text-cyan-300">{id} · {layerNames[id]}</span><span className={`mt-2 inline-block ${badge(check ? String(check.data.decision) : null)}`}>{check ? String(check.data.decision) : 'NOT REACHED'}</span><span className="mt-2 block text-xs text-slate-300">{check ? String(check.data.reason) : 'No checkpoint recorded'}</span></button>; })}</div></section>
      <section className="product-card p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="product-eyebrow">ACTION CHECKS</p><h3 className="mt-1 text-lg font-semibold text-white">What reached the gateway</h3></div><select aria-label="Select action" value={chosen} onChange={event => { setActionId(event.target.value); setSelectedLayer(''); }} className="product-input w-auto max-w-full">{actions.length ? actions.map((item, index) => <option key={item.id} value={item.id}>Action {index + 1} · {item.tool} · {item.source}</option>) : <option value="">No proposed action</option>}</select></div>
        {!actions.length && <p className="mt-5 rounded-xl border border-white/10 p-4 text-sm text-slate-300">No tool action was proposed. A model refusal or an admission check may have ended the run before action enforcement.</p>}
        {actions.length > 0 && <><div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{['L1', 'L4', 'L5', 'L2', 'L6', 'L3'].map(id => { const check = actionEvents.filter(event => event.layer === id).at(-1); const recorded = id === 'L6' && focused.some(event => event.type === 'execution_finished') && !focused.some(event => event.type === 'layer_completed' && event.layer === 'L6'); return <button type="button" key={id} onClick={() => setSelectedLayer(id)} className={`product-layer text-left ${latest?.type === 'layer_started' && latest.layer === id ? 'sentinel-layer-active' : ''}`}><span className="text-xs font-bold text-cyan-300">{id} · {layerNames[id]}</span><span className={`mt-2 inline-block ${badge(check ? String(check.data.decision) : recorded ? 'ALLOW' : null)}`}>{check ? String(check.data.decision) : recorded ? 'DISPATCH RECORDED' : 'NOT REACHED'}</span><span className="mt-2 block text-xs text-slate-300">{check ? String(check.data.reason) : recorded ? 'Audit/dispatch outcome is recorded in this action receipt.' : 'No checkpoint recorded for this action'}</span></button>; })}</div>
          <div className={`mt-4 rounded-xl border p-4 text-sm ${intercepted ? 'border-rose-400/30 bg-rose-500/10 text-rose-100' : 'border-cyan-400/20 bg-cyan-400/5 text-slate-200'}`}><strong>{intercepted ? `Intercepted at ${intercepted.layer}` : step?.completed ? 'Action completed' : step?.executor_invoked ? 'Executor invoked; operation incomplete' : 'Inspect the action receipt'}</strong><p className="mt-1 text-xs">{intercepted ? String(intercepted.data.detail) : step ? `${step.reason} · Executor ${step.executor_invoked ? 'invoked' : 'not invoked'} · ${step.effects.length} observed effect(s).` : 'This action has not produced a terminal receipt.'}</p></div></>}
      </section>
      <section className="product-card p-5"><div className="flex items-center justify-between gap-2"><div><p className="product-eyebrow">RECORDED EVENTS</p><h3 className="mt-1 font-semibold text-white">Chronological checkpoints</h3></div>{run.result && <button type="button" onClick={() => { setReplay(0); setPlaying(true); }} className="product-icon-button" aria-label="Replay trace"><RotateCcw size={16} /></button>}</div><div className="mt-4 max-h-72 space-y-2 overflow-y-auto">{visible.filter(event => event.type === 'layer_completed' || event.type === 'tool_proposed' || event.type === 'execution_finished' || event.type === 'approval_required' || event.type.startsWith('windows_')).map(event => <div key={event.sequence} className="flex items-start gap-3 rounded-lg border border-white/10 bg-slate-900/40 px-3 py-2 text-xs"><span className="w-14 shrink-0 font-mono text-slate-500">{event.elapsed_ms}ms</span><span className="text-cyan-300">{event.layer ?? 'RUN'}</span><span className="text-slate-200">{event.type === 'layer_completed' ? String(event.data.reason) : event.type.replaceAll('_', ' ')}{event.type.startsWith('windows_') && event.data.reason ? ` · ${String(event.data.reason)}` : ''}{event.action_id ? ` · action ${event.action_id.split(':').at(-1)}` : ''}</span></div>)}</div>{replay !== null && <div className="mt-4 flex items-center gap-2"><button type="button" className="product-icon-button" aria-label={playing ? 'Pause replay' : 'Play replay'} onClick={() => setPlaying(value => !value)}>{playing ? <Pause size={15} /> : <Play size={15} />}</button><input aria-label="Replay position" type="range" min={0} max={events.length} value={replay} onChange={event => { setPlaying(false); setReplay(Number(event.target.value)); }} className="flex-1" /><span className="text-xs text-slate-400">{replay}/{events.length}</span></div>}<p className="mt-3 text-[11px] text-slate-400">Replay is paced for viewing. Millisecond labels are recorded backend elapsed times.</p></section>
    </div><aside className="space-y-5"><section className="product-card p-5"><p className="product-eyebrow">SELECTED CHECK</p><h3 className="mt-2 text-lg font-semibold text-white">{selectedLayer ? `${selectedLayer} · ${layerNames[selectedLayer]}` : 'Choose a layer'}</h3><p className="mt-3 text-sm text-slate-300">{lastLayer ? String(lastLayer.data.detail) : 'Select any recorded layer to read its decision and reason.'}</p>{lastLayer && <p className="mt-3 font-mono text-xs text-cyan-300">{String(lastLayer.data.reason)}</p>}</section><section className="product-card p-5"><p className="product-eyebrow">EXECUTION RECEIPT</p><p className="mt-3 text-sm text-white">{step ? `Executor ${step.executor_invoked ? 'invoked' : 'not invoked'}` : 'No action receipt selected'}</p><p className="mt-2 text-sm text-slate-300">{step ? `${step.effects.length} application effect(s) recorded` : 'Unreached checks are not passes.'}</p>{step?.effects.map((effect, index) => <p key={index} className="mt-2 break-all rounded-lg bg-slate-800 p-2 text-xs text-slate-200">{effect.kind} · {effect.target}</p>)}</section><section className="product-card p-5"><p className="product-eyebrow">FINALIZATION</p><div className="mt-3 space-y-2">{finalization.map(event => <p key={event.sequence} className="text-xs text-slate-200">{event.layer} · {String(event.data.reason)}</p>)}{!finalization.length && <p className="text-xs text-slate-400">No finalization checkpoint recorded yet.</p>}</div></section></aside></div>}
  </div>;
}

export function RunResultsPage() {
  const { runId } = useParams();
  const { run, events, error, connection } = useSavedRun(runId);
  const [verification, setVerification] = useState<{ valid: boolean; reason?: string } | null>(null);
  const [comparison, setComparison] = useState<{ comparisons: { tool: string; original: string; counterfactual: string; reason: string }[]; limitations: string } | null>(null);
  const [notice, setNotice] = useState('');
  useEffect(() => { if (runId && run?.result) void labRequest<{ valid: boolean; reason?: string }>(`/runs/${runId}/verify`).then(setVerification).catch(() => setVerification({ valid: false, reason: 'EVIDENCE_UNAVAILABLE' })); }, [runId, run?.result]);
  const result = run?.result;
  const deniedAction = result?.steps?.find(step => step.decision === 'DENY');
  const stoppedAction = result?.steps?.find(step => step.executor_invoked && !step.completed);
  const interception = result?.enforcing_layer ?? events.find(event =>
    event.type === 'layer_completed' && event.data.decision === 'DENY')?.layer;
  const report = result?.steps?.some(step => step.effects.some(effect => effect.kind === 'file_write'));
  const ticket = result?.steps?.some(step => step.effects.some(effect => effect.kind === 'ticket_created'));
  async function download(kind: 'export' | 'artifact' | 'ticket') { try { await downloadLabFile(runId!, kind); } catch (cause) { setNotice(cause instanceof Error ? cause.message : 'Download unavailable.'); } }
  async function compare(profile: string) { try { setComparison(await labRequest(`/runs/${runId}/counterfactual`, { profile })); } catch (cause) { setNotice(cause instanceof Error ? cause.message : 'Comparison unavailable.'); } }
  return <div className="product-page sentinel-workbench space-y-5 pb-10">
    {run && <Breadcrumb run={run} view="Results" />}
    <header className="product-card flex flex-wrap items-start justify-between gap-4 p-6"><div><p className="product-eyebrow">RUN RESULTS</p><h2 className="mt-2 text-2xl font-bold text-white">What happened to this request?</h2><p className="mt-2 break-all font-mono text-xs text-slate-400">{runId}</p>{result && <p className="mt-2 text-xs text-cyan-200">{result.evidence_mode === 'MANUAL_ADAPTER' ? 'Direct policy probe · no model inference' : result.evidence_mode === 'EXTERNAL_INTEGRATION' ? 'External integration action' : result.evidence_mode === 'FIXTURE' ? 'Scripted fixture' : `${result.provider} live model`}</p>}</div>{runId && <Link to={`/runs/${runId}/trace`} className="product-secondary"><ArrowLeft size={15} /> Layer trace</Link>}</header>
    {error && <p role="alert" className="product-alert">{error}</p>}{notice && <p role="status" className="product-alert">{notice}</p>}{connection && <p className="text-xs text-cyan-200">{connection}</p>}
    {!run && !error && <p className="text-sm text-slate-300">Loading results…</p>}
    {run && <>{result?.workspace_documents && Object.keys(result.workspace_documents).length > 0 && <details className="product-card p-4"><summary className="cursor-pointer text-sm text-cyan-200">Documents bound to this run</summary>{Object.entries(result.workspace_documents).map(([id, doc]) => <p key={id} className="mt-3 break-all text-xs leading-6 text-slate-300">{doc.name} · {doc.bytes} bytes<br />Document: {id}<br />Source: {doc.source_id}<br />SHA-256: {doc.sha256}</p>)}</details>}<details><summary className="cursor-pointer text-sm font-semibold text-cyan-200">Explain all seven security responsibilities</summary><div className="mt-3"><LayerResponsibilities events={events} result={result} /></div></details><ActionStory events={events} result={result} busy={!terminal.has(run.status)} /><div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3"><div className="product-card p-5"><p className="product-eyebrow">OUTCOME</p><span className={`mt-3 inline-block ${badge(result?.status ?? run.status)}`}>{result?.status ?? run.status}</span><p className="mt-3 text-sm text-slate-200">{result?.reason?.replaceAll('_', ' ') ?? 'Run is still processing.'}</p></div><div className="product-card p-5"><p className="product-eyebrow">INTERCEPTION</p><p className="mt-3 text-lg font-semibold text-white">{interception ?? 'No enforcing layer'}</p><p className="mt-2 text-xs text-slate-400">{deniedAction ? `${deniedAction.tool} was denied (${deniedAction.reason}); executor ${deniedAction.executor_invoked ? 'invoked' : 'not invoked'}. ${result?.status === 'COMPLETED' ? 'The agent then continued within policy.' : ''}` : stoppedAction ? `${stoppedAction.tool} was authorized, but execution stopped (${result?.reason}). The executor was invoked and recorded ${stoppedAction.effects.length} effect(s).` : 'No tool proposal was denied. A model refusal is not a gateway interception.'}</p></div><div className="product-card p-5"><p className="product-eyebrow">EVIDENCE</p><p className={`mt-3 flex items-center gap-2 text-sm font-semibold ${verification?.valid ? 'text-emerald-300' : 'text-amber-200'}`}>{verification?.valid ? <CheckCircle2 size={17} /> : <ShieldAlert size={17} />}{verification ? verification.valid ? 'Verified against this host’s public key' : verification.reason ?? 'Not verified' : 'Verification pending'}</p><p className="mt-2 text-xs text-slate-400">A host-held signature is evidence integrity, not hardware attestation.</p></div></div>
      <section className="product-card p-6"><p className="product-eyebrow">AGENT ANSWER</p><p className="mt-4 whitespace-pre-wrap text-sm leading-7 text-slate-100">{result?.answer || (terminal.has(run.status) ? 'No public answer was released for this run.' : 'Waiting for the agent to finish.')}</p><p className="mt-3 text-xs text-slate-400">Model-written text is not general fact-checked output. Tool receipts and explicit arithmetic checks are shown separately.</p></section>
      <section className="product-card p-6"><p className="product-eyebrow">ACTION RECEIPTS</p><h3 className="mt-2 text-lg font-semibold text-white">What was requested. What actually ran.</h3><div className="mt-4 space-y-4">{result?.steps?.map(step => {
        const check = events.filter(event => event.type === 'layer_completed' && event.action_id === step.request_id && ['DENY', 'STOP'].includes(String(event.data.decision))).at(-1);
        return <article key={step.request_id} className={`rounded-xl border p-4 ${step.decision === 'DENY' ? 'border-rose-400/30 bg-rose-400/5' : 'border-white/10 bg-slate-900/40'}`}>
          <div className="flex flex-wrap justify-between gap-2"><strong className="text-sm text-white">{step.tool}</strong><span className={badge(step.decision)}>{step.decision}</span></div>
          <p className="mt-3 text-sm leading-6 text-slate-200">{step.decision === 'DENY' ? policyExplanation(step.reason) : step.completed ? 'The authorized tool completed. Its recorded effects are listed below.' : 'The tool was authorized, but did not complete. Inspect the receipt and trace.'}</p>
          <div className="mt-4 grid gap-3 text-xs sm:grid-cols-3"><div><span className="text-slate-400">Enforcing check</span><p className="mt-1 text-white">{check?.layer ?? (step.decision === 'DENY' ? 'See trace' : 'No denial recorded')}</p></div><div><span className="text-slate-400">Executor</span><p className="mt-1 text-white">{step.executor_invoked ? 'Invoked' : 'Not invoked'}</p></div><div><span className="text-slate-400">Recorded effects</span><p className="mt-1 text-white">{step.effects.length}</p></div></div>
          {step.effects.map((effect, index) => <p key={index} className="mt-2 text-xs text-slate-300">{effect.kind.replaceAll('_', ' ')} · {effect.target}</p>)}
          <details className="mt-4 text-xs text-slate-400"><summary className="cursor-pointer">Requested arguments & rule code</summary><pre className="mt-2 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-950/60 p-3">{JSON.stringify(step.arguments, null, 2)}</pre><p className="mt-2 font-mono text-cyan-300">{step.reason}</p><p className="mt-1 break-all">Request: {step.request_id}</p></details>
        </article>;
      })}{!result?.steps?.length && <p className="text-sm text-slate-400">No tool action receipts recorded. A model refusal alone is not a gateway interception. For admission failures, inspect the technical trace.</p>}</div></section>
      {!!result?.steps?.some(step => step.windows) && <details className="product-card p-6"><summary className="cursor-pointer text-sm font-semibold text-slate-200">Advanced · Windows worker & ETW</summary><p className="product-eyebrow mt-4">L3 WINDOWS WORKER</p><h3 className="mt-2 text-lg font-semibold text-white">Resource limits and observed activity</h3><p className="mt-2 text-xs text-slate-400">The Job Object constrains worker resources. ETW records process events when Windows permits tracing; it does not enforce file or network policy.</p><div className="mt-4 space-y-3">{result.steps.filter(step => step.windows).map(step => { const worker = step.windows!; return <div key={step.request_id} className="rounded-xl border border-white/10 bg-slate-900/50 p-4"><p className="text-sm font-semibold text-white">{step.tool} · {worker.termination_reason.replaceAll('_', ' ')}</p><p className="mt-2 text-xs text-slate-300">Job assigned: {worker.job_assigned ? 'yes' : 'no'} · Action released: {worker.action_released ? 'yes' : 'no'} · Worker PID: {worker.worker_pid ?? '—'} · {worker.duration_ms ?? '—'} ms</p>{worker.limits && <p className="mt-1 text-xs text-slate-400">Limit: {Math.round(worker.limits.process_memory_bytes / 1048576)} MiB · {worker.limits.active_processes} process · {worker.limits.wall_clock_seconds} s · kill on close {worker.limits.kill_on_close ? 'on' : 'off'}</p>}<p className="mt-2 text-xs text-cyan-200">ETW: {worker.etw?.status?.replaceAll('_', ' ') ?? 'not started'}{worker.etw?.reason ? ` · ${worker.etw.reason.replaceAll('_', ' ')}` : ''} · coverage {worker.etw?.coverage?.replaceAll('_', ' ') ?? 'none'}</p>{worker.etw?.events_scanned !== undefined && <p className="mt-1 text-xs text-slate-400">Process start {worker.etw.process_start_observed ? 'observed' : 'not observed'} · {worker.etw.matched_events?.length ?? 0} matching lifecycle event(s) from {worker.etw.events_scanned} scanned · loss count {worker.etw.lost_events ?? 'unknown'}.</p>}</div>; })}</div></details>}
      <details className="product-card p-6"><summary className="cursor-pointer text-sm font-semibold text-slate-200">Source provenance · documents to artifacts</summary><div className="mt-4"><ProvenanceGraph data={result?.provenance} /></div></details>
      <section className="product-card p-6"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="product-eyebrow">EXPORT AND COMPARE</p><h3 className="mt-2 text-lg font-semibold text-white">Inspectable evidence</h3></div><span className="text-xs text-slate-400">{result?.duration_ms ?? '—'} ms total run time</span></div><div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={() => void download('export')} disabled={!verification?.valid} className="product-secondary disabled:opacity-40"><Download size={15} /> Signed evidence</button>{report && <button type="button" onClick={() => void download('artifact')} disabled={!verification?.valid} className="product-secondary disabled:opacity-40"><Download size={15} /> Report</button>}{ticket && <button type="button" onClick={() => void download('ticket')} disabled={!verification?.valid} className="product-secondary disabled:opacity-40"><Download size={15} /> Local ticket</button>}</div><details className="mt-5 border-t border-white/10 pt-4"><summary className="mb-3 cursor-pointer text-xs text-slate-300">Advanced · Compare saved actions under another policy</summary><label className="text-xs text-slate-300">Compare the saved actions under another policy<select aria-label="Comparison policy" defaultValue="" onChange={event => { if (event.target.value) void compare(event.target.value); }} className="product-input mt-2 max-w-xs"><option value="">Choose a policy</option><option value="read_only">Read only</option><option value="balanced">Balanced</option><option value="strict">Strict input</option><option value="approval">Approval required</option></select></label>{comparison && <><p className="mt-3 text-xs text-slate-400">{comparison.limitations}</p><div className="mt-2 space-y-2">{comparison.comparisons.map((item, index) => <p key={index} className="rounded-lg bg-slate-800 p-2 text-xs text-slate-200">{item.tool}: {item.original} → {item.counterfactual} ({item.reason})</p>)}</div></>}</details></section>
    </>}
  </div>;
}
