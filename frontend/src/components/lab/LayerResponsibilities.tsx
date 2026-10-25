import type { LabEvent, LabResult } from '../../api/secureLab';

const responsibilities = [
  ['L1', 'Validation', 'Are the request and tool arguments in the declared format?', 'Request sizes, tool names and strict argument schemas.'],
  ['L2', 'Authorization', 'May this action access this resource?', 'Server-owned capabilities, selected document IDs, source citations and destinations.'],
  ['L3', 'Controlled execution', 'What actually ran, and within which limits?', 'Tool execution receipts; Windows Job resource/lifetime controls; optional ETW process observations.'],
  ['L4', 'Behavior rules', 'Is this sequence exceeding a documented boundary?', 'Per-run identical proposal counter (maximum 2) and live direct-read enumeration (maximum 4 distinct documents).'],
  ['L5', 'Governance', 'May work continue, and does this write need approval?', 'Six tool calls, 90-second run budget, cancellation, exact-action approval and expiry.'],
  ['L6', 'Evidence', 'Can the recorded decisions and outcomes be verified?', 'Durable records, local audit chain and signed export. The API host and signing key are trusted.'],
  ['L7', 'Software integrity', 'Do measured source files match the approved baseline?', 'Versioned source manifest checked before dispatch and after approval. No loaded-code or hardware proof.'],
];

export function LayerResponsibilities({ events, result }: { events: LabEvent[]; result?: LabResult | null }) {
  return <section className="product-card p-5"><h2 className="text-base font-semibold text-white">What each security layer did</h2><p className="mt-2 text-xs leading-6 text-slate-400">Responsibilities run at relevant lifecycle points and can repeat per action. No event means no claim of a pass. Open a layer to inspect its recorded checks.</p><div className="mt-4 space-y-2">{responsibilities.map(([id, name, question, rule]) => {
    const checks = events.filter(event => event.layer === id && event.type === 'layer_completed');
    const actual = result?.layers?.find(layer => layer.id === id);
    const latest = checks.at(-1);
    const decision = latest ? String(latest.data.decision) : actual?.decision ?? 'Not reached';
    return <details key={id} className="rounded-xl border border-white/10 p-3"><summary className="cursor-pointer text-sm text-slate-100">{id} · {name}<span className={`float-right text-xs ${['DENY', 'STOP'].includes(decision) ? 'text-rose-300' : 'text-cyan-200'}`}>{decision}</span></summary><p className="mt-3 text-sm text-slate-200">{question}</p><p className="mt-2 text-xs leading-6 text-slate-400">{rule}</p>{checks.length ? <ol className="mt-3 space-y-3">{checks.map(event => <li key={event.sequence} className="rounded-lg bg-white/5 p-3 text-xs leading-6 text-slate-300"><p>{new Date(event.timestamp).toLocaleTimeString()} · {event.action_id ?? 'Run lifecycle'} · {String(event.data.decision)}</p><p className="text-cyan-200">{String(event.data.reason)}</p><p>{String(event.data.detail)}</p><p className="text-slate-400">Mode: {String(event.data.mode)}</p></li>)}</ol> : <p className="mt-3 text-xs text-slate-400">{actual?.detail || 'No checkpoint recorded. This layer was not reached or no applicable action occurred.'}</p>}</details>;
  })}</div><p className="mt-4 text-[11px] leading-5 text-slate-400">ETW supplies process observations when available. It does not enforce file/network permissions. Windows Job Objects are resource controls; the trusted tool code enforces document access.</p></section>;
}
