import { useState } from 'react';
import { ArrowRight, FileText, Fingerprint, ShieldAlert, Ticket } from 'lucide-react';
import type { LabProvenance } from '../../api/secureLab';

export function ProvenanceGraph({ data }: { data?: LabProvenance }) {
  const [selected, setSelected] = useState<string | null>(null);
  if (!data) return <p className="text-xs text-slate-500">This older run has no provenance graph.</p>;
  const artifact = data.artifacts.find(value => value.artifact_id === selected);
  const visibleSources = artifact
    ? data.sources.filter(source => artifact.source_ids.includes(source.source_id)) : data.sources;
  const restricted = (classification: string) => classification === 'RESTRICTED_SYNTHETIC';

  return <section aria-label="Source provenance" className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div><h3 className="text-sm font-bold text-slate-950">Source → artifact → destination</h3>
        <p className="mt-1 text-xs text-slate-500">Conservative run scope: every observed source may have influenced later artifacts.</p></div>
      <span className="rounded-full border border-slate-200 px-2 py-1 font-mono text-[10px] text-slate-500" title={data.sha256}>Graph {data.sha256.slice(0, 12)}</span>
    </div>
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
      <div className="space-y-2"><p className="text-[10px] font-extrabold uppercase tracking-widest text-cyan-800">Observed sources</p>
        {visibleSources.map(source => <div key={source.source_id}
          className={`rounded-xl border p-3 ${restricted(source.classification) ? 'border-rose-300 bg-rose-50' : 'border-slate-200 bg-slate-50'}`}>
          <div className="flex items-center gap-2"><FileText size={15} aria-hidden="true" /><strong className="break-all text-xs">{source.source_id}</strong></div>
          <p className="mt-1 text-xs text-slate-600">{source.path}</p><p className="mt-1 font-mono text-[10px] text-slate-500">{source.classification}</p>
          <p className="mt-1 flex items-center gap-1 font-mono text-[10px] text-slate-500" title={source.sha256}><Fingerprint size={11} />{source.sha256.slice(0, 12)}</p>
        </div>)}
        {!visibleSources.length && <p className="rounded-lg bg-slate-50 p-3 text-xs text-slate-500">No sources observed.</p>}
      </div>
      <div className="hidden items-center text-cyan-700 lg:flex"><ArrowRight size={22} aria-hidden="true" /></div>
      <div className="space-y-2"><p className="text-[10px] font-extrabold uppercase tracking-widest text-cyan-800">Derived artifacts</p>
        {data.artifacts.map(item => <button key={item.artifact_id} type="button" onClick={() => setSelected(current => current === item.artifact_id ? null : item.artifact_id)}
          aria-pressed={selected === item.artifact_id}
          className={`block w-full rounded-xl border p-3 text-left focus-visible:outline-2 focus-visible:outline-cyan-500 ${selected === item.artifact_id ? 'border-cyan-400 bg-cyan-50' : 'border-slate-200 bg-slate-50'}`}>
          <div className="flex items-center gap-2">{item.kind === 'ticket_created' ? <Ticket size={15} aria-hidden="true" /> : <FileText size={15} aria-hidden="true" />}<strong className="text-xs">{item.target}</strong></div>
          <p className="mt-1 text-[11px] text-slate-600">{item.artifact_id} · {item.source_ids.length} observed parent sources</p>
          <p className="mt-1 font-mono text-[10px] text-slate-500">{item.classification}</p>
        </button>)}
        {!data.artifacts.length && <p className="rounded-lg bg-slate-50 p-3 text-xs text-slate-500">No artifact was created.</p>}
      </div>
    </div>
    {data.exports.length > 0 && <div className="space-y-2"><p className="text-[10px] font-extrabold uppercase tracking-widest text-cyan-800">Destination decisions</p>
      {data.exports.map((value, index) => <div key={`${value.destination}-${index}`} className={`rounded-xl border p-3 ${value.decision === 'DENY' ? 'border-rose-300 bg-rose-50' : 'border-emerald-200 bg-emerald-50'}`}>
        <p className="flex items-center gap-2 text-xs font-bold">{value.decision === 'DENY' && <ShieldAlert size={15} aria-hidden="true" />}{value.decision}: {value.tool} → {value.destination}</p>
        <p className="mt-1 text-xs text-slate-600">{value.reason} · {value.classification} · {value.source_ids.length} observed sources</p>
      </div>)}</div>}
    <p className="text-[11px] text-slate-500">Source labels and hashes come from the server. This graph tracks observed sources conservatively; it does not prove which words the model used.</p>
  </section>;
}
