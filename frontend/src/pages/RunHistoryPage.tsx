import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowRight, Download, FileCheck2, RefreshCw } from 'lucide-react';
import { apiClient } from '../api/client';

type RunSummary = {
  run_id: string;
  updated_at: string;
  provider: string;
  outcome: 'BLOCKED' | 'NO_DENIAL' | 'NO_PROPOSAL';
  tool_calls: number;
  verified: boolean;
  audit_records: number;
};

type RunDetail = RunSummary & {
  steps: { request_id: string; tool_name: string; decision: string; reason_code: string; executed: boolean; effect_verdict: string }[];
  layers: { layer: string; name: string; mode: string }[];
  stop_reason: string;
  final_message_sha256: string;
};

export function RunHistoryPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get('run');
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  function refresh() {
    setLoading(true);
    setError('');
    apiClient.get<{ runs: RunSummary[] }>('/api/runtime/runs').then(response => setRuns(response.data.runs))
      .catch(() => setError('Recent gateway runs could not be loaded.'))
      .finally(() => setLoading(false));
  }

  useEffect(() => { refresh(); }, []);
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    apiClient.get<RunDetail>(`/api/runtime/runs/${encodeURIComponent(selectedId)}`)
      .then(response => { setDetail(response.data); setError(''); })
      .catch(() => { setDetail(null); setError('This run could not be opened or its evidence is incomplete.'); });
  }, [selectedId]);

  return <div className="space-y-6 pb-12">
    <header className="rounded-2xl bg-slate-950 p-7 text-white"><div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em] text-cyan-300"><FileCheck2 className="h-4 w-4" /> Signed run history</div><h1 className="mt-2 text-3xl font-bold">Gateway evidence</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">Open a past run to inspect its actual policy decisions and verification state. The model is not rerun when you open evidence.</p></header>
    <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-slate-600">Only completed signed runs appear here. Historical research sessions are separate.</p><button type="button" onClick={refresh} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-800"><RefreshCw className="h-4 w-4" /> Refresh</button></div>
    {error && <p role="alert" className="rounded-xl border border-rose-300 bg-rose-50 p-4 text-sm text-rose-900">{error}</p>}
    <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
      <section aria-label="Recent gateway runs" className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"><h2 className="px-1 text-lg font-bold text-slate-950">Recent runs</h2>
        {loading ? <p className="p-5 text-sm text-slate-500">Loading signed runs…</p> : runs.length === 0 ? <div className="p-5 text-sm text-slate-600">No completed runs yet. <Link to="/lab" className="font-semibold text-blue-700 underline">Run the Live Lab</Link> to create one.</div> : <div className="mt-3 space-y-2">{runs.map(run => <button key={run.run_id} type="button" onClick={() => setSearchParams({ run: run.run_id })} className={`w-full rounded-xl border p-3 text-left ${selectedId === run.run_id ? 'border-blue-500 bg-blue-50' : 'border-slate-200 hover:border-blue-300'}`}>
          <div className="flex flex-wrap items-center justify-between gap-2"><strong className="text-sm text-slate-950">{run.outcome === 'BLOCKED' ? 'Blocked proposal' : run.outcome === 'NO_DENIAL' ? 'No denial' : 'No proposal'}</strong><span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${run.verified ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}`}>{run.verified ? 'Verified' : 'Invalid'}</span></div>
          <p className="mt-1 text-xs text-slate-600">{run.provider} · {run.tool_calls} tool {run.tool_calls === 1 ? 'call' : 'calls'} · {new Date(run.updated_at).toLocaleString()}</p><p className="mt-1 truncate font-mono text-xs text-slate-500">{run.run_id}</p>
        </button>)}</div>}
      </section>
      <section aria-label="Selected run evidence" className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        {!selectedId ? <div className="py-12 text-center text-sm text-slate-500">Select a run to inspect its tool decisions and layer status.</div> : !detail ? <p className="py-12 text-center text-sm text-slate-500">Loading selected run…</p> : <div>
          <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-xl font-bold text-slate-950">{detail.outcome === 'BLOCKED' ? 'Blocked proposal' : 'No denied proposal'}</h2><p className="mt-1 break-all font-mono text-xs text-slate-500">{detail.run_id}</p></div><span className={`rounded-full px-3 py-1 text-xs font-bold ${detail.verified ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}`}>{detail.verified ? 'Audit and signature verified' : 'Verification failed'}</span></div>
          <p className="mt-3 text-sm text-slate-600">{detail.provider} · {detail.audit_records} authenticated records · {detail.stop_reason}</p>
          <h3 className="mt-6 text-sm font-bold uppercase tracking-wide text-slate-500">Tool decisions</h3><div className="mt-2 space-y-2">{detail.steps.length ? detail.steps.map(step => <div key={step.request_id} className={`rounded-xl border p-3 text-sm ${step.decision === 'DENY' ? 'border-rose-200 bg-rose-50' : 'border-emerald-200 bg-emerald-50'}`}><strong>{step.tool_name} · {step.decision}</strong><p className="mt-1 text-xs text-slate-700">{step.reason_code} · executor {step.executed ? 'invoked' : 'not invoked'} · effect {step.effect_verdict}</p></div>) : <p className="text-sm text-slate-500">No tool proposal was recorded.</p>}</div>
          <details className="mt-5 rounded-xl border border-slate-200 p-3"><summary className="cursor-pointer text-sm font-semibold text-slate-900">Seven-layer provenance</summary><div className="mt-3 grid gap-2 sm:grid-cols-2">{detail.layers.map(layer => <div key={layer.layer} className="rounded-lg bg-slate-50 p-2 text-xs"><strong>{layer.layer} · {layer.name}</strong><p className="mt-1 text-blue-800">{layer.mode}</p></div>)}</div></details>
          <p className="mt-4 text-xs text-slate-500">The final answer is bound by SHA-256 in the signed audit; its text is not stored in this public history view.</p>
          {detail.verified && <a href={`${apiClient.defaults.baseURL}/api/runtime/runs/${detail.run_id}/evidence.zip`} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-blue-700 px-4 py-2 text-sm font-bold text-white"><Download className="h-4 w-4" /> Download evidence ZIP</a>}
        </div>}
      </section>
    </div>
    <Link to="/evidence/research" className="inline-flex items-center gap-1 text-sm font-semibold text-blue-800">Open historical ECES research evidence <ArrowRight className="h-4 w-4" /></Link>
  </div>;
}
