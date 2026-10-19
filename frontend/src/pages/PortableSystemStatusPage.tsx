import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { labRequest, type LabCapabilities } from '../api/secureLab';

const boundaries: Record<string, string> = {
  L1: 'Structured proposals and a narrow explicit input rule',
  L2: 'Server-owned tool and file permissions, plus synthetic output checks',
  L3: 'Bounded tools; this Windows demo runs authorized actions in a limited Job Object',
  L4: 'A defined repeated-action rule',
  L5: 'Tool and time budgets, cancellation, and request-bound approval',
  L6: 'Durable local audit, signed run evidence, and failure refusal',
  L7: 'Approved software source manifest checked before work',
};

export function PortableSystemStatusPage() {
  const [caps, setCaps] = useState<LabCapabilities | null>(null);
  const [error, setError] = useState('');
  useEffect(() => { labRequest<LabCapabilities>('/capabilities').then(setCaps).catch(cause => setError(cause.message)); }, []);
  return <div className="mx-auto max-w-5xl space-y-5 pb-12">
    <header><p className="text-xs font-bold uppercase tracking-widest text-cyan-700">Portable lab status</p>
      <h2 className="mt-2 text-2xl font-bold text-slate-950">What this deployment actually runs</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">These seven definitions are the same ones shown in the Playground. Research components have their own historical pages.</p></header>
    {error && <p role="alert" className="rounded-xl bg-rose-50 p-4 text-sm text-rose-800">{error}</p>}
    {!caps && !error && <p className="rounded-xl bg-white p-5 text-sm text-slate-500">Checking the local lab…</p>}
    {caps && <>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border bg-white p-4"><p className="text-xs text-slate-500">Source integrity</p><strong className={caps.integrity.valid ? 'text-emerald-700' : 'text-rose-700'}>{caps.integrity.valid ? 'Approved baseline ready' : caps.integrity.reason}</strong></div>
        <div className="rounded-xl border bg-white p-4"><p className="text-xs text-slate-500">AI providers</p><strong className="text-slate-900">Scripted · {caps.providers.ollama_available ? 'Ollama ready' : 'Ollama unavailable'} · {caps.providers.gemini_key_configured && caps.providers.gemini_sdk_installed ? 'Gemini ready' : 'Gemini unavailable'}</strong></div>
        <div className="rounded-xl border bg-white p-4"><p className="text-xs text-slate-500">L3 worker limits</p><strong className="text-slate-900">{caps.windows_job?.required && caps.windows_job.available ? 'Windows Job Object enabled' : caps.windows_job?.reason ?? 'Application tools'}</strong><p className="mt-1 text-xs text-slate-500">{caps.etw_process?.reason === 'ETW_BROKER_READY' ? 'Local ETW broker ready; each authorized action reports its actual process-event coverage.' : caps.etw_process?.available ? 'ETW tools installed; permission and event coverage are checked in each run.' : 'ETW process observation unavailable on this host.'}</p></div>
      </div>
      <section className="rounded-2xl border bg-white p-5"><h3 className="font-bold text-slate-950">Seven security responsibilities</h3>
        <div className="mt-4 grid gap-2 sm:grid-cols-2">{caps.layers.map(layer => <div key={layer.id} className="rounded-xl border border-slate-200 p-3"><p className="text-sm font-bold text-slate-950">{layer.id} · {layer.name}</p><p className="mt-1 text-xs leading-5 text-slate-600">{boundaries[layer.id]}</p></div>)}</div>
      </section>
      <section className="rounded-2xl border bg-slate-950 p-5 text-sm text-slate-200"><h3 className="font-bold text-white">Trust boundary</h3><p className="mt-2 leading-6">This site uses isolated demo data; scripted fixtures and live-model runs are labeled separately. Windows Job Objects limit worker resources and lifetime, while tool and file permissions come from the gateway. ETW provides partial process-event observation when the local broker is ready. L7 checks source files; TPM attestation requires a configured Linux host and trusted baseline.</p><p className="mt-2 text-xs text-slate-400">Issuer fingerprint: {caps.issuer_fingerprint ?? 'Unavailable'}</p></section>
    </>}
    <div className="flex flex-wrap gap-4 text-sm"><Link to="/lab" className="font-bold text-cyan-800 underline">Open Playground</Link><Link to="/research" className="font-bold text-slate-600 underline">Historical research</Link><Link to="/system/classic" className="font-bold text-slate-600 underline">Earlier architecture status</Link></div>
  </div>;
}
