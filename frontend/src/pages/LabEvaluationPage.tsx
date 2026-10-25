import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { labRequest } from '../api/secureLab';

type Report = { created_utc?: string; provider: string; cases: number; attack_cases: number; benign_cases: number;
  attack_assertions_passed: number; benign_assertions_passed: number; verified_exports: number;
  windows_job_runs?: number; etw_process_correlated_runs?: number;
  denied_executors_invoked: number; denied_proposals: number; provider_or_runtime_errors: number;
  latency_ms: { p50: number; p95: number }; dataset_sha256: string; source_manifest: string;
  limitations: string; rows: { id: string; kind?: string; status?: string; family: string; reason: string; assertion_passed: boolean }[] };
type LiveReport = { provider: string; model: string; dataset?: string; case_count: number; repeats_per_case: number;
  measurement: { trials: number; benign_trials: number; attacks_with_unauthorized_proposal: number;
    attacks_blocked_after_proposal: number; attacks_with_no_forbidden_proposal: number;
    attack_trials_inconclusive?: number;
    unauthorized_executions: number; benign_task_assertions_passed: number;
    provider_or_runtime_errors: number; verified_exports: number;
    descriptive_wilson_95?: { benign_task_assertion?: { lower: number; upper: number } | null;
      conditional_gateway_prevention?: { lower: number; upper: number } | null };
    end_to_end_latency_ms: { p50: number; p95: number } };
  limitations: string };

function Metric({ value, label }: { value: string; label: string }) {
  return <div className="rounded-xl bg-slate-50 p-4"><strong className="text-2xl text-slate-950">{value}</strong><p className="mt-2 text-xs text-slate-500">{label}</p></div>;
}

export function LabEvaluationPage() {
  const [report, setReport] = useState<Report | null>(null);
  const [liveReports, setLiveReports] = useState<LiveReport[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => { labRequest<{ available: boolean; report?: Report; live?: LiveReport; live_reports?: LiveReport[]; reason?: string }>('/evaluation')
    .then(value => { setReport(value.report ?? null); setLiveReports(value.live_reports ?? (value.live ? [value.live] : []));
      if (!value.available) setError(value.reason ?? 'No current evaluation available.'); })
    .catch(cause => setError(cause.message)).finally(() => setLoading(false)); }, []);
  return <div className="product-page sentinel-workbench space-y-5">
    <section className="product-card p-6 text-white"><p className="text-xs font-bold uppercase tracking-widest text-cyan-300">Measured evidence</p>
      <h2 className="mt-3 text-3xl font-bold">Security with measurable evidence</h2>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-300">Did authorized work finish? Did any denied action execute? These results are tied to the approved backend source baseline.</p></section>
    {loading && <p role="status" className="text-sm text-slate-400">Loading source-matched evaluation…</p>}
    {error && <p className="rounded-xl bg-amber-50 p-4 text-sm text-amber-900">{error}</p>}
    {!loading && !liveReports.length && <p className="product-card p-4 text-xs leading-6 text-slate-300">No live-model evaluation is displayed for this source baseline. Scripted checks below measure deterministic contracts; they do not establish real-world prompt-injection detection accuracy.</p>}
    {report && <section className="rounded-2xl border border-slate-200 bg-white p-6"><p className="text-[10px] font-bold tracking-wide text-slate-500">SCRIPTED CONTRACTS · {report.provider}</p>
      <h3 className="mt-2 text-xl font-bold">Deterministic gateway regression</h3>
      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric value={`${report.attack_assertions_passed}/${report.attack_cases}`} label="Attack contract assertions" />
        <Metric value={`${report.benign_assertions_passed}/${report.benign_cases}`} label="Useful benign assertions" />
        <Metric value={`${report.verified_exports}/${report.cases}`} label="Verified evidence exports" />
        <Metric value={`${report.denied_executors_invoked}/${report.denied_proposals}`} label="Denied proposals invoking executor" />
      </div><p className="mt-5 text-xs text-slate-600">End-to-end fixture latency: p50 {report.latency_ms.p50} ms · p95 {report.latency_ms.p95} ms · provider/runtime errors: {report.provider_or_runtime_errors}</p>{report.windows_job_runs !== undefined && <p className="mt-2 text-xs text-slate-600">Windows Job Object worker used: {report.windows_job_runs}/{report.cases} runs · ETW process correlation: {report.etw_process_correlated_runs ?? 0}/{report.cases}. Denied runs correctly start no worker.</p>}
      <p className="mt-3 text-xs leading-6 text-slate-400">{report.created_utc ? `Measured ${new Date(report.created_utc).toLocaleString()}. ` : ''}Benign checks include result assertions, not only ALLOW decisions. {report.rows.some(row => row.kind === 'benign') ? `Benign runs ending BLOCKED or STOPPED: ${report.rows.filter(row => row.kind === 'benign' && ['BLOCKED', 'STOPPED'].includes(row.status ?? '')).length}/${report.benign_cases}.` : ''} End-to-end latency includes tool work; isolated gateway overhead has not been measured.</p>
      <p className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-4 text-xs leading-6 text-amber-950">{report.limitations}</p>
      <details className="mt-4"><summary className="cursor-pointer text-xs font-bold text-slate-700">Source and dataset hashes</summary><p className="mt-2 break-all font-mono text-[10px] text-slate-500">Dataset: {report.dataset_sha256}<br />Source manifest: {report.source_manifest}</p></details>
      <details className="mt-4"><summary className="cursor-pointer text-xs font-bold text-slate-700">Inspect all {report.cases} case assertions</summary><div className="mt-3 max-h-96 space-y-2 overflow-y-auto">{report.rows.map(row => <div key={row.id} className="flex flex-wrap justify-between gap-2 rounded-lg bg-slate-50 p-3 text-xs"><span className="font-semibold">{row.id} · {row.family}</span><span>{row.reason} · {row.assertion_passed ? 'assertion passed' : 'assertion failed'}</span></div>)}</div></details>
    </section>}
    {liveReports.map(live => <section key={`${live.provider}-${live.model}`} className="rounded-2xl border border-slate-200 bg-white p-6"><p className="text-[10px] font-bold tracking-wide text-cyan-700">LIVE MODEL TRIALS · {live.provider} · {live.model}</p>
      <h3 className="mt-2 text-xl font-bold">Natural-language behavior</h3><p className="mt-1 text-xs text-slate-500">{live.case_count} synthetic cases × {live.repeats_per_case} repeat(s){live.dataset ? ` · ${live.dataset}` : ''}. A model refusal is separate from a gateway interception.</p>
      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><Metric value={live.measurement.attacks_with_unauthorized_proposal ? `${live.measurement.attacks_blocked_after_proposal}/${live.measurement.attacks_with_unauthorized_proposal}` : 'No proposals'} label="Forbidden proposals blocked" />
        <Metric value={String(live.measurement.attacks_with_no_forbidden_proposal)} label="Attacks with no forbidden proposal" />
        <Metric value={String(live.measurement.unauthorized_executions)} label="Unauthorized executions" />
        <Metric value={`${live.measurement.benign_task_assertions_passed}/${live.measurement.benign_trials}`} label="Useful task checks passed" /></div>
      <p className="mt-4 text-xs text-slate-600">Verified exports: {live.measurement.verified_exports}/{live.measurement.trials} · inconclusive attack trials: {live.measurement.attack_trials_inconclusive ?? 0} · provider/runtime errors: {live.measurement.provider_or_runtime_errors} · end-to-end p50 {live.measurement.end_to_end_latency_ms.p50} ms</p>
      {live.measurement.descriptive_wilson_95 && <p className="mt-2 text-xs text-slate-600">Descriptive 95% interval for useful task checks: {Math.round((live.measurement.descriptive_wilson_95.benign_task_assertion?.lower ?? 0) * 100)}–{Math.round((live.measurement.descriptive_wilson_95.benign_task_assertion?.upper ?? 1) * 100)}%. {live.measurement.descriptive_wilson_95.conditional_gateway_prevention ? `Conditional prevention interval: ${Math.round(live.measurement.descriptive_wilson_95.conditional_gateway_prevention.lower * 100)}–${Math.round(live.measurement.descriptive_wilson_95.conditional_gateway_prevention.upper * 100)}%.` : 'Conditional prevention is undefined when no forbidden proposal was observed.'}</p>}
      <p className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-4 text-xs leading-6 text-amber-950">{live.limitations}</p></section>)}
    <details className="product-card p-5 text-sm text-slate-300"><summary className="cursor-pointer font-semibold">Reproduce this evaluation</summary><p className="mt-3 text-xs leading-6">From the repository root, after reviewing and approving the current backend source baseline:</p><pre className="mt-3 overflow-x-auto rounded-xl bg-slate-950/60 p-3 text-xs">python scripts/evaluate_workspace.py --provider gemini --repeat 1 --windows-job</pre><p className="mt-3 text-xs leading-6">The corpus uses synthetic documents and repeated attack families. A live model that refuses an attack before proposing a tool is counted separately from a gateway interception. Inspect case assertions and source hashes before citing results.</p></details>
    <Link to="/research" className="inline-block text-sm font-semibold text-cyan-800 underline">Earlier research experiments and limitations</Link>
  </div>;
}
