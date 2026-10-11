import { useState } from 'react';
import { runChallenge, type ChallengeAction, type ChallengeLayer, type ChallengeResult } from '../../api/pipeline';

const EXAMPLES: Record<ChallengeLayer, { name: string; payload: string; action: ChallengeAction }> = {
  L1: { name: 'Proposal grammar', payload: '{"tool":"sys_exec","arguments":{"command":"echo example"}}', action: 'read_file' },
  L2: { name: 'Task policy', payload: '.env', action: 'read_file' },
  L3: { name: 'Kernel event replay', payload: 'sys_open(/etc/shadow)', action: 'read_file' },
  L4: { name: 'Behavior replay', payload: 'read_config -> request_sudo -> access_kernel_mem', action: 'read_file' },
  L5: { name: 'Temporal risk replay', payload: 'login_fail -> retry -> sudo -> secret', action: 'read_file' },
  L6: { name: 'Evidence integrity', payload: 'modified audit event', action: 'read_file' },
  L7: { name: 'Hardware attestation', payload: 'quote mismatch', action: 'read_file' },
};
const LAYERS = Object.keys(EXAMPLES) as ChallengeLayer[];

export function ChallengeLab() {
  const [layer, setLayer] = useState<ChallengeLayer>('L2');
  const [payload, setPayload] = useState(EXAMPLES.L2.payload);
  const [action, setAction] = useState<ChallengeAction>('read_file');
  const [results, setResults] = useState<Partial<Record<ChallengeLayer, ChallengeResult>>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chooseLayer = (next: ChallengeLayer) => {
    setLayer(next);
    setPayload(EXAMPLES[next].payload);
    setAction(EXAMPLES[next].action);
    setError(null);
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await runChallenge(layer, payload, action);
      setResults(previous => ({ ...previous, [layer]: result }));
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : 'Challenge failed');
    } finally {
      setBusy(false);
    }
  };

  const runAll = async () => {
    setBusy(true);
    setError(null);
    try {
      for (const next of LAYERS) {
        const example = EXAMPLES[next];
        const result = await runChallenge(next, example.payload, example.action);
        setResults(previous => ({ ...previous, [next]: result }));
      }
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : 'Challenge failed');
    } finally {
      setBusy(false);
    }
  };

  const result = results[layer];
  return <section className="rounded-xl border border-blue-200 bg-white p-5 shadow-sm space-y-4" aria-label="Custom seven layer challenge lab">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h3 className="text-xl font-bold text-gray-900">Custom seven-layer challenge lab</h3>
        <p className="text-sm text-gray-600 mt-1">Edit any input and run its check. L2 uses the live gateway; L3–L5 are replay rules; L7 requires a TPM host.</p>
      </div>
      <button type="button" onClick={runAll} disabled={busy} className="rounded bg-blue-700 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">Run seven examples</button>
    </div>
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-7">
      {LAYERS.map(item => <button key={item} type="button" onClick={() => chooseLayer(item)} disabled={busy}
        className={`rounded border p-2 text-left text-sm ${layer === item ? 'border-blue-600 bg-blue-50 text-blue-900' : 'border-gray-200 text-gray-700'}`}>
        <span className="font-bold">{item}</span><span className="block text-xs">{EXAMPLES[item].name}</span>
      </button>)}
    </div>
    <div className="grid gap-3 md:grid-cols-[1fr_auto]">
      <label className="text-sm font-semibold text-gray-800">Challenge input
        <textarea aria-label="Challenge input" value={payload} onChange={event => setPayload(event.target.value)} maxLength={2000} rows={3}
          className="mt-1 block w-full rounded border border-gray-300 p-2 font-mono text-sm" />
      </label>
      {layer === 'L2' && <label className="text-sm font-semibold text-gray-800">Tool action
        <select aria-label="Tool action" value={action} onChange={event => setAction(event.target.value as ChallengeAction)}
          className="mt-1 block w-full rounded border border-gray-300 p-2 text-sm">
          <option value="read_file">read_file</option><option value="execute_command">execute_command</option><option value="http_post">http_post</option>
        </select>
      </label>}
    </div>
    <button type="button" onClick={submit} disabled={busy || !payload.trim()} className="rounded bg-gray-900 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">{busy ? 'Checking…' : `Run ${layer} check`}</button>
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
    {result && <div className="rounded border border-gray-200 bg-gray-50 p-4 text-sm" aria-live="polite">
      <div className="flex flex-wrap gap-2 items-center"><strong className="text-base">{result.layer}: {result.verdict}</strong><span className="rounded bg-white px-2 py-1 font-mono text-xs">{result.mode}</span><span className="font-mono text-xs">{result.reason_code}</span></div>
      <p className="mt-2 text-gray-800">{result.explanation}</p>
      <p className="mt-1 text-gray-600"><strong>Check:</strong> {result.rule}</p>
      {result.mode === 'LIVE_GATEWAY' && <p className="mt-1 text-gray-700">Tool executed: {result.executed ? 'yes' : 'no'} · HMAC audit: {result.audit_valid ? 'verified' : 'failed'} · signed receipt: {result.receipt_valid ? 'verified' : 'failed'} · run {result.run_id}</p>}
      {result.mode === 'LIVE_INTEGRITY_CHECK' && <p className="mt-1 text-gray-700">Tampered copy verified: {result.audit_valid ? 'yes' : 'no, integrity check rejected it'}</p>}
    </div>}
    <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead><tr className="border-b text-gray-500"><th className="p-2">Layer</th><th className="p-2">Result</th><th className="p-2">Proof level</th><th className="p-2">Why</th></tr></thead><tbody>{LAYERS.map(item => <tr key={item} className="border-b"><td className="p-2 font-bold">{item}</td><td className="p-2">{results[item]?.verdict ?? 'Not run'}</td><td className="p-2">{results[item]?.mode ?? '—'}</td><td className="p-2"><span className="font-mono">{results[item]?.reason_code ?? '—'}</span>{results[item] && <span className="mt-1 block text-gray-600">{results[item]?.explanation}</span>}</td></tr>)}</tbody></table></div>
  </section>;
}
