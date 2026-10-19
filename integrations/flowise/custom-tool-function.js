// Paste this body into a Flowise Custom Tool JavaScript Function.
// Input Schema properties are `tool` and `arguments`; Flowise exposes them as
// $tool and $arguments. Static Flowise variables supply the local URL and a
// short-lived, tool-scoped bearer capability. Do not give Flowise a lab session.
const fetch = require('node-fetch');
const base = String($vars.agentSentinelUrl || 'http://127.0.0.1:8008').replace(/\/$/, '');
const capability = String($vars.agentSentinelCapability || '');
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base) || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(capability)) {
  return JSON.stringify({ error: 'Configure the local AgentSentinel URL and expiring capability.' });
}
let parsed;
try { parsed = JSON.parse(String($arguments)); }
catch { return JSON.stringify({ error: 'arguments must be a JSON object string' }); }
if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
  return JSON.stringify({ error: 'arguments must be a JSON object' });
}
const headers = { 'X-Lab-Capability': capability, 'Content-Type': 'application/json' };
const chat = String($flow.chatId || $flow.sessionId || 'local').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 24);
const stableArgs = JSON.stringify(Object.fromEntries(Object.keys(parsed).sort().map(key => [key, parsed[key]])));
const requestMaterial = `${String($tool)}:${stableArgs}`;
let hash = 2166136261;
for (let index = 0; index < requestMaterial.length; index++) {
  hash ^= requestMaterial.charCodeAt(index);
  hash = Math.imul(hash, 16777619);
}
// The server also binds this retry key to the full canonical request hash.
// Replaying the same action in one chat returns the original run/effect.
const retryId = `flowise-${chat}-${String($tool).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 18)}-${(hash >>> 0).toString(16)}`;
const started = await fetch(`${base}/api/lab/adapter/integration/action`, {
  method: 'POST', headers,
  body: JSON.stringify({ tool: String($tool), arguments: parsed,
    client_request_id: retryId.slice(0, 80) })
});
if (!started.ok) return JSON.stringify({ error: `Gateway admission failed: HTTP ${started.status}` });
const admission = await started.json();
let run;
for (let count = 0; count < 120; count++) {
  const response = await fetch(`${base}/api/lab/adapter/integration/runs/${admission.run_id}`, { headers });
  if (!response.ok) return JSON.stringify({ run_id: admission.run_id, error: `Run lookup failed: HTTP ${response.status}` });
  run = await response.json();
  if (['COMPLETED', 'BLOCKED', 'STOPPED', 'ERROR', 'CANCELLED'].includes(run.status)) break;
  await new Promise(resolve => setTimeout(resolve, 250));
}
if (!run || !['COMPLETED', 'BLOCKED', 'STOPPED', 'ERROR', 'CANCELLED'].includes(run.status)) {
  return JSON.stringify({ run_id: admission.run_id, error: 'The bounded wait expired; inspect this run in AgentSentinel.' });
}
const action = run.result?.steps?.find(step => step.request_id && step.request_id.endsWith(':1'))
  || run.result?.steps?.at(-1);
return JSON.stringify({ run_id: admission.run_id, request_id: action?.request_id || null,
  status: run.status, decision: action?.decision || null, reason: run.result?.reason || null,
  executor_invoked: action?.executor_invoked === true,
  output: action?.decision === 'ALLOW' && action?.completed === true ? run.result?.adapter_output || '' : null,
  signed_evidence_valid: run.result?.verification?.valid === true,
  detail: 'This tool executed only through the AgentSentinel gateway. No separate Flowise action ran.' });
