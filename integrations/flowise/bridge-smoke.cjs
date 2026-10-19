// Runs the exact custom-tool body with Flowise-like variables against the local API.
// This validates the JavaScript bridge, not an installed Flowise canvas.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const body = fs.readFileSync(path.join(__dirname, 'custom-tool-function.js'), 'utf8');
const execute = new AsyncFunction('$vars', '$flow', '$tool', '$arguments', 'require', body);
const base = (process.env.AGENTSENTINEL_API_BASE_URL || 'http://127.0.0.1:8008').replace(/\/$/, '');

async function main() {
  const response = await fetch(`${base}/api/lab/session`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 200);
  const { token } = await response.json();
  const issued = await fetch(`${base}/api/lab/adapter/capabilities`, {
    method: 'POST', headers: { 'X-Lab-Session': token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'incident_analyst', lifetime_seconds: 300 })
  });
  assert.equal(issued.status, 200);
  const { token: capability } = await issued.json();
  const vars = { agentSentinelUrl: base, agentSentinelCapability: capability };
  const mockRequire = name => {
    assert.equal(name, 'node-fetch');
    return fetch;
  };
  const allowed = JSON.parse(await execute(vars, { chatId: 'bridge-allow' }, 'read_file',
    JSON.stringify({ path: 'README.md' }), mockRequire));
  const denied = JSON.parse(await execute(vars, { chatId: 'bridge-deny' }, 'read_file',
    JSON.stringify({ path: '.env' }), mockRequire));
  const repeated = JSON.parse(await execute(vars, { chatId: 'bridge-allow' }, 'read_file',
    JSON.stringify({ path: 'README.md' }), mockRequire));
  assert.equal(allowed.decision, 'ALLOW');
  assert.equal(allowed.executor_invoked, true);
  assert.ok(typeof allowed.output === 'string' && allowed.output.includes('Incident'));
  assert.equal(denied.decision, 'DENY');
  assert.equal(denied.reason, 'PATH_OUT_OF_SCOPE');
  assert.equal(denied.executor_invoked, false);
  assert.equal(denied.output, null);
  assert.equal(repeated.run_id, allowed.run_id);
  assert.equal(allowed.signed_evidence_valid, true);
  assert.equal(denied.signed_evidence_valid, true);
  console.log(JSON.stringify({ scope: 'FLOWISE_FUNCTION_SIMULATOR_NOT_CANVAS', allowed, denied }, null, 2));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
