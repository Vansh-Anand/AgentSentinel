import { describe, expect, it } from 'vitest';
import { buildLayerFlow } from '../components/lab/LiveLayerFlow';
import type { LiveEvent, LiveEventName } from '../api/runtimeStream';

function event(name: LiveEventName, sequence: number, data: Record<string, unknown> = {}): LiveEvent {
  return { event: name, sequence, at: '2026-10-13T00:00:00Z', data };
}

describe('live layer flow', () => {
  it('does not claim evidence or hardware before the signed result arrives', () => {
    const stages = buildLayerFlow([
      event('tool_proposed', 1, { tool_name: 'read_file', source: 'fixture-replay' }),
      event('policy_decision', 2, { decision: 'DENY', reason_code: 'PATH_OUT_OF_SCOPE', executed: false }),
      event('effect_receipt', 3, { verdict: 'NOT_EXECUTED', telemetry_source: 'none' }),
    ]).layers;
    expect(stages[1]).toMatchObject({ status: '1 denied', tone: 'bad' });
    expect(stages[1].detail).toContain('executor not invoked');
    expect(stages[2]).toMatchObject({ status: 'No effect attempted', tone: 'active' });
    expect(stages[5].status).toBe('Waiting');
    expect(stages[6].status).toBe('Waiting');
  });

  it('marks L6 verified only from the terminal result and L7 as software measurement', () => {
    const stages = buildLayerFlow([
      event('tool_proposed', 1, { tool_name: 'read_file', source: 'ollama' }),
      event('policy_decision', 2, { decision: 'ALLOW', reason_code: 'TASK_POLICY_ALLOW', executed: true }),
      event('effect_receipt', 3, { verdict: 'INCOMPLETE', telemetry_source: 'none' }),
      event('risk_assessment', 4, { score: 50, action: 'REVIEW' }),
      event('run_completed', 5, { result: {
        audit_verification: { valid: true }, signed_receipt: { valid: true },
        layers: [{ layer: 'L7', mode: 'SOFTWARE_MEASUREMENT' }],
      } }),
    ]).layers;
    expect(stages[1].status).toBe('Allowed');
    expect(stages[2]).toMatchObject({ status: 'No native collector', tone: 'limited' });
    expect(stages[3].detail).toContain('no trained model');
    expect(stages[5].status).toBe('Verified');
    expect(stages[6]).toMatchObject({ status: 'Software measurement', tone: 'limited' });
    expect(stages[6].detail).toContain('no TPM quote');
  });
});
