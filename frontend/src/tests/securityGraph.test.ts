import { describe, expect, it } from 'vitest';
import { deriveLayers } from '../components/lab/SecurityGraph';
import type { LabEvent, LabResult } from '../api/secureLab';

describe('portable layer graph evidence boundaries', () => {
  it('keeps unreached layers neutral when a prompt is denied early', () => {
    const event: LabEvent = { schema_version: 2, run_id: 'test', sequence: 1, timestamp: '', elapsed_ms: 0,
      type: 'layer_completed', layer: 'L1', data: { decision: 'DENY', reason: 'INPUT_RULE', detail: 'Explicit rule' } };
    const layers = deriveLayers([event]);
    expect(layers.find(layer => layer.id === 'L1')?.decision).toBe('DENY');
    expect(layers.find(layer => layer.id === 'L3')?.decision).toBeNull();
    expect(layers.find(layer => layer.id === 'L7')?.decision).toBeNull();
  });
  it('uses authoritative terminal states instead of inventing passes', () => {
    const result = { layers: [{ id: 'L3', name: 'Bounded execution', state: 'NOT_REACHED', decision: null,
      reason: 'NOT_REACHED', mode: 'LIVE_APPLICATION', detail: '' }] } as LabResult;
    expect(deriveLayers([], result)[0].state).toBe('NOT_REACHED');
    expect(deriveLayers([], result)[0].decision).toBeNull();
  });
  it('does not show a prior allowed read as execution of the denied latest proposal', () => {
    const proposal: LabEvent = { schema_version: 2, run_id: 'test', sequence: 9, timestamp: '', elapsed_ms: 0,
      type: 'tool_proposed', layer: 'L1', data: { request_id: 'denied' } };
    const result = { enforcing_layer: 'L2', layers: [{ id: 'L3', name: 'Bounded execution', state: 'COMPLETED',
      decision: 'ALLOW', reason: 'PRIOR_READ_COMPLETED', mode: 'LIVE_APPLICATION', detail: 'Prior README read' }] } as LabResult;
    expect(deriveLayers([proposal], result)[0]).toMatchObject({ state: 'NOT_REACHED', decision: null,
      reason: 'LATEST_PROPOSAL_NOT_DISPATCHED' });
  });
});
