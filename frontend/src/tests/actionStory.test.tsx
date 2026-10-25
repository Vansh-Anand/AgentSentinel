import { describe, expect, it } from 'vitest';
import { actionStory } from '../components/lab/ActionStory';
import type { LabEvent, LabResult } from '../api/secureLab';

function event(sequence: number, type: string, data: Record<string, unknown> = {}, action = 'a'): LabEvent {
  return { sequence, type, data, action_id: action, layer: 'L2', schema_version: 2, run_id: 'run', timestamp: '', elapsed_ms: sequence };
}
function result(steps: LabResult['steps'] = []): LabResult {
  return { run_id: 'run', status: 'COMPLETED', reason: 'TASK_FINISHED', enforcing_layer: null, answer: '', provider: 'fixture', steps };
}
describe('Recorded action story', () => {
  it('does not turn a model refusal into an interception or execution', () => {
    const story = actionStory([event(1, 'run_started')], result());
    expect(story[1].state).toBe('waiting');
    expect(story[2].state).toBe('waiting');
    expect(story[3].detail).toBe('No execution receipt');
  });
  it('shows a denied action with no execution and no invented downstream pass', () => {
    const story = actionStory([event(1, 'tool_proposed', { tool: 'read_file' }), event(2, 'layer_completed', { decision: 'DENY', reason: 'PATH_OUT_OF_SCOPE' })], result([{ request_id: 'a', tool: 'read_file', arguments: { path: '.env' }, decision: 'DENY', reason: 'PATH_OUT_OF_SCOPE', executor_invoked: false, completed: false, effects: [] }]));
    expect(story[2].state).toBe('blocked');
    expect(story[3]).toMatchObject({ state: 'waiting', detail: 'Executor not invoked' });
    expect(story[4].state).toBe('waiting');
  });
  it('does not reuse an earlier action’s execution or denial for the latest action', () => {
    const story = actionStory([event(1, 'tool_proposed', { tool: 'read_file' }), event(2, 'execution_finished', { executor_invoked: true, completed: true }), event(3, 'tool_proposed', { tool: 'create_ticket' }, 'b')], undefined, true);
    expect(story[1].detail).toBe('create_ticket');
    expect(story[3].state).toBe('waiting');
  });
  it('distinguishes execution start from completion', () => {
    const story = actionStory([event(1, 'tool_proposed', { tool: 'calculate' }), event(2, 'execution_finished', { executor_invoked: true, completed: false })]);
    expect(story[3]).toMatchObject({ state: 'blocked', detail: 'Started; operation incomplete' });
  });
  it('shows a later schema rejection without borrowing an earlier successful proposal', () => {
    const story = actionStory([event(1, 'tool_proposed', { tool: 'read_file' }), event(2, 'execution_finished', { executor_invoked: true, completed: true }), event(3, 'layer_completed', { decision: 'DENY', reason: 'INVALID_PROPOSAL_SCHEMA' }, 'b')]);
    expect(story[1].detail).toBe('No proposal recorded');
    expect(story[2].state).toBe('blocked');
    expect(story[3].detail).toBe('No execution receipt');
  });
});
