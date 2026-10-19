import { afterEach, describe, expect, it, vi } from 'vitest';
import { streamRuntimeRun, type LiveEvent } from '../api/runtimeStream';

afterEach(() => vi.unstubAllGlobals());

describe('live runtime event reader', () => {
  it('delivers split event frames in order and requires a terminal result', async () => {
    const encoder = new TextEncoder();
    const chunks = [
      'event: run_started\ndata: {"sequence":1,"at":"2026-10-13T00:00:00Z","data":{"provider":"fixture"}}\n',
      '\nevent: policy_decision\ndata: {"sequence":2,"at":"2026-10-13T00:00:01Z","data":{"decision":"DENY","executed":false}}\n\n',
      'event: run_completed\ndata: {"sequence":3,"at":"2026-10-13T00:00:02Z","data":{"result":{"run_id":"test"}}}\n\n',
    ];
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({
      start(controller) {
        chunks.forEach(chunk => controller.enqueue(encoder.encode(chunk)));
        controller.close();
      },
    }), { status: 200 })));
    const received: LiveEvent[] = [];
    await streamRuntimeRun({ task: 'Inspect README', readme_text: '# Synthetic', provider: 'fixture' },
      event => received.push(event));
    expect(received.map(event => event.event)).toEqual(['run_started', 'policy_decision', 'run_completed']);
    expect(received[1].data.executed).toBe(false);
  });

  it('rejects a stream that ends without a signed terminal result', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({
      start(controller) { controller.close(); },
    }), { status: 200 })));
    await expect(streamRuntimeRun({ task: 'Inspect README', readme_text: '# Synthetic', provider: 'fixture' },
      () => {})).rejects.toThrow('ended before a signed result');
  });
});
