import { describe, expect, it, vi } from 'vitest';
import { apiClient } from '../api/client';
import { getEvidenceSessions, getSessionChain, verifySession } from '../api/evidence';

vi.mock('../api/client', () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
}));

describe('ECES evidence API routes', () => {
  it('calls the registered /api/evidence endpoints', async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { sessions: [] } });
    vi.mocked(apiClient.post).mockResolvedValue({ data: { valid: false } });

    await getEvidenceSessions();
    await getSessionChain('session-1');
    await verifySession('session-1');

    expect(apiClient.get).toHaveBeenCalledWith('/api/evidence/sessions');
    expect(apiClient.get).toHaveBeenCalledWith('/api/evidence/session/session-1');
    expect(apiClient.post).toHaveBeenCalledWith('/api/evidence/session/session-1/verify');
  });
});
