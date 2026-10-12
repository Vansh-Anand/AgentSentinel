import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { EvidencePage } from '../pages/EvidencePage';
import { ExecutionMode } from '../types/api';
import * as evidenceApi from '../api/evidence';

vi.mock('../api/evidence', () => ({
  getEvidenceSessions: vi.fn(),
  getSessionChain: vi.fn(),
  verifySession: vi.fn(),
}));

describe('EvidencePage Tests', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders No Session Selected initially and displays session list', async () => {
    vi.mocked(evidenceApi.getEvidenceSessions).mockResolvedValue({
      sessions: [
        { session_id: 'sess-1', event_count: 5, start_time_ns: 1000000000000, execution_mode: ExecutionMode.REAL_RUNTIME }
      ]
    });

    render(<EvidencePage />);
    
    expect(screen.getByText('ECES Evidence Chain Inspector')).toBeInTheDocument();
    
    await waitFor(() => {
      expect(screen.getByText('sess-1')).toBeInTheDocument();
    });
    
    expect(screen.getByText('No Session Selected')).toBeInTheDocument();
  });

  it('handles empty sessions safely without error banner', async () => {
    vi.mocked(evidenceApi.getEvidenceSessions).mockResolvedValue({ sessions: [] });

    render(<EvidencePage />);
    
    await waitFor(() => {
      expect(screen.getByText('No evidence sessions yet. Run an attack scenario in the Security Pipeline to generate cryptographic evidence chains.')).toBeInTheDocument();
      expect(screen.queryByText('Failed to load sessions')).not.toBeInTheDocument();
    });
  });

  it('handles 404 as expected empty state without error banner', async () => {
    const err = new Error('Not Found');
    (err as any).response = { status: 404, data: { detail: 'Not Found' } };
    
    // In our component, we mocked evidenceApi.getEvidenceSessions. 
    // Wait, the component calls useEvidence which calls getEvidenceSessions.
    // So we reject getEvidenceSessions with 404.
    vi.mocked(evidenceApi.getEvidenceSessions).mockRejectedValue(err);

    render(<EvidencePage />);
    
    await waitFor(() => {
      expect(screen.getByText('No evidence sessions yet. Run an attack scenario in the Security Pipeline to generate cryptographic evidence chains.')).toBeInTheDocument();
      expect(screen.queryByText('Failed to load sessions')).not.toBeInTheDocument();
    });
  });

  it('displays error banner for genuine failures (500)', async () => {
    const err = new Error('Internal Server Error');
    (err as any).response = { status: 500, data: { detail: 'Internal Server Error' } };
    vi.mocked(evidenceApi.getEvidenceSessions).mockRejectedValue(err);

    render(<EvidencePage />);
    
    await waitFor(() => {
      expect(screen.getByText('Failed to load sessions')).toBeInTheDocument();
      expect(screen.getByText('Internal Server Error')).toBeInTheDocument();
    });
  });

  it('loads evidence chain on session select and displays timeline', async () => {
    vi.mocked(evidenceApi.getEvidenceSessions).mockResolvedValue({
      sessions: [
        { session_id: 'sess-1', event_count: 2, start_time_ns: 1000000000000, execution_mode: ExecutionMode.REAL_RUNTIME }
      ]
    });

    const mockChain = {
      session_id: 'sess-1',
      execution_mode: ExecutionMode.REAL_RUNTIME,
      chain: [
        {
          sequence_number: 1,
          timestamp_ns: 1000000000000,
          event_type: 'TOOL_INVOCATION',
          source_layer: 'L1',
          event_id: 'evt-1',
          previous_hash: 'genesis-hash-1234',
          event_hash: 'event-hash-5678',
          payload: { action: 'read_file' }
        },
        {
          sequence_number: 2,
          timestamp_ns: 2000000000000,
          event_type: 'DECISION',
          source_layer: 'L5',
          event_id: 'evt-2',
          previous_hash: 'event-hash-5678',
          event_hash: 'event-hash-9999',
          payload: { decision: 'ALLOW' }
        }
      ]
    };

    vi.mocked(evidenceApi.getSessionChain).mockResolvedValue(mockChain);

    render(<EvidencePage />);
    
    await waitFor(() => screen.getByText('sess-1'));
    fireEvent.click(screen.getByText('sess-1'));

    await waitFor(() => {
      expect(screen.queryByText('No Session Selected')).not.toBeInTheDocument();
      expect(screen.getByText('Hash Chain')).toBeInTheDocument();
      expect(screen.getByText('TOOL_INVOCATION')).toBeInTheDocument();
      expect(screen.getByText('DECISION')).toBeInTheDocument();
    });

    // Detail panel
    expect(screen.getByText('evt-1')).toBeInTheDocument();
    
    // Click second record
    fireEvent.click(screen.getByText('DECISION'));
    
    await waitFor(() => {
      expect(screen.getByText('evt-2')).toBeInTheDocument();
      expect(screen.getByText(/"decision": "ALLOW"/)).toBeInTheDocument();
    });
  });

  it('handles chain verification', async () => {
    vi.mocked(evidenceApi.getEvidenceSessions).mockResolvedValue({
      sessions: [
        { session_id: 'sess-1', event_count: 1, start_time_ns: 1000000000000, execution_mode: ExecutionMode.REAL_RUNTIME }
      ]
    });

    vi.mocked(evidenceApi.getSessionChain).mockResolvedValue({
      session_id: 'sess-1', execution_mode: ExecutionMode.REAL_RUNTIME, chain: []
    });

    vi.mocked(evidenceApi.verifySession).mockResolvedValue({
      session_id: 'sess-1',
      valid: true,
      records_checked: 5,
      execution_mode: ExecutionMode.REAL_RUNTIME
    });

    render(<EvidencePage />);
    
    await waitFor(() => screen.getByText('sess-1'));
    fireEvent.click(screen.getByText('sess-1'));

    await waitFor(() => screen.getByText('Verify Chain'));
    
    fireEvent.click(screen.getByText('Verify Chain'));

    await waitFor(() => {
      expect(screen.getByText('Chain Verified')).toBeInTheDocument();
      expect(screen.getByText(/Records Checked: 5/)).toBeInTheDocument();
    });
  });

  it('reports intact hash links without claiming unverified signatures are valid', async () => {
    vi.mocked(evidenceApi.getEvidenceSessions).mockResolvedValue({
      sessions: [{ session_id: 'replay-1', event_count: 1, start_time_ns: 1000000000000, execution_mode: ExecutionMode.SIMULATED }]
    });
    vi.mocked(evidenceApi.getSessionChain).mockResolvedValue({
      session_id: 'replay-1', execution_mode: ExecutionMode.SIMULATED, chain: []
    });
    vi.mocked(evidenceApi.verifySession).mockResolvedValue({
      session_id: 'replay-1', valid: false, hash_chain_valid: true,
      signature_status: 'UNVERIFIED_KEY_UNAVAILABLE', records_checked: 5,
      failure: 'SIGNATURE_KEY_UNAVAILABLE', execution_mode: ExecutionMode.SIMULATED
    });

    render(<EvidencePage />);
    await waitFor(() => screen.getByText('replay-1'));
    fireEvent.click(screen.getByText('replay-1'));
    fireEvent.click(screen.getByText('Verify Chain'));

    await waitFor(() => {
      expect(screen.getByText('Hash chain intact; signatures unverified')).toBeInTheDocument();
      expect(screen.queryByText('Chain Integrity Failure')).not.toBeInTheDocument();
    });
  });
});
