import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { OverviewPage } from '../pages/OverviewPage';
import { ExecutionMode } from '../types/api';

// Mock the custom hooks used by OverviewPage
vi.mock('../hooks/useSystemStatus', () => ({
  useSystemStatus: vi.fn()
}));
vi.mock('../hooks/useExperiments', () => ({
  useExperiments: vi.fn()
}));
vi.mock('../hooks/useEvidence', () => ({
  useEvidence: vi.fn()
}));

import { useSystemStatus } from '../hooks/useSystemStatus';
import { useExperiments } from '../hooks/useExperiments';
import { useEvidence } from '../hooks/useEvidence';

describe('OverviewPage Tests', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    
    vi.mocked(useSystemStatus).mockReturnValue({
      status: {
        backend_status: 'OPERATIONAL',
        database_status: 'OPERATIONAL',
        overall_description: 'Test mode.',
        layers: [
          { name: 'L1', operational_status: 'OPERATIONAL' },
          { name: 'L2', operational_status: 'OPERATIONAL' }
        ]
      },
      loading: false,
      error: null
    } as any);

    vi.mocked(useExperiments).mockReturnValue({
      experiments: [
        { experiment_id: 'EXP-1', title: 'Test Exp 1', status: 'COMPLETED' }
      ],
      loading: false,
      error: null
    } as any);
  });

  it('displays 0 sessions and Run a scenario to populate when sessions are empty, with no REAL RUNTIME badge', () => {
    vi.mocked(useEvidence).mockReturnValue({
      sessions: [],
      sessionsLoading: false,
      sessionsError: null
    } as any);

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    );

    // Should display 0 sessions
    const sessionsText = screen.getByText('0');
    expect(sessionsText).toBeInTheDocument();
    
    // Should display the note
    expect(screen.getByText('Run a scenario to populate')).toBeInTheDocument();

    // Should NOT display REAL RUNTIME for the database card (we check that the badge isn't there)
    // Wait, the status card for "Environment Constraints" still says REAL RUNTIME in the text, 
    // but the actual ExecutionModeBadge under "ECES Evidence" should not be there.
    // The ExecutionModeBadge renders exactly "REAL RUNTIME". Let's check how many times it's in the document.
    // Actually, to be safe we can just verify the badge isn't rendered inside the ECES Evidence section.
    const ecesCard = screen.getByText('ECES Evidence').parentElement?.parentElement;
    expect(ecesCard).not.toHaveTextContent('REAL RUNTIME');
  });

  it('displays the session execution mode when sessions are present', () => {
    vi.mocked(useEvidence).mockReturnValue({
      sessions: [
        { session_id: 's1', event_count: 1, start_time_ns: 123, execution_mode: ExecutionMode.SIMULATED }
      ],
      sessionsLoading: false,
      sessionsError: null
    } as any);

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>
    );

    // The card reflects the session mode, not just the database availability.
    const ecesCard = screen.getByText('ECES Evidence').parentElement?.parentElement;
    expect(ecesCard).toHaveTextContent('1');
    expect(ecesCard).toHaveTextContent('SIMULATED');
  });
});
