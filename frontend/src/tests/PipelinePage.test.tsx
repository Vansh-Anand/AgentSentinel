import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { PipelinePage } from '../pages/PipelinePage';
import { ExecutionMode } from '../types/api';
import * as pipelineApi from '../api/pipeline';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../api/pipeline', () => ({
  runPipelineScenario: vi.fn(),
}));

describe('PipelinePage Tests', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  it('renders Pipeline Idle state initially', () => {
    render(<MemoryRouter><PipelinePage /></MemoryRouter>);
    expect(screen.getByText('Pipeline Idle')).toBeInTheDocument();
    expect(screen.getAllByText('AcademIQ Security Pipeline').length).toBeGreaterThan(0);
  });

  it('handles scenario selection and displays attack payload', () => {
    render(<MemoryRouter><PipelinePage /></MemoryRouter>);
    
    // Initial state: no payload or Execute button
    expect(screen.queryByText('Attack Payload')).not.toBeInTheDocument();
    expect(screen.queryByText('Execute Attack')).not.toBeInTheDocument();

    // Click to select
    fireEvent.click(screen.getByText('L3 Kernel Syscall Probe'));
    
    // Payload and Execute button appear
    expect(screen.getByText('Attack Payload')).toBeInTheDocument();
    expect(screen.getByText(/sys_open/)).toBeInTheDocument();
    expect(screen.getByText('Target Defense Layer')).toBeInTheDocument();
    expect(screen.getByText('Execute Attack')).toBeInTheDocument();

    // Pipeline should remain Idle since we didn't execute
    expect(screen.getByText('Pipeline Idle')).toBeInTheDocument();
  });

  it('handles reset functionality', () => {
    render(<MemoryRouter><PipelinePage /></MemoryRouter>);
    
    fireEvent.click(screen.getByText('L3 Kernel Syscall Probe'));
    expect(screen.getByText('Attack Payload')).toBeInTheDocument();

    // Click Reset
    fireEvent.click(screen.getByText('Reset'));

    // Payload should disappear
    expect(screen.queryByText('Attack Payload')).not.toBeInTheDocument();
  });

  it('handles scenario execution visualization with 600ms delays', async () => {
    const mockResponse = {
      session_id: 'test-session',
      scenario_id: 'L7_ATTESTATION',
      overall_decision: 'ALLOW',
      stopping_layer: 'L7',
      total_latency_ns: 1000000,
      L1: { decision: 'ALLOW', latency: 1000, metadata: { tool_name: 'read_file' } },
      L2: { decision: 'UNAVAILABLE', normalized_command: null, detection_reason: null, latency: null },
      L3: { status: 'MOCKED', event_count: 5, anomalies: 0, execution_mode: ExecutionMode.SIMULATED },
      L4: { isolation_forest_score: 0.1, siamese_score: 0.1, ensemble_score: 0.1, drift_state: 'NOMINAL', execution_mode: ExecutionMode.SIMULATED },
      L5: { bayesian_probability: 0.05, governance_state: 'ALLOW', highest_risk_path: 'N/A', cross_session_status: 'CLEAN' },
      L6: { evidence_chain_reference: 'chain-1', chain_status: 'APPENDED', storage_backend: 'SQLite' },
      L7: { isolation_status: 'ALLOW', scope_information: null }
    };

    let resolvePromise: (val: any) => void = () => {};
    const promise = new Promise((resolve) => { resolvePromise = resolve; });
    vi.mocked(pipelineApi.runPipelineScenario).mockReturnValue(promise as any);

    render(<MemoryRouter><PipelinePage /></MemoryRouter>);
    
    // Select
    fireEvent.click(screen.getByText('L7 Hardware Attestation Failure'));
    
    // Execute
    fireEvent.click(screen.getByText('Execute Attack'));
    
    // Expect the state to change from idle to executing
    expect(screen.queryByText('Pipeline Idle')).not.toBeInTheDocument();
    expect(screen.getAllByText('Processing...').length).toBeGreaterThan(0);

    await act(async () => {
      resolvePromise(mockResponse);
      await promise;
    });

    expect(screen.queryByText('Executing...')).not.toBeInTheDocument();
    expect(screen.getByText('Live Pipeline Execution')).toBeInTheDocument();
    
    act(() => {
      vi.advanceTimersByTime(6000);
    });

    expect(screen.getByText('Agent execution permitted')).toBeInTheDocument();
    
    // Check final verdict panel
    expect(screen.getByText('SECURITY DECISION')).toBeInTheDocument();
    expect(screen.getAllByText('ALLOW').length).toBeGreaterThan(0);
    expect(screen.getByText('No malicious intent or policy violations detected across the pipeline.')).toBeInTheDocument();
  });
  
  it('handles blocked result and sets remaining layers to skipped', async () => {
    const mockResponse = {
      session_id: 'test-session',
      scenario_id: 'L2_BACKSLASH',
      overall_decision: 'BLOCK',
      stopping_layer: 'L2',
      total_latency_ns: 2000000,
      L1: { decision: 'ALLOW', latency: 1000, metadata: { tool_name: 'bash' } },
      L2: { decision: 'BLOCK', normalized_command: 'cat /etc/passwd', detection_reason: 'SDN_OBFUSCATION_DETECTED', latency: 1000 },
      L3: undefined,
      L4: undefined,
      L5: undefined,
      L6: undefined,
      L7: undefined
    };

    let resolvePromise: (val: any) => void = () => {};
    const promise = new Promise((resolve) => { resolvePromise = resolve; });
    vi.mocked(pipelineApi.runPipelineScenario).mockReturnValue(promise as any);

    render(<MemoryRouter><PipelinePage /></MemoryRouter>);
    
    fireEvent.click(screen.getByText('L2 Backslash Obfuscation'));
    fireEvent.click(screen.getByText('Execute Attack'));
    
    expect(screen.getAllByText('Processing...').length).toBeGreaterThan(0);

    await act(async () => {
      resolvePromise(mockResponse);
      await promise;
    });

    expect(screen.getByText('Live Pipeline Execution')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(3000);
    });

    expect(screen.getByText('Execution blocked at L2')).toBeInTheDocument();
    
    // Check final verdict panel
    expect(screen.getByText('SECURITY DECISION')).toBeInTheDocument();
    expect(screen.getAllByText('BLOCK').length).toBeGreaterThan(0);
    expect(screen.getByText('Obfuscated command normalized and rejected by semantic policy.')).toBeInTheDocument();
  });
});
