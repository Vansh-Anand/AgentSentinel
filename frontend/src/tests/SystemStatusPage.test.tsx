import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SystemStatusPage } from '../pages/SystemStatusPage';
import { getSystemStatus } from '../api/status';
import { ExecutionMode } from '../types/api';

vi.mock('../api/status', () => ({
  getSystemStatus: vi.fn()
}));

const mockStatus = {
  api_version: "1.0.0",
  backend_status: "OPERATIONAL",
  database_status: "OPERATIONAL",
  overall_status: "PARTIALLY OPERATIONAL",
  overall_description: "Native Linux eBPF telemetry is not active.",
  infrastructure: [
    {
      name: "Dashboard API",
      status: "OPERATIONAL",
      execution_mode: ExecutionMode.REAL_RUNTIME,
      description: "Serving REST API."
    },
    {
      name: "Native Runtime Telemetry",
      status: "UNAVAILABLE",
      execution_mode: ExecutionMode.UNAVAILABLE,
      description: "Kernel probes"
    }
  ],
  layers: [
    {
      layer_id: "L1",
      name: "Grammar-Constrained Decoding",
      operational_status: "OPERATIONAL",
      execution_mode: ExecutionMode.REAL_RUNTIME,
      description: "Enforces strict schema.",
      capabilities: ["GCD", "Pushdown Automaton"],
      limitations: ["Constrained prompts only."]
    },
    {
      layer_id: "L3",
      name: "Runtime Telemetry",
      operational_status: "PARTIAL",
      execution_mode: ExecutionMode.SIMULATED,
      description: "Collects execution context.",
      capabilities: ["JSONL replay"],
      limitations: ["No native eBPF"]
    }
  ],
  capabilities: [
    {
      name: "Prompt Injection Defense",
      status: "Operational",
      validation_level: "Real LLM benchmark",
      execution_mode: ExecutionMode.BENCHMARK
    },
    {
      name: "Native eBPF",
      status: "Pending",
      validation_level: "Not validated",
      execution_mode: ExecutionMode.UNAVAILABLE
    }
  ]
};

describe('SystemStatusPage Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state initially', () => {
    vi.mocked(getSystemStatus).mockReturnValue(new Promise(() => {})); // Never resolves
    render(<SystemStatusPage />);
    expect(screen.getByText(/Querying architecture health/i)).toBeInTheDocument();
  });

  it('renders error state on API failure', async () => {
    vi.mocked(getSystemStatus).mockRejectedValue(new Error('Network Error'));
    render(<SystemStatusPage />);
    
    await waitFor(() => {
      expect(screen.getByText('System Status Unavailable')).toBeInTheDocument();
    });
  });

  it('renders overall status header and environment notice', async () => {
    vi.mocked(getSystemStatus).mockResolvedValue(mockStatus as any);
    render(<SystemStatusPage />);
    
    await waitFor(() => {
      expect(screen.getByText(/AcademIQ System Status/i)).toBeInTheDocument();
    });

    expect(screen.getByText('API v1.0.0')).toBeInTheDocument();
    expect(screen.getByText('PARTIALLY OPERATIONAL')).toBeInTheDocument();
    expect(screen.getByText(/Native Linux eBPF telemetry is not active/)).toBeInTheDocument();
  });

  it('renders infrastructure correctly and handles unavailable items', async () => {
    vi.mocked(getSystemStatus).mockResolvedValue(mockStatus as any);
    render(<SystemStatusPage />);
    
    await waitFor(() => {
      expect(screen.getByText('Dashboard API')).toBeInTheDocument();
    });
    
    expect(screen.getByText('Native Runtime Telemetry')).toBeInTheDocument();
    
    // In our mock, Dashboard API is OPERATIONAL, Telemetry is UNAVAILABLE. 
    // Both text contents will exist
    const opStatuses = screen.getAllByText('OPERATIONAL');
    expect(opStatuses.length).toBeGreaterThan(0);
    const unStatuses = screen.getAllByText('UNAVAILABLE');
    expect(unStatuses.length).toBeGreaterThan(0);
  });

  it('renders layer grid with correct execution modes', async () => {
    vi.mocked(getSystemStatus).mockResolvedValue(mockStatus as any);
    render(<SystemStatusPage />);
    
    await waitFor(() => {
      expect(screen.getByText('L1')).toBeInTheDocument();
    });
    
    expect(screen.getByText('Grammar-Constrained Decoding')).toBeInTheDocument();
    expect(screen.getByText('L3')).toBeInTheDocument();
    expect(screen.getByText('Runtime Telemetry')).toBeInTheDocument();
    
    // Check capabilities and limitations
    expect(screen.getByText('GCD')).toBeInTheDocument();
    expect(screen.getByText('No native eBPF')).toBeInTheDocument();

    // Check execution mode badges (these texts come from ExecutionModeBadge component)
    expect(screen.getAllByText('REAL RUNTIME').length).toBeGreaterThan(0);
    expect(screen.getAllByText('SIMULATED (Demonstration)').length).toBeGreaterThan(0);
  });

  it('renders capability matrix', async () => {
    vi.mocked(getSystemStatus).mockResolvedValue(mockStatus as any);
    render(<SystemStatusPage />);
    
    await waitFor(() => {
      expect(screen.getByText('SYNTHETIC / BENCHMARK')).toBeInTheDocument();
    });
    
    expect(screen.getByText('Prompt Injection Defense')).toBeInTheDocument();
    expect(screen.getByText('Native eBPF')).toBeInTheDocument();
    expect(screen.getByText('Real LLM benchmark')).toBeInTheDocument();
    expect(screen.getByText('BENCHMARK (Dataset)')).toBeInTheDocument();
  });
});
