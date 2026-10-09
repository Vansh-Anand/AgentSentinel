import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ExecutionModeBadge } from '../components/common/ExecutionModeBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { ExecutionMode } from '../types/api';
import App from '../App';

describe('App Foundation Tests', () => {
  it('renders ExecutionModeBadge correctly', () => {
    const { rerender } = render(<ExecutionModeBadge mode={ExecutionMode.REAL_RUNTIME} />);
    expect(screen.getByText('REAL RUNTIME')).toBeInTheDocument();

    rerender(<ExecutionModeBadge mode={ExecutionMode.SIMULATED} />);
    expect(screen.getByText('SIMULATED (Demonstration)')).toBeInTheDocument();
  });

  it('renders StatusBadge correctly', () => {
    const { rerender } = render(<StatusBadge status="ALLOW" />);
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
    
    rerender(<StatusBadge status="BLOCK" />);
    expect(screen.getByText('BLOCK')).toBeInTheDocument();
    
    rerender(<StatusBadge status={null} />);
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
  });

  it('renders application shell navigation', () => {
    render(<App />);
    expect(screen.getByText('AgentSentinel')).toBeInTheDocument();
    expect(screen.getAllByText('Overview').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Security Pipeline').length).toBeGreaterThan(0);
  });
});
