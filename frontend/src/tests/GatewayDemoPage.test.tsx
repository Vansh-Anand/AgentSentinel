import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { GatewayDemoPage } from '../pages/GatewayDemoPage';
import { apiClient } from '../api/client';

vi.mock('../api/client', () => ({ apiClient: { defaults: { baseURL: 'http://127.0.0.1:8000' }, post: vi.fn(), get: vi.fn().mockResolvedValue({ data: { available: false } }) } }));

describe('Gateway demo truthfulness', () => {
  it('shows measured model outcomes with denominators and limits', async () => {
    vi.mocked(apiClient.get).mockResolvedValueOnce({ data: {
      available: true, model: ['gemini-3.5-flash-lite'], attack_cases: 25,
      attack_cases_with_denied_proposal: 5, attack_denied_proposals: 5,
      denied_proposals_executed: 0, benign_cases: 25, benign_completed: 25,
      provider_errors: 0, audit_chains_verified: 50, signed_receipts_verified: 50,
      source_hashes_match_current_checkout: true,
    } });
    render(<GatewayDemoPage />);
    const report = await screen.findByRole('region', { name: 'Measured model evaluation' });
    expect(report).toHaveTextContent('5/25');
    expect(report).toHaveTextContent('0/5');
    expect(report).toHaveTextContent('25/25');
    expect(report).toHaveTextContent('answer quality is not scored');
    expect(report).toHaveTextContent('source hashes matched at publication: yes');
  });
  it('labels the held-out answer assertion and signed final results', async () => {
    vi.mocked(apiClient.get).mockResolvedValueOnce({ data: {
      available: true, report_version: 'agentsentinel_model_eval_v3',
      model: ['gemini-3.5-flash-lite'], repeats: 1,
      attack_cases: 25, attack_cases_with_denied_proposal: 1,
      attack_denied_proposals: 1, denied_proposals_executed: 0,
      benign_cases: 25, benign_completed: 25, benign_task_success: 25,
      final_results_bound_to_audit: 50,
      provider_errors: 0, audit_chains_verified: 50, signed_receipts_verified: 50,
      source_hashes_match_current_checkout: true,
    } });
    render(<GatewayDemoPage />);
    const report = await screen.findByRole('region', { name: 'Measured model evaluation' });
    expect(report).toHaveTextContent('1/25');
    expect(report).toHaveTextContent('0/1');
    expect(report).toHaveTextContent('25/25');
    expect(report).toHaveTextContent('lexical task check');
    expect(report).toHaveTextContent('50 final answers bound to audits');
  });
  it('shows real gateway decisions and incomplete telemetry clearly', async () => {
    vi.mocked(apiClient.post).mockResolvedValueOnce({ data: {
      run_id: 'run-1', provider: 'fixture-replay', execution_mode: 'FIXTURE_REPLAY',
      stop_reason: 'FINISHED', final_message: 'Summary: The module validates session tokens. The out-of-scope request was denied.',
      audit_file: '.data/runtime-audit/run-1.jsonl',
      audit_verification: { valid: true, records_checked: 8 },
      signed_receipt: { valid: true, key_fingerprint_sha256: 'a'.repeat(64), public_key_hex: 'b'.repeat(64), receipt_file: 'receipt.json' },
      steps: [
        { request_id: 'r:0', tool_name: 'read_file', arguments_sha256: 'digest1',
          decision: 'ALLOW', reason_code: 'TASK_POLICY_ALLOW', executed: true,
          effectseal: { verdict: 'INCOMPLETE', reason_codes: ['TELEMETRY_INCOMPLETE'], observation_count: 0, telemetry_source: 'none' } },
        { request_id: 'r:1', tool_name: 'read_file', arguments_sha256: 'digest2',
          decision: 'DENY', reason_code: 'PATH_OUT_OF_SCOPE', executed: false,
          effectseal: { verdict: 'NOT_EXECUTED', reason_codes: [], observation_count: 0, telemetry_source: 'none' },
          risk: { score: 60, action: 'REVIEW', denied_calls: 1, incidents: 1, signals: ['PATH_OUT_OF_SCOPE'] } },
      ],
      layers: [
        { layer: 'L1', name: 'Proposal format', mode: 'FIXTURE_REPLAY', evidence: { provider: 'fixture-replay', gateway_proposals: 2 } },
        { layer: 'L2', name: 'Task policy', mode: 'REAL_RUNTIME', evidence: { allowed_executed: 1, denied: 1 } },
        { layer: 'L3', name: 'Native effects', mode: 'UNAVAILABLE', evidence: { reason: 'No native Linux collector attached to this run' } },
        { layer: 'L4', name: 'Behavior signal', mode: 'REAL_RULE_SIGNAL', evidence: { score: 60 } },
        { layer: 'L5', name: 'Risk governance', mode: 'REAL_RUNTIME', evidence: { action: 'REVIEW', incidents: 1 } },
        { layer: 'L6', name: 'Audit evidence', mode: 'LOCAL_HMAC_AND_ED25519', evidence: { algorithm: 'HMAC-SHA256 + Ed25519' } },
        { layer: 'L7', name: 'Runtime trust', mode: 'SOFTWARE_MEASUREMENT', evidence: { digest_sha256: 'abcdef' } },
      ],
    } });
    render(<GatewayDemoPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Run through gateway' }));
    await waitFor(() => expect(screen.getByText('PATH_OUT_OF_SCOPE')).toBeInTheDocument());
    expect(screen.getAllByText('FIXTURE_REPLAY')).toHaveLength(2);
    expect(screen.getByText('FINISHED')).toBeInTheDocument();
    expect(screen.getByText(/Summary: The module validates session tokens/)).toBeInTheDocument();
    expect(screen.getByText('INCOMPLETE')).toBeInTheDocument();
    expect(screen.getByText('NOT_EXECUTED')).toBeInTheDocument();
    expect(screen.getByText(/Audit chain:/)).toHaveTextContent('verified');
    expect(screen.getByText(/Ed25519 receipt:/)).toHaveTextContent('verified');
    expect(screen.getByRole('link', { name: 'Download public evidence ZIP' })).toHaveAttribute('href', 'http://127.0.0.1:8000/api/runtime/runs/run-1/evidence.zip');
    expect(screen.getByRole('region', { name: 'Seven-layer evidence report' })).toHaveTextContent('L3 · Native effects');
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText(/hardware attested: no/)).toBeInTheDocument();
    expect(screen.getByText(/Risk:/)).toHaveTextContent('REVIEW');
  });

  it('shows the real container attack outcome and telemetry gap', async () => {
    vi.mocked(apiClient.post).mockResolvedValueOnce({ data: {
      run_id: 'container-run', execution_mode: 'REAL_DOCKER_RESTRICTED',
      fixture: 'attack', decision: 'ALLOW', reason_code: 'TASK_POLICY_ALLOW',
      executed: true,
      output: 'secret read denied: FileNotFoundError\nnetwork attempt denied: OSError [Errno 101] Network is unreachable',
      error_type: null,
      effectseal: { verdict: 'INCOMPLETE', reason_codes: ['TELEMETRY_INCOMPLETE'], observation_count: 0, telemetry_source: 'none' },
      audit_verification: { valid: true, records_checked: 3 },
    } });
    render(<GatewayDemoPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Run attack fixture' }));
    await waitFor(() => expect(screen.getByText(/secret read denied: FileNotFoundError/)).toBeInTheDocument());
    expect(screen.getByText(/network attempt denied:/)).toBeInTheDocument();
    expect(screen.getByText(/EffectSeal:/)).toHaveTextContent('INCOMPLETE');
    expect(screen.getByText(/Audit chain:/)).toHaveTextContent('verified');
    expect(apiClient.post).toHaveBeenCalledWith('/api/runtime/container-demo', { attack: true }, { timeout: 60000 });
  });
});
