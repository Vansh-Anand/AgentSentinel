import React from 'react';
import type { PipelineRunResponse } from '../../types/api';
import { AVAILABLE_SCENARIOS } from '../../types/pipeline';
import { ShieldAlert, ShieldCheck, HelpCircle, AlertTriangle, ArrowDown } from 'lucide-react';

interface InterceptionDetailsProps {
  result: PipelineRunResponse;
  selectedLayerId: string;
}

const LAYER_NAMES: Record<string, string> = {
  'L1': 'Grammar-Constrained Decoding',
  'L2': 'Semantic Deobfuscation and Normalization',
  'L3': 'Kernel Execution Telemetry',
  'L4': 'Behavioral Divergence Detection',
  'L5': 'Temporal Risk Chain Correlation',
  'L6': 'Cryptographic Evidence Chain / ECES',
  'L7': 'Trusted Execution Environment Attestation'
};

export const InterceptionDetails: React.FC<InterceptionDetailsProps> = ({ result, selectedLayerId }) => {
  const scenario = AVAILABLE_SCENARIOS.find(s => s.id === result.scenario_id);
  if (!scenario) return null;

  const isBlocked = result.stopping_layer === selectedLayerId && result.overall_decision !== 'ALLOW';
  const isExpectedMatch = scenario.targetLayer === result.stopping_layer;
  const isAllow = result.overall_decision === 'ALLOW';

  // Determine state for header
  let stateTitle = '';
  let bgColor = 'bg-gray-900';
  let icon = <ShieldAlert className="w-5 h-5 text-white" />;

  if (isAllow) {
    stateTitle = `🟢 ALLOWED AT ${selectedLayerId}`;
    bgColor = 'bg-emerald-900';
    icon = <ShieldCheck className="w-5 h-5 text-emerald-400" />;
  } else if (result.overall_decision === 'FREEZE' && result.stopping_layer === selectedLayerId) {
    stateTitle = `🟠 FROZEN AT ${selectedLayerId}`;
    bgColor = 'bg-orange-900';
    icon = <AlertTriangle className="w-5 h-5 text-orange-400" />;
  } else if (isBlocked) {
    stateTitle = `🔴 BLOCKED AT ${selectedLayerId}`;
    bgColor = 'bg-red-900';
    icon = <ShieldAlert className="w-5 h-5 text-red-400" />;
  } else {
    // Just viewing a layer that didn't block
    const outcome = (result as any)[selectedLayerId];
    const passed = outcome?.decision === 'ALLOW' || outcome?.status === 'ALLOW' || outcome?.governance_state === 'ALLOW' || outcome?.chain_status === 'APPENDED' || outcome?.isolation_status === 'ISOLATED' || outcome?.drift_state === 'NORMAL';
    if (passed) {
      stateTitle = `🟢 PASSED ${selectedLayerId}`;
      bgColor = 'bg-emerald-900';
      icon = <ShieldCheck className="w-5 h-5 text-emerald-400" />;
    } else {
      stateTitle = `⚪ SKIPPED / UNAVAILABLE ${selectedLayerId}`;
      bgColor = 'bg-gray-800';
      icon = <HelpCircle className="w-5 h-5 text-gray-400" />;
    }
  }

  const renderL1Details = () => {
    const l1 = result.L1;
    if (!l1) return null;
    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Security Mechanism</h5>
          <p className="text-gray-200">Grammar-Constrained Decoding</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Decision</h5>
          <p className="text-gray-200">{l1.decision}</p>
        </div>
        {l1.metadata?.policy_violation && (
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Reason</h5>
            <p className="text-red-400">Policy violation detected before generation.</p>
          </div>
        )}
        {l1.metadata?.tool_name && (
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Forbidden action/tool</h5>
            <p className="text-gray-200 font-mono text-sm">{l1.metadata.tool_name}</p>
          </div>
        )}
      </div>
    );
  };

  const renderL2Details = () => {
    const l2 = result.L2;
    if (!l2) return null;
    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Original Payload</h5>
          <pre className="bg-gray-900 p-2 rounded text-gray-300 font-mono text-sm whitespace-pre-wrap">{scenario.attackPayload}</pre>
        </div>
        {l2.normalized_command && (
          <>
            <div className="flex justify-center text-gray-500 my-2">
              <div className="flex flex-col items-center">
                <ArrowDown className="w-4 h-4" />
                <span className="text-[10px] uppercase">Decode</span>
                <ArrowDown className="w-4 h-4" />
              </div>
            </div>
            <div>
              <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Normalized / Canonical</h5>
              <pre className="bg-gray-900 p-2 rounded text-gray-300 font-mono text-sm whitespace-pre-wrap">{l2.normalized_command}</pre>
            </div>
            <div className="flex justify-center text-gray-500 my-2">
              <div className="flex flex-col items-center">
                <ArrowDown className="w-4 h-4" />
                <span className="text-[10px] uppercase">Policy Check</span>
                <ArrowDown className="w-4 h-4" />
              </div>
            </div>
          </>
        )}
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Policy Decision</h5>
          <p className={l2.decision === 'BLOCK' ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>{l2.decision || 'UNKNOWN'}</p>
        </div>
        {l2.detection_reason && (
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Reason</h5>
            <p className="text-red-400">{l2.detection_reason}</p>
          </div>
        )}
      </div>
    );
  };

  const renderL3Details = () => {
    const l3 = result.L3;
    if (!l3) return null;
    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Execution Mode</h5>
          <p className="text-blue-400 font-semibold">{l3.execution_mode}</p>
          {l3.execution_mode === 'SIMULATED' && (
            <p className="text-xs text-gray-500 mt-1">SIMULATED — Native eBPF not active in this environment</p>
          )}
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Telemetry Source</h5>
          <p className="text-gray-200">{l3.execution_mode === 'SIMULATED' ? 'Replayed trace or Mock telemetry' : 'OS / Kernel Audit'}</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Events Analyzed</h5>
          <p className="text-gray-200">{l3.event_count || 0}</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Anomalies Detected</h5>
          <p className="text-gray-200">{l3.anomalies || 0}</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Decision</h5>
          <p className={l3.status === 'DETECTED' ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>{l3.status}</p>
        </div>
      </div>
    );
  };

  const renderL4Details = () => {
    const l4 = result.L4;
    if (!l4) return null;

    // Visualize score if it exists
    const score = l4.ensemble_score ?? 0;
    const maxScore = 100;
    const width = Math.min(100, Math.max(0, (score / maxScore) * 100));
    const normalWidth = 20;

    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Execution Mode</h5>
          <p className="text-blue-400 font-semibold">{l4.execution_mode}</p>
          {l4.execution_mode === 'SYNTHETIC' && (
            <p className="text-xs text-gray-500 mt-1">SYNTHETIC — Detector evaluated on synthetic/replayed data</p>
          )}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Isolation Forest</h5>
            <p className="text-gray-200">{l4.isolation_forest_score?.toFixed(2) || '—'}</p>
          </div>
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Siamese Network</h5>
            <p className="text-gray-200">{l4.siamese_score?.toFixed(2) || '—'}</p>
          </div>
        </div>

        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Ensemble Divergence Score</h5>
          <p className="text-gray-200 text-lg font-bold">{score.toFixed(2)}</p>
        </div>

        {score > 0 && (
          <div className="space-y-2 mt-4 bg-gray-900 p-3 rounded">
            <div>
              <div className="text-xs text-gray-400 mb-1 flex justify-between">
                <span>Normal behavior</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className="bg-emerald-500 h-2 rounded-full" style={{ width: `${normalWidth}%` }}></div>
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-400 mb-1 flex justify-between">
                <span>Observed behavior</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className={`h-2 rounded-full ${score > 50 ? 'bg-red-500' : 'bg-amber-500'}`} style={{ width: `${width}%` }}></div>
              </div>
            </div>
          </div>
        )}

        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Detection</h5>
          <p className={l4.drift_state !== 'NORMAL' ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>{l4.drift_state}</p>
        </div>
      </div>
    );
  };

  const renderL5Details = () => {
    const l5 = result.L5;
    if (!l5) return null;
    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Execution Mode</h5>
          <p className="text-blue-400 font-semibold">{l5.execution_mode || 'REAL_RUNTIME'}</p>
          {l5.execution_mode === 'SIMULATED' && (
            <p className="text-xs text-gray-500 mt-1">SIMULATED — Demonstration Heuristic applied to visualization</p>
          )}
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Bayesian Risk</h5>
          <p className="text-gray-200 text-lg font-bold">{(l5.bayesian_probability ? l5.bayesian_probability * 100 : 0).toFixed(1)}%</p>
        </div>

        {l5.execution_mode === 'SIMULATED' && (
          <>
            <div>
              <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Model</h5>
              <p className="text-gray-200">Demonstration Heuristic</p>
            </div>
            <div>
              <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Input Source</h5>
              <p className="text-gray-200">Simulated demonstration events</p>
            </div>
          </>
        )}

        {l5.highest_risk_path && (
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Chain</h5>
            <div className="bg-gray-900 p-3 rounded">
              <div className="flex flex-col items-center space-y-1">
                {l5.highest_risk_path.split('->').map((step, idx, arr) => (
                  <React.Fragment key={idx}>
                    <div className="text-gray-300 font-mono text-xs bg-gray-800 px-2 py-1 rounded w-full text-center">
                      {step.trim()}
                    </div>
                    {idx < arr.length - 1 && <ArrowDown className="w-3 h-3 text-gray-600" />}
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>
        )}

        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Governance Decision</h5>
          <p className={l5.governance_state === 'FREEZE' || l5.governance_state === 'BLOCK' ? 'text-orange-400 font-semibold' : 'text-emerald-400 font-semibold'}>{l5.governance_state}</p>
        </div>
      </div>
    );
  };

  const renderL6Details = () => {
    const l6 = result.L6;
    if (!l6) return null;
    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Execution Mode</h5>
          <p className="text-blue-400 font-semibold">REAL_RUNTIME</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Storage Backend</h5>
          <p className="text-gray-200">{l6.storage_backend}</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Evidence Hash / Reference</h5>
          <p className="text-gray-300 font-mono text-sm bg-gray-900 p-2 rounded break-all">{l6.evidence_chain_reference}</p>
        </div>

        <div className="bg-gray-900 p-4 rounded flex flex-col items-center text-xs font-mono text-gray-400 space-y-2 mt-4">
          <div className="border border-gray-700 p-2 rounded w-full text-center">Previous Hash</div>
          <ArrowDown className="w-4 h-4 text-gray-600" />
          <div className="border border-blue-900 bg-blue-950 text-blue-200 p-2 rounded w-full text-center">Current Record</div>
          <ArrowDown className="w-4 h-4 text-gray-600" />
          <div className="border border-emerald-900 bg-emerald-950 text-emerald-200 p-2 rounded w-full text-center">Current Hash</div>
        </div>

        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Chain Status</h5>
          <p className={l6.chain_status === 'TAMPERED' ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>{l6.chain_status}</p>
        </div>
      </div>
    );
  };

  const renderL7Details = () => {
    const l7 = result.L7;
    if (!l7) return null;
    return (
      <div className="space-y-4">
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Execution Mode</h5>
          <p className="text-gray-400 font-semibold">UNAVAILABLE</p>
          <p className="text-xs text-gray-500 mt-1">Hardware attestation unavailable on this Windows environment.</p>
        </div>
        <div>
          <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Isolation Status</h5>
          <p className={l7.isolation_status === 'FAILED' ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>{l7.isolation_status}</p>
        </div>
        {l7.scope_information && (
          <div>
            <h5 className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Scope Information</h5>
            <p className="text-gray-200">{l7.scope_information}</p>
          </div>
        )}
      </div>
    );
  };

  const getWhyBlockedReason = () => {
    if (result.stopping_layer !== selectedLayerId) return null;
    if (result.overall_decision === 'ALLOW') return null;

    switch (selectedLayerId) {
      case 'L1': return "Grammar/policy constraints rejected the requested action before it could proceed.";
      case 'L2': return "The command was normalized from an obfuscated representation to a restricted command and rejected by shell policy.";
      case 'L3': return result.L3?.execution_mode === 'SIMULATED'
        ? "Simulated kernel telemetry matched the restricted syscall/resource access pattern."
        : "Native kernel telemetry identified the restricted syscall/resource access pattern.";
      case 'L4': return result.L4?.execution_mode === 'SYNTHETIC'
        ? "The synthetic observed action sequence diverged from the learned behavioral baseline."
        : "The observed runtime action sequence diverged from the learned behavioral baseline.";
      case 'L5': return result.L5?.execution_mode === 'SIMULATED'
        ? "The simulated temporal sequence produced excessive risk and triggered the governance decision."
        : "The temporal sequence produced excessive risk and triggered the governance decision.";
      case 'L6': return "The cryptographic evidence chain detected a hash mismatch, indicating evidence tampering.";
      case 'L7': return "System integrity/attestation validation did not satisfy the trusted execution requirement.";
      default: return null;
    }
  };

  return (
    <div className="bg-gray-950 border border-gray-800 rounded-lg shadow-xl overflow-hidden text-sm xl:h-full flex flex-col">
      <div className={`${bgColor} px-4 py-3 flex items-center space-x-3 border-b border-gray-800`}>
        {icon}
        <div>
          <h3 className="text-white font-bold tracking-wider">{stateTitle}</h3>
          <p className="text-gray-300 text-xs">{LAYER_NAMES[selectedLayerId]}</p>
        </div>
      </div>

      <div className="p-5 space-y-8 flex-1">
        {selectedLayerId === result.stopping_layer && (
          <div className="flex items-center space-x-2">
            {isExpectedMatch ? (
              <span className="text-emerald-400 text-xs font-semibold flex items-center">
                <ShieldCheck className="w-4 h-4 mr-1" /> ✓ Expected interception confirmed
              </span>
            ) : (
              <span className="text-amber-400 text-xs font-semibold flex items-center">
                <AlertTriangle className="w-4 h-4 mr-1" /> ⚠ Observed path differs from expected ({scenario.targetLayer} expected)
              </span>
            )}
          </div>
        )}

        <div className="bg-gray-900/50 p-4 rounded-lg border border-gray-800">
          {selectedLayerId === 'L1' && renderL1Details()}
          {selectedLayerId === 'L2' && renderL2Details()}
          {selectedLayerId === 'L3' && renderL3Details()}
          {selectedLayerId === 'L4' && renderL4Details()}
          {selectedLayerId === 'L5' && renderL5Details()}
          {selectedLayerId === 'L6' && renderL6Details()}
          {selectedLayerId === 'L7' && renderL7Details()}
        </div>

        {getWhyBlockedReason() && (
          <div>
            <h4 className="text-sm font-bold text-gray-200 mb-2 border-b border-gray-800 pb-2">WHY WAS IT BLOCKED?</h4>
            <p className="text-gray-400 italic">"{getWhyBlockedReason()}"</p>
          </div>
        )}

        <div className="mt-auto pt-4">
          <h4 className="text-sm font-bold text-gray-200 mb-3 border-b border-gray-800 pb-2">FORENSIC SUMMARY</h4>
          <div className="grid grid-cols-2 gap-y-3 gap-x-4 text-xs">
            <div>
              <span className="text-gray-500 block">Session ID</span>
              <span className="text-gray-300 font-mono break-all">{result.session_id}</span>
            </div>
            <div>
              <span className="text-gray-500 block">Verdict</span>
              <span className={result.overall_decision === 'ALLOW' ? 'text-emerald-400' : 'text-red-400'}>{result.overall_decision}</span>
            </div>
            <div>
              <span className="text-gray-500 block">Stopping Layer</span>
              <span className="text-gray-300">{result.stopping_layer}</span>
            </div>
            <div>
              <span className="text-gray-500 block">Total Latency</span>
              <span className="text-gray-300">{result.total_latency_ns ? `${(result.total_latency_ns / 1_000_000).toFixed(2)} ms` : '—'}</span>
            </div>
            <div className="col-span-2">
              <span className="text-gray-500 block">Evidence ID / Hash (L6)</span>
              <span className="text-gray-300 font-mono break-all">{result.L6?.evidence_chain_reference || '—'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
