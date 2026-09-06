import React from 'react';
import { PipelineLayerCard } from './PipelineLayerCard';
import { usePipelineExecution } from '../../hooks/usePipelineExecution';
import { ShieldAlert, ArrowDown, Loader2 } from 'lucide-react';
import { ExecutionModeBadge } from '../common/ExecutionModeBadge';

interface PipelineFlowProps {
  execution: ReturnType<typeof usePipelineExecution>;
}

export const PipelineFlow: React.FC<PipelineFlowProps> = ({ execution }) => {
  const { isRunning, layerStates, result, pendingResult, selectedLayerId, setSelectedLayerId } = execution;
  const activeResult = pendingResult || result;
  
  const isFetching = isRunning && !activeResult;
  const showInterceptBanner = result && result.overall_decision === 'BLOCK';
  const showFreezeBanner = result && result.overall_decision === 'FREEZE';
  const showAllowBanner = result && result.overall_decision === 'ALLOW';

  const formatLatency = (ns?: number) => ns ? `${(ns / 1_000_000).toFixed(2)} ms` : '— ms';

  const renderConnector = (_currentState: string, nextState: string) => {
    // If the next layer started processing or finished, the connector is active.
    // However, if the current layer blocked, we should just hide or mute the connector.
    const isActive = nextState !== 'PENDING';
    return (
      <div className="flex justify-center py-1 overflow-hidden">
        <ArrowDown className={`w-5 h-5 transition-all duration-500 transform ${isActive ? 'text-blue-400 translate-y-0 opacity-100' : 'text-gray-200 -translate-y-4 opacity-50'}`} />
      </div>
    );
  };

  if (isFetching) {
    return (
      <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 flex flex-col items-center justify-center text-center h-full min-h-[400px]">
        <Loader2 className="w-12 h-12 text-blue-500 animate-spin mb-4" />
        <h3 className="text-lg font-medium text-gray-900">Processing...</h3>
        <p className="mt-2 text-sm text-gray-500">Transmitting scenario payload to pipeline orchestration layer...</p>
      </div>
    );
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div className="flex justify-between items-center mb-6">
        <h3 className="text-lg font-semibold text-gray-900">Live Pipeline Execution</h3>
        {isRunning && <span className="text-sm font-medium text-blue-600 animate-pulse">Running simulation...</span>}
      </div>

      <div className="relative space-y-2">
        <PipelineLayerCard
          id="L1"
          name="Grammar-Constrained Decoding"
          state={layerStates.L1}
          executionMode={activeResult?.L1?.latency ? activeResult.L3?.execution_mode : undefined}
          details={activeResult?.L1?.metadata ? 
            <div className="space-y-1">
              <div><span className="font-semibold text-gray-700">Tool Evaluated:</span> {activeResult.L1.metadata.tool_name}</div>
              {activeResult.L1.metadata.policy_violation && <div><span className="font-semibold text-red-600 animate-pulse">Policy Violation Detected</span></div>}
              <div className="flex justify-between">
                <span className="font-semibold text-gray-700">Latency:</span>
                <span>{formatLatency(activeResult.L1.latency)}</span>
              </div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L1'); }}
          isSelected={selectedLayerId === 'L1'}
        />

        {renderConnector(layerStates.L1, layerStates.L2)}

        <PipelineLayerCard
          id="L2"
          name="Semantic Deobfuscation and Normalization"
          state={layerStates.L2}
          executionMode={activeResult?.L2?.latency ? activeResult.L3?.execution_mode : undefined}
          details={activeResult?.L2 ? 
            <div className="space-y-1">
              {activeResult.L2.normalized_command && <div><span className="font-semibold text-gray-700">Canonical:</span> <code className="bg-gray-100 px-1 rounded">{activeResult.L2.normalized_command}</code></div>}
              {activeResult.L2.detection_reason && <div><span className="font-semibold text-gray-700">Reason:</span> {activeResult.L2.detection_reason}</div>}
              <div className="flex justify-between">
                <span className="font-semibold text-gray-700">Latency:</span>
                <span>{formatLatency(activeResult.L2.latency)}</span>
              </div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L2'); }}
          isSelected={selectedLayerId === 'L2'}
        />

        {renderConnector(layerStates.L2, layerStates.L3)}

        <PipelineLayerCard
          id="L3"
          name="Kernel Execution Telemetry"
          state={layerStates.L3}
          executionMode={activeResult?.L3?.execution_mode}
          details={activeResult?.L3?.event_count !== undefined ? 
            <div className="space-y-1">
              <div><span className="font-semibold text-gray-700">Events Captured:</span> {activeResult.L3.event_count}</div>
              <div><span className="font-semibold text-gray-700">Anomalies Detected:</span> {activeResult.L3.anomalies}</div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L3'); }}
          isSelected={selectedLayerId === 'L3'}
        />

        {renderConnector(layerStates.L3, layerStates.L4)}

        <PipelineLayerCard
          id="L4"
          name="Behavioral Divergence Detection"
          state={layerStates.L4}
          executionMode={activeResult?.L4?.execution_mode}
          details={activeResult?.L4?.ensemble_score !== undefined ? 
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div><span className="font-semibold text-gray-700">IsoForest:</span> {activeResult.L4.isolation_forest_score?.toFixed(3)}</div>
              <div><span className="font-semibold text-gray-700">Siamese:</span> {activeResult.L4.siamese_score?.toFixed(3)}</div>
              <div className="col-span-2"><span className="font-semibold text-gray-700">Ensemble:</span> {activeResult.L4.ensemble_score?.toFixed(3)} ({activeResult.L4.drift_state})</div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L4'); }}
          isSelected={selectedLayerId === 'L4'}
        />

        {renderConnector(layerStates.L4, layerStates.L5)}

        <PipelineLayerCard
          id="L5"
          name="Temporal Risk Chain Correlation"
          state={layerStates.L5}
          executionMode={activeResult?.L4?.execution_mode}
          details={activeResult?.L5?.bayesian_probability !== undefined ? 
            <div className="space-y-1">
              <div><span className="font-semibold text-gray-700">Bayesian Risk:</span> {(activeResult.L5.bayesian_probability * 100).toFixed(1)}%</div>
              <div><span className="font-semibold text-gray-700">Cross-Session:</span> {activeResult.L5.cross_session_status}</div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L5'); }}
          isSelected={selectedLayerId === 'L5'}
        />

        {renderConnector(layerStates.L5, layerStates.L6)}

        <PipelineLayerCard
          id="L6"
          name="Cryptographic Evidence Chain / ECES"
          state={layerStates.L6}
          executionMode={activeResult?.L3?.execution_mode}
          details={activeResult?.L6?.evidence_chain_reference ? 
            <div className="space-y-1">
              <div><span className="font-semibold text-gray-700">Chain Ref:</span> <span className="font-mono text-xs">{activeResult.L6.evidence_chain_reference.substring(0, 16)}</span></div>
              <div><span className="font-semibold text-gray-700">Backend:</span> {activeResult.L6.storage_backend} ({activeResult.L6.chain_status})</div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L6'); }}
          isSelected={selectedLayerId === 'L6'}
        />

        {renderConnector(layerStates.L6, layerStates.L7)}

        <PipelineLayerCard
          id="L7"
          name="Trusted Execution Environment Attestation"
          state={layerStates.L7}
          executionMode={activeResult?.L3?.execution_mode}
          details={activeResult?.L7?.isolation_status ? 
            <div className="space-y-1">
              <div><span className="font-semibold text-gray-700">Status:</span> {activeResult.L7.isolation_status}</div>
            </div> : null
          }
          onClick={() => { if (!isRunning && result) setSelectedLayerId('L7'); }}
          isSelected={selectedLayerId === 'L7'}
        />

        {showInterceptBanner && !isRunning && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10 bg-white/60 backdrop-blur-[2px] rounded-lg">
            <div className="bg-red-900 border-4 border-red-500 shadow-2xl rounded-xl p-8 max-w-lg w-full transform -translate-y-12 pointer-events-auto text-center animate-in fade-in zoom-in duration-300">
              <div className="flex justify-center mb-4">
                <div className="bg-red-500 p-3 rounded-full animate-pulse">
                  <ShieldAlert className="w-12 h-12 text-white" />
                </div>
              </div>
              <h2 className="text-3xl font-black text-white tracking-widest mb-2 uppercase">Execution blocked at {result.stopping_layer}</h2>
              <div className="bg-red-950 p-4 rounded-lg border border-red-800 text-left space-y-2 mt-6">
                <div className="flex justify-between items-center border-b border-red-800 pb-2 pt-2">
                  <span className="text-red-300 text-sm uppercase tracking-wider font-semibold">Total Latency</span>
                  <span className="text-white font-mono">{formatLatency(result.total_latency_ns)}</span>
                </div>
                <div className="flex justify-between items-center pt-2">
                  <span className="text-red-300 text-sm uppercase tracking-wider font-semibold">Execution Mode</span>
                  <ExecutionModeBadge mode={result.L3?.execution_mode || result.L4?.execution_mode || 'UNAVAILABLE'} className="bg-red-800 text-white border-red-700" />
                </div>
              </div>
            </div>
          </div>
        )}

        {showFreezeBanner && !isRunning && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10 bg-white/60 backdrop-blur-[2px] rounded-lg">
            <div className="bg-orange-900 border-4 border-orange-500 shadow-2xl rounded-xl p-8 max-w-lg w-full transform -translate-y-12 pointer-events-auto text-center animate-in fade-in zoom-in duration-300">
              <div className="flex justify-center mb-4">
                <div className="bg-orange-500 p-3 rounded-full animate-pulse">
                  <ShieldAlert className="w-12 h-12 text-white" />
                </div>
              </div>
              <h2 className="text-2xl font-black text-white tracking-widest mb-2 uppercase">Agent frozen — multi-step attack detected</h2>
              <div className="bg-orange-950 p-4 rounded-lg border border-orange-800 text-left space-y-2 mt-6">
                <div className="flex justify-between items-center border-b border-orange-800 pb-2">
                  <span className="text-orange-300 text-sm uppercase tracking-wider font-semibold">Stopping Layer</span>
                  <span className="text-white font-bold text-lg">{result.stopping_layer}</span>
                </div>
                <div className="flex justify-between items-center border-b border-orange-800 pb-2 pt-2">
                  <span className="text-orange-300 text-sm uppercase tracking-wider font-semibold">Total Latency</span>
                  <span className="text-white font-mono">{formatLatency(result.total_latency_ns)}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {showAllowBanner && !isRunning && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10 bg-white/60 backdrop-blur-[2px] rounded-lg">
            <div className="bg-emerald-900 border-4 border-emerald-500 shadow-2xl rounded-xl p-8 max-w-lg w-full transform -translate-y-12 pointer-events-auto text-center animate-in fade-in zoom-in duration-300">
              <div className="flex justify-center mb-4">
                <div className="bg-emerald-500 p-3 rounded-full">
                  <ShieldAlert className="w-12 h-12 text-white" />
                </div>
              </div>
              <h2 className="text-2xl font-black text-white tracking-widest mb-2 uppercase">Agent execution permitted</h2>
              <div className="bg-emerald-950 p-4 rounded-lg border border-emerald-800 text-left space-y-2 mt-6">
                <div className="flex justify-between items-center border-b border-emerald-800 pb-2 pt-2">
                  <span className="text-emerald-300 text-sm uppercase tracking-wider font-semibold">Total Latency</span>
                  <span className="text-white font-mono">{formatLatency(result.total_latency_ns)}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
