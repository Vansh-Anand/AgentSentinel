import React from 'react';
import { ScenarioSelector } from '../components/pipeline/ScenarioSelector';
import { PipelineFlow } from '../components/pipeline/PipelineFlow';
import { InterceptionDetails } from '../components/pipeline/InterceptionDetails';
import { PipelineStatistics } from '../components/pipeline/PipelineStatistics';
import { ChallengeLab } from '../components/pipeline/ChallengeLab';
import { usePipelineExecution } from '../hooks/usePipelineExecution';
import { useSessionStatistics } from '../hooks/useSessionStatistics';
import { useDemoOrchestrator } from '../hooks/useDemoOrchestrator';
import { ErrorState } from '../components/common/ErrorState';
import { Shield, Play, Square, RotateCcw, CheckCircle, Database, XCircle, AlertTriangle } from 'lucide-react';

const getVerdictReason = (layer: string, decision: string) => {
  if (decision === 'ALLOW') return 'This research scenario reached its allow result; the simulated layers do not establish live safety.';
  switch (layer) {
    case 'L1': return 'Research scenario: the simulated orchestrator rejected this proposal at L1.';
    case 'L2': return 'Research scenario: the simulated orchestrator rejected this command at L2.';
    case 'L3': return 'Simulated kernel event replay; no live kernel telemetry was collected.';
    case 'L4': return 'Synthetic behavioral divergence result; no live learned baseline was evaluated.';
    case 'L5': return 'Simulated temporal risk threshold; no live cross-session governance ran.';
    case 'L6': return 'Simulated evidence-tampering scenario. Use the challenge lab for a real HMAC integrity check.';
    case 'L7': return 'Hardware attestation is unavailable on this host.';
    default: return 'Action was intercepted by security policy.';
  }
};

const getExecutionModeDisplay = (layer: string, decision: string) => {
  if (decision === 'ALLOW') return { mode: 'SIMULATED', desc: 'Execution spanned simulated layers (L3-L5)' };
  switch (layer) {
    case 'L1': return { mode: 'SIMULATED', desc: 'Research orchestrator scenario; use the challenge lab for a schema check.' };
    case 'L2': return { mode: 'SIMULATED', desc: 'Research orchestrator scenario; use the challenge lab for live gateway enforcement.' };
    case 'L3': return { mode: 'SIMULATED', desc: 'Simulated telemetry replay or mock execution.' };
    case 'L4': return { mode: 'SYNTHETIC', desc: 'Detector evaluated on synthetic benchmark data.' };
    case 'L5': return { mode: 'SIMULATED', desc: 'Demonstration heuristic, not live Bayesian inference.' };
    case 'L6': return { mode: 'SIMULATED', desc: 'Preset result; use the challenge lab for a real HMAC check.' };
    case 'L7': return { mode: 'UNAVAILABLE', desc: 'Hardware attestation unavailable.' };
    default: return { mode: 'UNKNOWN', desc: '' };
  }
};
import { Link } from 'react-router-dom';
import { AVAILABLE_SCENARIOS } from '../types/pipeline';

export const PipelinePage: React.FC = () => {
  const execution = usePipelineExecution();
  const stats = useSessionStatistics(execution.result);
  const demo = useDemoOrchestrator(execution);

  const activeScenarioId = (demo.demoState !== 'IDLE' && demo.demoState !== 'CANCELLED' && demo.demoState !== 'COMPLETE') 
    ? demo.currentScenarioId 
    : null;

  return (
    <div className="space-y-6">
      <div className="mb-8 flex justify-between items-start">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 flex items-center">
            <Shield className="w-6 h-6 mr-2 text-blue-600" />
            AgentSentinel Research Pipeline
          </h2>
          <p className="mt-2 text-gray-600">Compare editable challenge checks with the research pipeline scenario replay. Each result states its proof level.</p>
        </div>
        <div className="flex space-x-3">
          {(demo.demoState === 'IDLE' || demo.demoState === 'CANCELLED' || demo.demoState === 'COMPLETE') && (
            <button 
              onClick={demo.startDemo}
              disabled={execution.isRunning}
              className="flex items-center px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white text-sm font-bold rounded-md shadow-sm transition-colors disabled:opacity-50"
            >
              <Play className="w-4 h-4 mr-2" />
              Run Research Replay
            </button>
          )}
          {(demo.demoState === 'RUNNING' || demo.demoState === 'PAUSED_BETWEEN' || demo.demoState === 'ERROR') && (
            <button 
              onClick={demo.stopDemo}
              className="flex items-center px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-bold rounded-md shadow-sm transition-colors"
            >
              <Square className="w-4 h-4 mr-2" />
              Stop Demo
            </button>
          )}
        </div>
      </div>
      <ChallengeLab />
      
      {(demo.demoState === 'RUNNING' || demo.demoState === 'PAUSED_BETWEEN') && (
        <div className="bg-amber-100 border border-amber-300 rounded-md p-3 mb-6 flex items-center justify-between shadow-sm animate-pulse">
          <div className="flex items-center">
            <Play className="w-5 h-5 text-amber-600 mr-3" />
            <span className="font-bold text-amber-900 tracking-wider">DEMO MODE ACTIVE</span>
            <span className="mx-3 text-amber-300">|</span>
            <span className="text-amber-800 font-medium">
              Scenario {demo.currentScenarioIndex + 1} of {demo.sequenceCount} — {AVAILABLE_SCENARIOS.find(s => s.id === demo.currentScenarioId)?.label}
            </span>
          </div>
        </div>
      )}

      {demo.demoState === 'ERROR' && (
        <div className="bg-red-100 border border-red-300 rounded-md p-4 mb-6 shadow-sm">
          <h3 className="font-bold text-red-900 flex items-center">
            <Shield className="w-5 h-5 mr-2" />
            DEMO INTERRUPTED
          </h3>
          <p className="mt-2 text-red-800 text-sm">
            <strong>Scenario:</strong> {AVAILABLE_SCENARIOS.find(s => s.id === demo.currentScenarioId)?.label}
          </p>
          <p className="mt-1 text-red-800 text-sm">
            <strong>Reason:</strong> {execution.error || 'Unknown error occurred'}
          </p>
          <div className="mt-4 flex space-x-3">
            <button onClick={demo.resetDemo} className="px-3 py-1.5 bg-red-200 hover:bg-red-300 text-red-900 text-sm font-medium rounded transition-colors">Stop Demo</button>
          </div>
        </div>
      )}

      {execution.error && demo.demoState === 'IDLE' && (
        <ErrorState title="Execution Failed" message={execution.error} className="mb-6" />
      )}

      <h3 className="text-lg font-semibold text-gray-800">Research replay statistics</h3>
      <PipelineStatistics stats={stats} />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-1 space-y-6">
            <ScenarioSelector 
              onSelect={execution.executeScenario} 
              onReset={() => {
                execution.reset();
                if (demo.demoState !== 'IDLE') demo.resetDemo();
              }}
              isRunning={execution.isRunning || (demo.demoState !== 'IDLE' && demo.demoState !== 'CANCELLED' && demo.demoState !== 'COMPLETE')} 
              result={execution.result}
              activeScenarioId={activeScenarioId}
            />
          
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 text-sm text-gray-600 space-y-4">
            <h4 className="font-semibold text-gray-900 border-b border-gray-200 pb-2">Execution Notes</h4>
            <p>
              Scenarios are processed synchronously by the backend orchestrator. The pipeline flow animation is a UI visualization of the returned event trace, not a WebSocket stream.
            </p>
            <p>
              This scenario runner is a research replay. Its preset L3-L6 outcomes are simulated; hardware L7 is unavailable on this host. Use the challenge lab above for live L2 policy and L6 HMAC checks.
            </p>
          </div>
        </div>

        <div className="xl:col-span-2 space-y-6">
          {demo.demoState === 'COMPLETE' ? (
            <div className="bg-gray-950 border border-gray-800 rounded-lg shadow-xl p-8 h-full flex flex-col items-center">
              <CheckCircle className="w-16 h-16 text-emerald-500 mb-6" />
              <h3 className="text-2xl font-black text-white tracking-widest uppercase mb-8">Demo Complete</h3>
              
              <div className="grid grid-cols-2 gap-12 w-full max-w-2xl mb-8">
                <div className="space-y-4">
                  <div className="flex justify-between border-b border-gray-800 pb-2">
                    <span className="text-gray-400">Attacks Executed</span>
                    <span className="text-white font-bold">{stats.attacksRun}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800 pb-2">
                    <span className="text-gray-400">Blocked</span>
                    <span className="text-red-400 font-bold">{stats.blocked}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800 pb-2">
                    <span className="text-gray-400">Frozen</span>
                    <span className="text-orange-400 font-bold">{stats.frozen}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800 pb-2">
                    <span className="text-gray-400">Allowed</span>
                    <span className="text-emerald-400 font-bold">{stats.allowed}</span>
                  </div>
                </div>

                <div className="flex flex-col justify-center items-center bg-gray-900 rounded-lg p-6 border border-gray-800">
                  <Database className="w-8 h-8 text-blue-400 mb-3" />
                  <span className="text-gray-300 text-sm mb-1 uppercase tracking-wider font-bold">ECES</span>
                  <span className="text-3xl text-white font-black">{stats.ecesCount}</span>
                  <span className="text-gray-500 text-xs mt-1">evidence records</span>
                  <Link to="/evidence" className="mt-4 text-blue-400 hover:text-blue-300 text-sm font-semibold transition-colors flex items-center">
                    View cryptographic audit &rarr;
                  </Link>
                </div>
              </div>

              <div className="w-full max-w-3xl overflow-x-auto rounded border border-gray-800">
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
                    <tr>
                      <th className="px-4 py-3">Scenario</th>
                      <th className="px-4 py-3">Expected</th>
                      <th className="px-4 py-3">Observed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 text-gray-300 bg-gray-950">
                    {demo.demoResults.map((res, i) => {
                      const scenarioDef = AVAILABLE_SCENARIOS.find(s => s.id === res.scenario_id);
                      let expected = scenarioDef?.expectedDefense || 'Unknown';
                      if (expected === 'ALLOW') expected = 'ALLOW';
                      else expected = scenarioDef?.targetLayer || expected;
                      
                      const observed = res.overall_decision === 'ALLOW' ? 'ALLOWED' : `${res.stopping_layer} ${res.overall_decision}`;
                      return (
                        <tr key={res.session_id + i}>
                          <td className="px-4 py-3 font-medium text-white">{scenarioDef?.label}</td>
                          <td className="px-4 py-3">{expected}</td>
                          <td className="px-4 py-3 font-mono">{observed}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="mt-8">
                <button 
                  onClick={() => {
                    execution.reset();
                    demo.resetDemo();
                  }}
                  className="flex items-center px-6 py-2 bg-gray-800 hover:bg-gray-700 text-white font-semibold rounded-md transition-colors"
                >
                  <RotateCcw className="w-4 h-4 mr-2" />
                  Reset Demo
                </button>
              </div>
            </div>
          ) : (!execution.result && !execution.isRunning && execution.currentLayer === null) ? (
            <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 border-dashed flex flex-col items-center justify-center text-center h-full min-h-[400px]">
              <Shield className="w-16 h-16 text-gray-300 mb-4" />
              <h3 className="text-lg font-medium text-gray-900">Pipeline Idle</h3>
              <p className="mt-2 text-sm text-gray-500 max-w-sm">Select a scenario from the left panel to begin execution simulation through the defense layers.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full">
              <div className="lg:col-span-1 h-full">
                <PipelineFlow execution={execution} />
              </div>
              <div className="lg:col-span-1 h-full">
                {execution.result && execution.selectedLayerId ? (
                  <>
                    {/* Final Verdict Panel */}
                    {!execution.isRunning && (
                      <div className={`p-6 rounded-lg shadow-xl border ${
                        execution.result.overall_decision === 'ALLOW' ? 'bg-emerald-950 border-emerald-800' :
                        execution.result.overall_decision === 'FREEZE' ? 'bg-orange-950 border-orange-800' :
                        execution.result.overall_decision === 'UNAVAILABLE' ? 'bg-gray-900 border-gray-700' :
                        'bg-red-950 border-red-800'
                      }`}>
                        <div className="flex items-start space-x-4">
                          {execution.result.overall_decision === 'ALLOW' ? <CheckCircle className="w-10 h-10 text-emerald-400 flex-shrink-0" /> :
                           execution.result.overall_decision === 'FREEZE' ? <AlertTriangle className="w-10 h-10 text-orange-400 flex-shrink-0" /> :
                           execution.result.overall_decision === 'UNAVAILABLE' ? <AlertTriangle className="w-10 h-10 text-amber-400 flex-shrink-0" /> :
                           <XCircle className="w-10 h-10 text-red-400 flex-shrink-0" />}
                          
                          <div className="flex-1">
                            <h3 className="text-xs font-bold uppercase tracking-widest text-gray-400 mb-1">SECURITY DECISION</h3>
                            <div className="flex items-baseline space-x-3 mb-4">
                              <span className={`text-3xl font-black tracking-tight ${
                                execution.result.overall_decision === 'ALLOW' ? 'text-emerald-400' :
                                execution.result.overall_decision === 'FREEZE' ? 'text-orange-400' :
                                execution.result.overall_decision === 'UNAVAILABLE' ? 'text-amber-400' : 'text-red-400'
                              }`}>
                                {execution.result.overall_decision}
                              </span>
                            </div>
                            
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm mb-4 border-t border-gray-800/50 pt-4">
                              <div>
                                <span className="block text-gray-500 font-semibold mb-1">Stopping Layer</span>
                                <span className="text-gray-200 font-mono bg-gray-900 px-2 py-1 rounded">
                                  {execution.result.stopping_layer}
                                </span>
                              </div>
                              <div>
                                <span className="block text-gray-500 font-semibold mb-1">Execution Mode</span>
                                <span className="text-blue-400 font-bold">
                                  {getExecutionModeDisplay(execution.result.stopping_layer, execution.result.overall_decision).mode}
                                </span>
                              </div>
                            </div>
                            
                            <div className="bg-gray-900/50 p-3 rounded text-sm">
                              <span className="block text-gray-500 font-semibold mb-1">Reason</span>
                              <p className="text-gray-300">
                                {getVerdictReason(execution.result.stopping_layer, execution.result.overall_decision)}
                              </p>
                            </div>
                            
                            {getExecutionModeDisplay(execution.result.stopping_layer, execution.result.overall_decision).mode !== 'REAL_RUNTIME' && (
                              <p className="mt-3 text-xs font-semibold text-gray-400 italic flex items-center">
                                <AlertTriangle className="w-3 h-3 mr-1" />
                                {getExecutionModeDisplay(execution.result.stopping_layer, execution.result.overall_decision).desc}
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                    
                    <InterceptionDetails result={execution.result} selectedLayerId={execution.selectedLayerId} />
                  </>
                ) : (
                  <div className="bg-gray-950 border border-gray-800 rounded-lg shadow-xl p-8 flex flex-col items-center justify-center text-center h-full min-h-[400px]">
                    {execution.isRunning ? (
                      <>
                        <div className="w-12 h-12 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin mb-4"></div>
                        <h3 className="text-lg font-medium text-gray-300">Processing...</h3>
                        <p className="mt-2 text-sm text-gray-500">Executing security pipeline and creating cryptographic evidence.</p>
                      </>
                    ) : (
                      <>
                        <Shield className="w-12 h-12 text-gray-700 mb-4" />
                        <h3 className="text-lg font-medium text-gray-400">Awaiting Details</h3>
                        <p className="mt-2 text-sm text-gray-600">Forensic details will appear here once execution completes or when a layer is selected.</p>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
