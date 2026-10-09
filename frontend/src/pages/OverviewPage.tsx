import React from 'react';
import { Link } from 'react-router-dom';
import { useSystemStatus } from '../hooks/useSystemStatus';
import { useExperiments } from '../hooks/useExperiments';
import { useEvidence } from '../hooks/useEvidence';
import { ExecutionModeBadge } from '../components/common/ExecutionModeBadge';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { ShieldCheck, Activity, Database, FlaskConical, ArrowRight } from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const { status, loading: statusLoading, error: statusError } = useSystemStatus();
  const { experiments, loading: expLoading } = useExperiments();
  const { sessions, sessionsLoading: evLoading } = useEvidence();

  if (statusError) {
    return <ErrorState title="Dashboard Unavailable" message={statusError} />;
  }

  if (statusLoading || expLoading || evLoading) {
    return <LoadingState message="Initializing AgentSentinel Dashboard..." />;
  }

  if (!status) return null;

  return (
    <div className="space-y-8 pb-32">
      <div className="mb-4">
        <h2 className="text-2xl font-bold text-slate-900 dark:text-white">AgentSentinel System Overview</h2>
        <p className="mt-2 text-slate-600 dark:text-slate-400">
          High-level summary of the multi-layer AI agent security system capabilities and execution modes in this environment.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* System Health */}
        <div className="bg-white dark:bg-slate-900 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 p-6 flex flex-col h-full">
          <div className="flex items-center mb-4">
            <Activity className="w-5 h-5 text-indigo-500 mr-2" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">System Health</h3>
          </div>
          <div className="flex-grow">
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Backend Connection</p>
            <span className={`px-2 py-1 rounded text-xs font-bold font-mono ${
              status.backend_status === 'OPERATIONAL' ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400' : 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400'
            }`}>
              {status.backend_status}
            </span>
          </div>
          <Link to="/system" className="mt-4 flex items-center text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700">
            View Architecture Status <ArrowRight className="w-4 h-4 ml-1" />
          </Link>
        </div>

        {/* Security Pipeline */}
        <div className="bg-white dark:bg-slate-900 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 p-6 flex flex-col h-full">
          <div className="flex items-center mb-4">
            <ShieldCheck className="w-5 h-5 text-emerald-500 mr-2" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Security Pipeline</h3>
          </div>
          <div className="flex-grow">
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Active Layers</p>
            <div className="text-3xl font-bold text-slate-900 dark:text-white">
              {status.layers.filter(l => l.operational_status !== 'UNAVAILABLE').length} <span className="text-lg text-slate-500 font-normal">/ 7</span>
            </div>
          </div>
          <Link to="/pipeline" className="mt-4 flex items-center text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700">
            Test Pipeline Engine <ArrowRight className="w-4 h-4 ml-1" />
          </Link>
        </div>

        {/* ECES Evidence */}
        <div className="bg-white dark:bg-slate-900 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 p-6 flex flex-col h-full">
          <div className="flex items-center mb-4">
            <Database className="w-5 h-5 text-blue-500 mr-2" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">ECES Evidence</h3>
          </div>
          <div className="flex-grow">
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Recorded Sessions</p>
            <div className="text-3xl font-bold text-slate-900 dark:text-white">
              {sessions.length}
            </div>
            <div className="mt-2">
              {sessions.length === 0 ? (
                <span className="text-sm text-slate-500 italic">Run a scenario to populate</span>
              ) : (
                <ExecutionModeBadge mode={status.database_status === 'OPERATIONAL' ? 'REAL_RUNTIME' : 'UNAVAILABLE'} />
              )}
            </div>
          </div>
          <Link to="/evidence" className="mt-4 flex items-center text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700">
            Inspect Audit Chains <ArrowRight className="w-4 h-4 ml-1" />
          </Link>
        </div>

        {/* Research Benchmarks */}
        <div className="bg-white dark:bg-slate-900 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 p-6 flex flex-col h-full">
          <div className="flex items-center mb-4">
            <FlaskConical className="w-5 h-5 text-purple-500 mr-2" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Research Benchmarks</h3>
          </div>
          <div className="flex-grow">
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Completed Experiments</p>
            <div className="text-3xl font-bold text-slate-900 dark:text-white">
              {experiments.length}
            </div>
          </div>
          <Link to="/experiments" className="mt-4 flex items-center text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700">
            View Research Data <ArrowRight className="w-4 h-4 ml-1" />
          </Link>
        </div>
      </div>

      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
        <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-4">Environment Constraints</h3>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          {status.overall_description} The dashboard explicitly flags components as natively available (<span className="text-xs font-mono font-bold text-emerald-600">REAL_RUNTIME</span>) versus <span className="text-xs font-mono font-bold text-amber-600">SIMULATED</span> or <span className="text-xs font-mono font-bold text-blue-600">BENCHMARK</span> to preserve scientific honesty in demonstrations.
        </p>
      </div>
    </div>
  );
};
