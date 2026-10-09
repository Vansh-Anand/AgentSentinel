import React from 'react';
import { useSystemStatus } from '../hooks/useSystemStatus';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { LayerStatusGrid } from '../components/status/LayerStatusGrid';
import { CapabilityMatrix } from '../components/status/CapabilityMatrix';
import { InfrastructureStatusGrid } from '../components/status/InfrastructureStatusGrid';
import { ShieldCheck, Info } from 'lucide-react';

export const SystemStatusPage: React.FC = () => {
  const { status, loading, error } = useSystemStatus();

  if (error) {
    return <ErrorState title="System Status Unavailable" message={error} />;
  }

  if (loading || !status) {
    return <LoadingState message="Querying architecture health..." />;
  }

  return (
    <div className="space-y-8 pb-32">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center">
            <ShieldCheck className="w-6 h-6 mr-2 text-indigo-500" />
            AgentSentinel System Status
          </h2>
          <p className="mt-2 text-slate-600 dark:text-slate-400">
            Deployment capabilities and validation modes, with inactive dependencies shown explicitly.
          </p>
        </div>
        
        <div className="text-right">
          <div className="inline-flex flex-col items-end">
            <span className="text-xs text-slate-500 font-mono mb-1">API v{status.api_version}</span>
            <span className={`px-3 py-1 rounded text-sm font-bold font-mono ${
              status.overall_status === 'OPERATIONAL' ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' :
              status.overall_status.includes('PARTIAL') ? 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400' :
              'bg-red-500/10 text-red-600 dark:text-red-400'
            }`}>
              {status.overall_status}
            </span>
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-700 rounded-lg p-5 flex items-start space-x-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <h4 className="text-sm font-medium text-slate-100">Environment Limitations</h4>
          <p className="text-sm text-slate-300 mt-1">{status.overall_description}</p>
        </div>
      </div>

      <section>
        <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-4">Infrastructure</h3>
        <InfrastructureStatusGrid infrastructure={status.infrastructure} />
      </section>

      <section>
        <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-4">L1–L7 Architecture</h3>
        <LayerStatusGrid layers={status.layers} />
      </section>

      <section>
        <CapabilityMatrix capabilities={status.capabilities} />
      </section>
    </div>
  );
};
