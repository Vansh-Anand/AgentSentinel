import React from 'react';
import type { CapabilityStatus } from '../../types/api';
import { ExecutionModeBadge } from '../common/ExecutionModeBadge';

interface Props {
  capabilities: CapabilityStatus[];
}

export const CapabilityMatrix: React.FC<Props> = ({ capabilities }) => {
  const groups = [
    { label: 'AVAILABLE / IMPLEMENTED', items: capabilities.filter(c => c.execution_mode === 'REAL_RUNTIME') },
    { label: 'SIMULATED / DEMONSTRATION', items: capabilities.filter(c => c.execution_mode === 'SIMULATED') },
    { label: 'SYNTHETIC / BENCHMARK', items: capabilities.filter(c => c.execution_mode === 'SYNTHETIC' || c.execution_mode === 'BENCHMARK') },
    { label: 'UNAVAILABLE / DEPENDENCY', items: capabilities.filter(c => c.execution_mode === 'UNAVAILABLE') }
  ].filter(g => g.items.length > 0);

  return (
    <div className="space-y-6">
      {groups.map((group, groupIdx) => (
        <div key={groupIdx} className="bg-slate-900 border border-slate-700 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-700 bg-slate-800 flex justify-between items-center">
            <h3 className="text-lg font-medium text-slate-100">{group.label}</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-700">
              <thead className="bg-slate-800/50">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Capability</th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Validation</th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Mode</th>
                </tr>
              </thead>
              <tbody className="bg-slate-900 divide-y divide-slate-700/50">
                {group.items.map((cap, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-200">
                      {cap.name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        cap.status === 'Operational' ? 'bg-emerald-400/10 text-emerald-400' :
                        cap.status === 'Partial' ? 'bg-yellow-400/10 text-yellow-400' :
                        'bg-slate-700 text-slate-300'
                      }`}>
                        {cap.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {cap.validation_level}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <ExecutionModeBadge mode={cap.execution_mode} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
};
