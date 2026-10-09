import React from 'react';
import type { LayerSystemStatus } from '../../types/api';
import { ExecutionModeBadge } from '../common/ExecutionModeBadge';
import { Check, X } from 'lucide-react';

interface Props {
  layers: LayerSystemStatus[];
}

export const LayerStatusGrid: React.FC<Props> = ({ layers }) => {
  const groups = [
    { label: 'AVAILABLE / IMPLEMENTED', items: layers.filter(l => l.execution_mode === 'REAL_RUNTIME') },
    { label: 'SIMULATED / DEMONSTRATION', items: layers.filter(l => l.execution_mode === 'SIMULATED') },
    { label: 'SYNTHETIC / BENCHMARK', items: layers.filter(l => l.execution_mode === 'SYNTHETIC' || l.execution_mode === 'BENCHMARK') },
    { label: 'UNAVAILABLE / DEPENDENCY', items: layers.filter(l => l.execution_mode === 'UNAVAILABLE') }
  ].filter(g => g.items.length > 0);

  return (
    <div className="space-y-8">
      {groups.map(group => (
        <div key={group.label} className="space-y-3">
          <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">{group.label}</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {group.items.map((layer) => (
              <div key={layer.layer_id} className="bg-slate-900 border border-slate-700 rounded-lg overflow-hidden flex flex-col h-full">
                <div className="px-4 py-3 bg-slate-800 border-b border-slate-700 flex justify-between items-start">
                  <div>
                    <span className="text-xs font-bold text-blue-400 bg-blue-400/10 px-2 py-0.5 rounded mr-2">
                      {layer.layer_id}
                    </span>
                    <h3 className="text-sm font-semibold text-slate-100 mt-1">{layer.name}</h3>
                  </div>
                  <div className="flex flex-col items-end space-y-1">
                    <span className={`text-xs font-mono font-bold ${layer.operational_status === 'OPERATIONAL' ? 'text-emerald-400' : layer.operational_status === 'PARTIAL' ? 'text-yellow-400' : 'text-red-400'}`}>
                      {layer.operational_status}
                    </span>
                    <ExecutionModeBadge mode={layer.execution_mode} />
                  </div>
                </div>
                <div className="p-4 flex-grow flex flex-col space-y-4">
                  <p className="text-xs text-slate-300">
                    {layer.description}
                  </p>

                  <div className="flex-grow">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Capabilities</h4>
                    <ul className="space-y-1">
                      {layer.capabilities.map((cap, i) => (
                        <li key={i} className="text-xs text-emerald-300 flex items-start">
                          <Check className="w-3.5 h-3.5 mr-1.5 mt-0.5 shrink-0" />
                          <span>{cap}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {layer.limitations.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Limitations</h4>
                      <ul className="space-y-1">
                        {layer.limitations.map((lim, i) => (
                          <li key={i} className="text-xs text-red-300/80 flex items-start">
                            <X className="w-3.5 h-3.5 mr-1.5 mt-0.5 shrink-0" />
                            <span>{lim}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};
