import React from 'react';
import { AnimatedNumber } from './AnimatedNumber';
import { Link } from 'react-router-dom';
import { Activity, ShieldAlert, ShieldCheck, AlertTriangle, Clock, Database } from 'lucide-react';

interface PipelineStatisticsProps {
  stats: {
    attacksRun: number;
    blocked: number;
    frozen: number;
    allowed: number;
    cumulativeLatency: number;
    ecesCount: number;
  };
}

export const PipelineStatistics: React.FC<PipelineStatisticsProps> = ({ stats }) => {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded-lg shadow-xl overflow-hidden mb-6">
      {/* Top Grid: Main Counters */}
      <div className="grid grid-cols-4 divide-x divide-gray-800">
        <div className="p-4 flex flex-col items-center justify-center">
          <div className="flex items-center space-x-2 text-gray-400 mb-2">
            <Activity className="w-4 h-4" />
            <span className="text-xs font-bold tracking-wider uppercase">Scenarios Run</span>
          </div>
          <div className="text-3xl font-black text-white">
            <AnimatedNumber value={stats.attacksRun} />
          </div>
        </div>

        <div className="p-4 flex flex-col items-center justify-center">
          <div className="flex items-center space-x-2 text-red-400 mb-2">
            <ShieldAlert className="w-4 h-4" />
            <span className="text-xs font-bold tracking-wider uppercase">L1/L2 Blocked</span>
          </div>
          <div className="text-3xl font-black text-red-400">
            <AnimatedNumber value={stats.blocked} />
          </div>
        </div>

        <div className="p-4 flex flex-col items-center justify-center">
          <div className="flex items-center space-x-2 text-orange-400 mb-2">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs font-bold tracking-wider uppercase">Frozen</span>
          </div>
          <div className="text-3xl font-black text-orange-400">
            <AnimatedNumber value={stats.frozen} />
          </div>
        </div>

        <div className="p-4 flex flex-col items-center justify-center">
          <div className="flex items-center space-x-2 text-emerald-400 mb-2">
            <ShieldCheck className="w-4 h-4" />
            <span className="text-xs font-bold tracking-wider uppercase">Allowed</span>
          </div>
          <div className="text-3xl font-black text-emerald-400">
            <AnimatedNumber value={stats.allowed} />
          </div>
        </div>
      </div>

      {/* Bottom Grid: Contextual Metrics */}
      <div className="bg-gray-900 border-t border-gray-800 flex justify-between items-center px-6 py-3">
        <div className="flex items-center space-x-3 text-sm">
          <Clock className="w-4 h-4 text-gray-500" />
          <span className="text-gray-400 uppercase tracking-wider text-xs font-bold">Total Latency:</span>
          <span className="text-gray-200 font-mono font-semibold">
            <AnimatedNumber value={stats.cumulativeLatency} decimals={1} /> ms
          </span>
        </div>

        <div className="flex items-center space-x-3 text-sm">
          <Database className="w-4 h-4 text-gray-500" />
          <span className="text-gray-400 uppercase tracking-wider text-xs font-bold">ECES Evidence:</span>
          <span className="text-gray-200 font-mono font-semibold">
            <AnimatedNumber value={stats.ecesCount} /> records
          </span>
          <Link 
            to="/evidence" 
            className="ml-3 text-blue-400 hover:text-blue-300 hover:underline transition-colors text-xs font-semibold flex items-center"
          >
            View replay evidence &rarr;
          </Link>
        </div>
      </div>
    </div>
  );
};
