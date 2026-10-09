import React from 'react';
import { ExecutionMode } from '../../types/api';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface ExecutionModeBadgeProps {
  mode: ExecutionMode;
  className?: string;
}

export const ExecutionModeBadge: React.FC<ExecutionModeBadgeProps> = ({ mode, className }) => {
  const styles: Record<string, string> = {
    [ExecutionMode.REAL_RUNTIME]: 'bg-emerald-100 text-emerald-800 border-emerald-200',
    [ExecutionMode.SIMULATED]: 'bg-amber-100 text-amber-800 border-amber-200',
    [ExecutionMode.BENCHMARK]: 'bg-blue-100 text-blue-800 border-blue-200',
    [ExecutionMode.SYNTHETIC]: 'bg-purple-100 text-purple-800 border-purple-200',
    [ExecutionMode.UNAVAILABLE]: 'bg-gray-100 text-gray-800 border-gray-200',
  };

  const labels: Record<string, string> = {
    [ExecutionMode.REAL_RUNTIME]: 'REAL RUNTIME',
    [ExecutionMode.SIMULATED]: 'SIMULATED (Demonstration)',
    [ExecutionMode.BENCHMARK]: 'BENCHMARK (Dataset)',
    [ExecutionMode.SYNTHETIC]: 'SYNTHETIC (Benchmark data)',
    [ExecutionMode.UNAVAILABLE]: 'UNAVAILABLE (Native dependency)',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
        styles[mode] || styles[ExecutionMode.UNAVAILABLE],
        className
      )}
    >
      {labels[mode] || mode}
    </span>
  );
};
