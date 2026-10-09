import React, { useState, useMemo } from 'react';
import { useExperiments } from '../hooks/useExperiments';
import { useExperiment } from '../hooks/useExperiment';
import { ExperimentCard } from '../components/experiments/ExperimentCard';
import { ExperimentFilters, type FilterState } from '../components/experiments/ExperimentFilters';
import { ExperimentDetail } from '../components/experiments/ExperimentDetail';
import { ExperimentComparison } from '../components/experiments/ExperimentComparison';
import { ErrorState } from '../components/common/ErrorState';
import { FlaskConical, Loader2, BarChart2 } from 'lucide-react';
import type { ExperimentNormalized } from '../types/api';
import { getExperimentDetail } from '../api/experiments';

export const ExperimentsPage: React.FC = () => {
  const { experiments, loading: listLoading, error: listError } = useExperiments();
  const [activeExperimentId, setActiveExperimentId] = useState<string | null>(null);
  const { experiment: activeExperiment, loading: detailLoading, error: detailError } = useExperiment(activeExperimentId);
  
  const [filters, setFilters] = useState<FilterState>({ search: '', category: null, executionMode: null });
  const [comparedExperiments, setComparedExperiments] = useState<ExperimentNormalized[]>([]);
  const [compareError, setCompareError] = useState<string | null>(null);

  // Derive categories dynamically from available experiments
  const categories = useMemo(() => {
    const cats = new Set<string>();
    experiments.forEach(e => cats.add(e.category));
    return Array.from(cats).sort();
  }, [experiments]);

  // Apply filters
  const filteredExperiments = useMemo(() => {
    return experiments.filter(exp => {
      const matchSearch = filters.search === '' || 
        exp.title.toLowerCase().includes(filters.search.toLowerCase()) || 
        exp.experiment_id.toLowerCase().includes(filters.search.toLowerCase()) ||
        (exp.model_name && exp.model_name.toLowerCase().includes(filters.search.toLowerCase()));
      
      const matchCategory = filters.category === null || exp.category === filters.category;
      const matchMode = filters.executionMode === null || exp.execution_mode === filters.executionMode;
      
      return matchSearch && matchCategory && matchMode;
    });
  }, [experiments, filters]);

  // Calculate safe aggregate stats
  const aggregateStats = useMemo(() => {
    let realModel = 0;
    let synthetic = 0;
    let techniques = 0;
    experiments.forEach(e => {
      if (e.execution_mode === 'REAL_RUNTIME') realModel++;
      else if (e.execution_mode === 'SYNTHETIC') synthetic++;
      
      if (e.category.includes('Technique')) techniques++;
    });
    return { total: experiments.length, realModel, synthetic, techniques };
  }, [experiments]);

  const handleToggleCompare = async (id: string) => {
    setCompareError(null);
    if (comparedExperiments.some(e => e.experiment_id === id)) {
      setComparedExperiments(prev => prev.filter(e => e.experiment_id !== id));
      return;
    }
    
    if (comparedExperiments.length >= 3) {
      setCompareError("You can only compare up to 3 experiments at a time.");
      // Auto-clear error after 3s
      setTimeout(() => setCompareError(null), 3000);
      return;
    }

    try {
      const expDetail = await getExperimentDetail(id);
      setComparedExperiments(prev => [...prev, expDetail]);
    } catch (err: any) {
      setCompareError("Failed to fetch experiment details for comparison.");
      setTimeout(() => setCompareError(null), 3000);
    }
  };

  return (
    <div className="space-y-8 pb-32">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 flex items-center">
            <FlaskConical className="w-6 h-6 mr-2 text-purple-600" />
            Research Benchmark Results
          </h2>
          <p className="mt-2 text-gray-600">Explore security performance and latency benchmarks for AgentSentinel.</p>
        </div>
      </div>

      {listError && <ErrorState title="Failed to load experiments" message={listError} />}

      {/* Aggregate Stats Section */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
          <div className="text-sm font-semibold text-gray-500 uppercase">Total Experiments</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{aggregateStats.total}</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
          <div className="text-sm font-semibold text-gray-500 uppercase">Real LLM Evals</div>
          <div className="text-2xl font-bold text-emerald-600 mt-1">{aggregateStats.realModel}</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
          <div className="text-sm font-semibold text-gray-500 uppercase">Synthetic / Sim</div>
          <div className="text-2xl font-bold text-purple-600 mt-1">{aggregateStats.synthetic}</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
          <div className="text-sm font-semibold text-gray-500 uppercase">Patent Techniques</div>
          <div className="text-2xl font-bold text-blue-600 mt-1">{aggregateStats.techniques}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
        
        {/* Left Column: Catalog & Filters */}
        <div className="xl:col-span-1 space-y-6">
          <ExperimentFilters 
            filters={filters} 
            onFilterChange={setFilters} 
            categories={categories} 
          />
          
          {compareError && (
            <div className="bg-red-50 text-red-700 text-sm p-3 rounded-lg border border-red-200">
              {compareError}
            </div>
          )}
          
          {listLoading ? (
            <div className="flex justify-center items-center py-12">
              <Loader2 className="w-8 h-8 text-purple-500 animate-spin" />
            </div>
          ) : filteredExperiments.length === 0 ? (
            <div className="bg-gray-50 p-8 rounded-lg border border-dashed border-gray-300 text-center text-gray-500">
              No experiments match your filters.
            </div>
          ) : (
            <div className="space-y-4 max-h-[800px] overflow-y-auto pr-2">
              {filteredExperiments.map(exp => (
                <ExperimentCard 
                  key={exp.experiment_id}
                  experiment={exp}
                  isSelected={activeExperimentId === exp.experiment_id}
                  onSelect={setActiveExperimentId}
                  onToggleCompare={handleToggleCompare}
                  isCompared={comparedExperiments.some(e => e.experiment_id === exp.experiment_id)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Detail View */}
        <div className="xl:col-span-2">
          {detailLoading ? (
            <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 flex justify-center items-center min-h-[400px]">
              <div className="animate-pulse flex flex-col items-center text-gray-500">
                <Loader2 className="w-8 h-8 mb-4 animate-spin text-purple-500" />
                <span>Loading experiment details...</span>
              </div>
            </div>
          ) : detailError ? (
            <ErrorState title="Experiment Unavailable" message={detailError} />
          ) : activeExperiment ? (
            <ExperimentDetail experiment={activeExperiment} />
          ) : (
            <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 border-dashed flex flex-col items-center justify-center text-center min-h-[400px]">
              <BarChart2 className="w-16 h-16 text-gray-300 mb-4" />
              <h3 className="text-lg font-medium text-gray-900">Select an Experiment</h3>
              <p className="mt-2 text-sm text-gray-500 max-w-sm">
                Browse the catalog on the left to inspect detailed benchmark metrics, latency overheads, and comparison visualizations.
              </p>
            </div>
          )}
        </div>
      </div>

      <ExperimentComparison 
        experiments={comparedExperiments} 
        onRemove={(id) => setComparedExperiments(prev => prev.filter(e => e.experiment_id !== id))}
        onClear={() => setComparedExperiments([])}
      />
    </div>
  );
};
