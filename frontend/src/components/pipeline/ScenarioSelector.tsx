import React, { useState } from 'react';
import { AVAILABLE_SCENARIOS, type ScenarioCategory } from '../../types/pipeline';
import type { PipelineRunResponse } from '../../types/api';
import { Play, RotateCcw, ChevronDown, ChevronRight, CheckCircle2, AlertCircle } from 'lucide-react';

interface ScenarioSelectorProps {
  onSelect: (scenarioId: string) => void;
  onReset: () => void;
  isRunning: boolean;
  result: PipelineRunResponse | null;
  activeScenarioId?: string | null;
}

export const ScenarioSelector: React.FC<ScenarioSelectorProps> = ({ 
  onSelect, 
  onReset, 
  isRunning, 
  result,
  activeScenarioId 
}) => {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const handleReset = () => {
    setSelectedId(null);
    onReset();
  };

  const categories: ScenarioCategory[] = ['PREVENTION', 'DETECTION', 'FORENSICS_INTEGRITY'];

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Select Execution Scenario</h3>
        <button
          onClick={handleReset}
          className="flex items-center text-sm font-medium text-gray-500 hover:text-gray-900"
          title="Reset pipeline"
        >
          <RotateCcw className="w-4 h-4 mr-1" />
          Reset
        </button>
      </div>
      <div className="flex flex-col gap-6">
        {categories.map(category => {
          const categoryScenarios = AVAILABLE_SCENARIOS.filter(s => s.category === category);
          if (categoryScenarios.length === 0) return null;

          return (
            <div key={category} className="space-y-3">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider pl-1">
                {category.replace('_', ' & ')}
              </h4>
              <div className="flex flex-col gap-3">
                {categoryScenarios.map((scenario) => {
                  const isSelected = selectedId === scenario.id;
                  const isExpectedMatch = result && result.stopping_layer === scenario.targetLayer;
                  
                  return (
                    <div
                      key={scenario.id}
                      className={`flex flex-col text-left border rounded-lg transition-colors overflow-hidden ${
                        isSelected ? 'border-blue-500 ring-1 ring-blue-500' : 'border-gray-200 hover:border-blue-400'
                      }`}
                    >
              <button
                onClick={() => !isRunning && setSelectedId(isSelected ? null : scenario.id)}
                disabled={isRunning && !isSelected}
                className={`flex justify-between items-start w-full p-4 transition-colors ${
                  (activeScenarioId || selectedId) === scenario.id ? 'bg-blue-50/50' : 'hover:bg-blue-50 group disabled:opacity-50 disabled:cursor-not-allowed'
                }`}
              >
                <div className="flex items-start">
                  <div className="mt-0.5 mr-2 text-gray-400">
                    {isSelected ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5 group-hover:text-blue-500" />}
                  </div>
                  <div>
                    <span className={`font-medium block ${isSelected ? 'text-blue-700' : 'text-gray-900 group-hover:text-blue-700'}`}>
                      {scenario.label}
                    </span>
                    {!isSelected && (
                      <span className="text-sm text-gray-500 line-clamp-2 mt-1">{scenario.description}</span>
                    )}
                  </div>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${
                  scenario.category === 'Safe' ? 'bg-emerald-100 text-emerald-700' : 'bg-indigo-100 text-indigo-700'
                }`}>
                  {scenario.targetLayer}
                </span>
              </button>
                
                {isSelected && (
                  <div className="p-4 border-t border-gray-100 bg-white space-y-4 animate-in slide-in-from-top-2 fade-in duration-200">
                    <div>
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Target Defense Layer</h4>
                      <p className="text-sm font-medium text-indigo-700 bg-indigo-50 p-2 rounded border border-indigo-100">
                        {scenario.targetLayer} — {scenario.expectedDefense}
                      </p>
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Attack Payload</h4>
                      <pre className="bg-gray-900 text-green-400 p-3 rounded-md text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                        {scenario.attackPayload}
                      </pre>
                    </div>
                    
                    {result && !isRunning && (
                      <div className="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
                        <h4 className="text-xs font-bold text-gray-700 uppercase tracking-wider mb-3">Observed Result</h4>
                        
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="block text-gray-500 mb-1">Expected:</span>
                            <span className="font-medium text-gray-900">{scenario.targetLayer}</span>
                          </div>
                          
                          <div>
                            <span className="block text-gray-500 mb-1">Observed:</span>
                            <span className="font-medium text-gray-900">{result.stopping_layer} — {result.overall_decision}</span>
                          </div>
                        </div>

                        <div className="mt-3 pt-3 border-t border-gray-200">
                          <span className="block text-gray-500 mb-1 text-sm">Status:</span>
                          {isExpectedMatch ? (
                            <span className="inline-flex items-center text-sm font-medium text-emerald-600 bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200">
                              <CheckCircle2 className="w-4 h-4 mr-1.5" />
                              MATCH
                            </span>
                          ) : (
                            <span className="inline-flex items-center text-sm font-medium text-amber-600 bg-amber-50 px-2.5 py-1 rounded-md border border-amber-200">
                              <AlertCircle className="w-4 h-4 mr-1.5" />
                              DIFFERENT PATH
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                    
                      <div className="pt-2">
                        <button
                          onClick={() => onSelect(scenario.id)}
                          disabled={isRunning}
                          className="w-full flex items-center justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          <Play className="w-4 h-4 mr-2" />
                          Execute Attack
                        </button>
                      </div>
                  </div>
                )}
              </div>
            );
          })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
