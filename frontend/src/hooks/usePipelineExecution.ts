import { useState, useCallback, useEffect } from 'react';
import { runPipelineScenario } from '../api/pipeline';
import type { PipelineRunResponse } from '../types/api';
import type { LayerState } from '../types/pipeline';

interface PipelineDisplayState {
  L1: LayerState;
  L2: LayerState;
  L3: LayerState;
  L4: LayerState;
  L5: LayerState;
  L6: LayerState;
  L7: LayerState;
}

const INITIAL_LAYER_STATE: PipelineDisplayState = {
  L1: 'PENDING',
  L2: 'PENDING',
  L3: 'PENDING',
  L4: 'PENDING',
  L5: 'PENDING',
  L6: 'PENDING',
  L7: 'PENDING',
};

export const usePipelineExecution = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PipelineRunResponse | null>(null);
  const [layerStates, setLayerStates] = useState<PipelineDisplayState>(INITIAL_LAYER_STATE);
  const [currentLayer, setCurrentLayer] = useState<string | null>(null);
  const [selectedLayerId, setSelectedLayerId] = useState<string | null>(null);
  const [pendingResult, setPendingResult] = useState<PipelineRunResponse | null>(null);
  const [executionId, setExecutionId] = useState<number>(0);

  const executeScenario = useCallback(async (scenarioId: string) => {
    setIsRunning(true);
    setError(null);
    setResult(null);
    setPendingResult(null);
    setLayerStates({ ...INITIAL_LAYER_STATE });
    setCurrentLayer(null);
    setSelectedLayerId(null);
    setExecutionId(Date.now()); // Unique ID for this execution

    try {
      // 1. Fetch synchronous response from backend
      const response = await runPipelineScenario(scenarioId);
      setPendingResult(response);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'An error occurred during pipeline execution.');
      setLayerStates({ ...INITIAL_LAYER_STATE });
      setCurrentLayer(null);
      setSelectedLayerId(null);
      setIsRunning(false);
    }
  }, []);

  useEffect(() => {
    if (!pendingResult) return;

    let timeoutId: ReturnType<typeof setTimeout>;
    let stopped = false;
    let currentIdx = 0;
    const layers: Array<keyof PipelineRunResponse> = ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7'];

    const animateLayer = () => {
      if (stopped || currentIdx >= layers.length) {
        setResult(pendingResult);
        setCurrentLayer(null);
        if (pendingResult.overall_decision === 'ALLOW') {
          setSelectedLayerId('L5');
        } else {
          setSelectedLayerId(pendingResult.stopping_layer);
        }
        setIsRunning(false);
        setPendingResult(null);
        return;
      }

      const layerKey = layers[currentIdx] as keyof PipelineDisplayState;
      setCurrentLayer(layerKey);
      setLayerStates(prev => ({ ...prev, [layerKey]: 'PROCESSING' }));

      timeoutId = setTimeout(() => {
        if (stopped) return;

        let finalState: LayerState = 'UNAVAILABLE';
        const outcome: any = pendingResult[layerKey];

        if (layerKey === 'L1' || layerKey === 'L2') {
          if (!outcome || !outcome.decision) finalState = 'UNAVAILABLE';
          else finalState = outcome.decision;
        } else if (layerKey === 'L3' || layerKey === 'L4') {
            finalState = outcome ? (pendingResult.stopping_layer === layerKey && pendingResult.overall_decision === 'BLOCK' ? 'BLOCK' : 'ALLOW') : 'UNAVAILABLE';
        } else if (layerKey === 'L5') {
            finalState = outcome?.governance_state || 'UNAVAILABLE';
        } else if (layerKey === 'L6') {
            finalState = outcome?.chain_status === 'TAMPERED' ? 'BLOCK' : outcome?.chain_status === 'APPENDED' ? 'ALLOW' : 'UNAVAILABLE';
        } else if (layerKey === 'L7') {
            finalState = outcome?.isolation_status === 'UNAVAILABLE' ? 'UNAVAILABLE' : 'ALLOW';
        }

        setLayerStates((prev) => ({ ...prev, [layerKey]: finalState }));

        if (finalState === 'BLOCK' || finalState === 'FREEZE') {
          stopped = true;
          setLayerStates(prev => {
            const next = { ...prev };
            for (let i = currentIdx + 1; i < layers.length; i++) {
              next[layers[i] as keyof PipelineDisplayState] = 'SKIPPED';
            }
            return next;
          });
        }
        
        currentIdx++;
        if (!stopped && currentIdx < layers.length) {
          timeoutId = setTimeout(animateLayer, 0); // Immediately start next layer's PROCESSING state
        } else {
          // If stopped or finished, wait 500ms before showing verdict banner
          timeoutId = setTimeout(() => {
            setResult(pendingResult);
            setCurrentLayer(null);
            if (pendingResult.overall_decision === 'ALLOW') {
              setSelectedLayerId('L5');
            } else {
              setSelectedLayerId(pendingResult.stopping_layer);
            }
            setIsRunning(false);
            setPendingResult(null);
          }, 500);
        }
      }, 600);
    };

    animateLayer();

    return () => {
      clearTimeout(timeoutId);
    };
  }, [pendingResult, executionId]);

  const reset = useCallback(() => {
    setIsRunning(false);
    setError(null);
    setResult(null);
    setPendingResult(null);
    setLayerStates({ ...INITIAL_LAYER_STATE });
    setCurrentLayer(null);
    setSelectedLayerId(null);
    setExecutionId(prev => prev + 1); // Cancel ongoing animation
  }, []);

  return {
    isRunning,
    error,
    result, // Only populated when animation finishes
    layerStates,
    currentLayer,
    selectedLayerId,
    setSelectedLayerId,
    executeScenario,
    reset,
    pendingResult // Useful to get metric values during animation
  };
};
