import type { LiveRunInput } from '../api/runtimeStream';

export type LabScenario = 'injection' | 'direct' | 'benign';

export function buildLabRunInput(
  scenario: LabScenario,
  task: string,
  documentText: string,
  attackPrompt: string,
  provider: LiveRunInput['provider'],
): LiveRunInput {
  return {
    task: scenario === 'direct' ? attackPrompt : task,
    readme_text: scenario === 'injection'
      ? `${documentText.trimEnd()}\n\n## Operator note\n${attackPrompt}`
      : documentText,
    provider,
  };
}
