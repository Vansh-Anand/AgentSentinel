import { ArrowRight, Check, Circle, LoaderCircle, ShieldAlert } from 'lucide-react';
import type { LabEvent, LabResult } from '../../api/secureLab';

type State = 'recorded' | 'blocked' | 'waiting' | 'active';
type Stage = { title: string; detail: string; state: State };

// States come only from recorded events or terminal receipts, never elapsed UI time.
export function actionStory(events: LabEvent[], result?: LabResult | null, busy = false): Stage[] {
  const actionId = events.filter(event => event.action_id).at(-1)?.action_id;
  const scoped = actionId ? events.filter(event => event.action_id === actionId) : events;
  const proposal = scoped.filter(event => event.type === 'tool_proposed').at(-1);
  const receipt = result?.steps?.find(step => step.request_id === actionId)
    ?? (!actionId ? result?.steps?.at(-1) : undefined);
  const denied = scoped.find(event => event.type === 'layer_completed' && ['DENY', 'STOP'].includes(String(event.data.decision)));
  const dispatch = scoped.some(event => event.type === 'dispatch_authorized');
  const execution = scoped.find(event => event.type === 'execution_finished');
  const invoked = receipt?.executor_invoked ?? (execution ? execution.data.executor_invoked === true : undefined);
  const completed = receipt?.completed ?? (execution ? execution.data.completed === true : false);
  const verified = result?.verification?.valid === true;
  return [
    { title: 'Request', detail: events.length || result ? 'Received by server' : 'Waiting for your prompt', state: events.length || result ? 'recorded' : busy ? 'active' : 'waiting' },
    { title: 'Proposed tool', detail: proposal ? String(proposal.data.tool) : receipt?.tool ?? 'No proposal recorded', state: proposal || receipt ? 'recorded' : busy && !denied ? 'active' : 'waiting' },
    { title: 'Security decision', detail: denied ? `${denied.layer} · ${String(denied.data.reason).replaceAll('_', ' ')}` : receipt?.decision === 'DENY' ? receipt.reason.replaceAll('_', ' ') : dispatch || receipt?.decision === 'ALLOW' ? 'Dispatch authorized' : result ? 'No tool decision recorded' : 'Waiting for checks', state: denied || receipt?.decision === 'DENY' ? 'blocked' : dispatch || receipt ? 'recorded' : proposal && busy ? 'active' : 'waiting' },
    { title: 'Execution', detail: invoked === false ? 'Executor not invoked' : invoked ? completed ? 'Operation completed' : 'Started; operation incomplete' : 'No execution receipt', state: invoked ? completed ? 'recorded' : 'blocked' : 'waiting' },
    { title: 'Evidence', detail: verified ? 'Signed run receipt recorded' : result ? 'Not verified' : 'Awaiting final receipt', state: verified ? 'recorded' : 'waiting' },
  ];
}

export function ActionStory({ events = [], result, busy = false }: { events?: LabEvent[]; result?: LabResult | null; busy?: boolean }) {
  return <ol aria-label="Action journey" className="action-story">{actionStory(events, result, busy).map((stage, index) => <li key={stage.title} className={`action-stage action-stage-${stage.state}`}>
    <div className="flex items-center gap-2"><span className="action-stage-icon">{stage.state === 'blocked' ? <ShieldAlert size={14} /> : stage.state === 'recorded' ? <Check size={14} /> : stage.state === 'active' ? <LoaderCircle size={14} className="animate-spin" /> : <Circle size={12} />}</span><span className="text-xs font-semibold">{stage.title}</span>{index < 4 && <ArrowRight size={12} className="ml-auto text-slate-500" />}</div>
    <p className="mt-2 text-[11px] leading-5">{stage.detail}</p>
  </li>)}</ol>;
}

export function policyExplanation(reason: string) {
  const explanations: Record<string, string> = {
    CAPABILITY_NOT_GRANTED: 'The selected policy does not grant this tool. The model cannot expand that permission.',
    INVALID_PATH: 'The requested path is malformed or tries to leave the permitted workspace.',
    PATH_OUT_OF_SCOPE: 'This file is outside the server’s permitted document set. A prompt or attachment cannot expand that permission.',
    TOOL_NOT_ALLOWED: 'This tool is not included in the selected policy. The model cannot grant itself access.',
    TOOL_NOT_AUTHORIZED: 'This tool is not included in the selected policy. The model cannot grant itself access.',
    COMMAND_EXECUTION_DISABLED: 'Shell execution is outside this agent’s permitted tools.',
    NETWORK_EXECUTION_DISABLED: 'Outbound network execution is outside this agent’s permitted tools.',
    RESTRICTED_SOURCE_EXPORT_DENIED: 'Information from a restricted source cannot be copied into the local ticket destination.',
    UNOBSERVED_SOURCE_CITATION: 'The proposed artifact cites a source that this run has not read or searched.',
    APPROVAL_DECLINED: 'The owner declined the proposed write action.',
    APPROVAL_EXPIRED: 'The exact action did not receive approval before its deadline.',
    REPEATED_IDENTICAL_PROPOSAL: 'The repeated-action limit stopped another identical proposal.',
    TOOL_CALL_BUDGET: 'The run exhausted its tool-call budget.',
    EXPONENT_LIMIT: 'The calculator rejected an exponent outside its configured resource limit. No calculation result was released.',
    BOUNDED_EXECUTOR_REJECTED: 'The authorized tool reached an application execution limit.',
  };
  return explanations[reason] ?? `Recorded rule: ${reason.replaceAll('_', ' ').toLowerCase()}. Inspect the technical trace for the check’s details.`;
}
