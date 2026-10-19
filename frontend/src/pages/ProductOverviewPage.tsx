import { Link } from 'react-router-dom';
import { ArrowRight, FileSearch, LockKeyhole, ScanEye, ShieldCheck } from 'lucide-react';

const cards = [
  { icon: FileSearch, title: 'Useful work', body: 'Ask the agent to investigate synthetic incidents, calculate a result, or draft a cited local report.', to: '/lab' },
  { icon: LockKeyhole, title: 'Attack the boundary', body: 'Try an unauthorized request or hide instructions in lower-trust document text.', to: '/lab' },
  { icon: ScanEye, title: 'Inspect the proof', body: 'Open each action trace, inspect observed effects, and verify its signed run receipt.', to: '/evidence' },
];

export function ProductOverviewPage() {
  return <div className="product-page space-y-8 pb-12">
    <section className="product-hero relative overflow-hidden rounded-3xl border border-cyan-400/20 p-7 sm:p-12">
      <div className="relative z-10 max-w-3xl">
        <p className="product-eyebrow">AGENTSENTINEL / LOCAL SECURITY LAB</p>
        <h2 className="mt-5 text-4xl font-bold tracking-tight text-white sm:text-6xl">See the action.<br /><span className="text-cyan-300">Understand the decision.</span></h2>
        <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300">Give an AI agent a task or a suspicious instruction. AgentSentinel checks each proposed tool action against server-owned permissions and records what actually happened.</p>
        <div className="mt-7 flex flex-wrap gap-3"><Link to="/lab" className="product-primary">Open the playground <ArrowRight size={16} /></Link><Link to="/evidence" className="product-secondary">Browse saved runs</Link></div>
      </div>
      <div className="product-orbit" aria-hidden="true"><ShieldCheck size={110} strokeWidth={1} /></div>
    </section>
    <div className="grid gap-4 md:grid-cols-3">{cards.map(card => <Link key={card.title} to={card.to} className="product-card group p-6"><card.icon className="text-cyan-300" size={24} /><h3 className="mt-5 text-lg font-semibold text-white">{card.title}</h3><p className="mt-2 text-sm leading-6 text-slate-300">{card.body}</p><span className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-cyan-300 group-hover:gap-3">Explore <ArrowRight size={15} /></span></Link>)}</div>
    <section className="product-card p-6"><div className="flex flex-wrap items-center justify-between gap-4"><div><p className="product-eyebrow">THE SECURITY MODEL</p><h3 className="mt-2 text-xl font-semibold text-white">A real decision for each proposed action</h3></div><Link to="/lab" className="text-sm font-semibold text-cyan-300 hover:underline">Try a custom prompt →</Link></div><div className="mt-6 grid gap-3 text-sm sm:grid-cols-3"><div className="product-step">01 <strong>Agent proposes</strong><span>Structured tool and arguments</span></div><div className="product-step">02 <strong>Gateway checks</strong><span>Scope, sequence, approval, audit</span></div><div className="product-step">03 <strong>Result is recorded</strong><span>Executor, effects, signed evidence</span></div></div><p className="mt-5 text-xs leading-5 text-slate-400">The portable lab uses synthetic documents and application-level effects. On Windows, a verified Job worker can be observed by ETW when the elevated broker is active; inspect each run for actual coverage. Source integrity is software measurement, not TPM attestation.</p></section>
  </div>;
}
