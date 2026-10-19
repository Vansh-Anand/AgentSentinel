import { Link } from 'react-router-dom';
import { ArrowRight, BarChart3, FlaskConical, Layers3, Server } from 'lucide-react';

const resources = [
  { title: 'Saved experiments', description: 'Benchmark tables, plots, datasets, and evidence modes. These are historical results, not today\'s live run.', href: '/experiments', icon: BarChart3 },
  { title: 'Seven-layer challenge lab', description: 'Edit layer inputs and compare real gateway checks with research replay checks. Each result states its proof level.', href: '/pipeline', icon: Layers3 },
  { title: 'Research agent replay', description: 'An earlier conversation view that visualizes the research pipeline. Some outcomes are simulated.', href: '/agent', icon: FlaskConical },
  { title: 'Advanced gateway fixtures', description: 'Restricted Docker command fixture and the original detailed gateway view.', href: '/gateway-classic', icon: Server },
];

export function ResearchPage() {
  return <div className="space-y-6">
    <header className="rounded-2xl bg-slate-950 p-7 text-white"><p className="text-xs font-bold uppercase tracking-[0.18em] text-cyan-300">Technical appendix</p><h1 className="mt-2 text-3xl font-bold">Research and advanced demonstrations</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">The Live Lab is the primary tool-governed agent experience. The material here provides saved experiments, editable research checks, and advanced fixtures. Follow the execution-mode label on each result.</p></header>
    <div className="grid gap-4 md:grid-cols-2">{resources.map(resource => <Link key={resource.href} to={resource.href} className="group rounded-2xl border border-slate-200 bg-white p-5 shadow-sm hover:border-blue-300 hover:shadow-md"><resource.icon className="h-6 w-6 text-blue-700" /><h2 className="mt-3 text-lg font-bold text-slate-950">{resource.title}</h2><p className="mt-1 text-sm leading-6 text-slate-600">{resource.description}</p><span className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-blue-800">Open <ArrowRight className="h-4 w-4" /></span></Link>)}</div>
  </div>;
}
