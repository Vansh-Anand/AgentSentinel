import { useEffect, useState } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { checkHealth } from '../../api/client';
import { MessageSquare, ListChecks, FlaskConical, Settings2, ShieldCheck, ArrowUpRight } from 'lucide-react';

const navigation = [
  { name: 'Chat', href: '/lab', icon: MessageSquare },
  { name: 'Run details', href: '/evidence', icon: ListChecks },
  { name: 'Evaluation', href: '/experiments', icon: FlaskConical },
];
export function AppShell() {
  const [status, setStatus] = useState('checking');
  const location = useLocation();
  useEffect(() => {
    let alive = true;
    async function check() { try { await checkHealth(); if (alive) setStatus('connected'); } catch { if (alive) setStatus('unavailable'); } }
    void check(); const timer = setInterval(() => void check(), 30000);
    return () => { alive = false; clearInterval(timer); };
  }, []);
  return <div className="sentinel-shell flex h-screen flex-col overflow-hidden lg:flex-row">
    <aside className="sentinel-sidebar flex shrink-0 flex-col border-b border-white/10 lg:w-56 lg:border-r lg:border-b-0">
      <Link to="/lab" className="flex h-16 items-center gap-3 px-5"><span className="grid h-9 w-9 place-items-center rounded-xl bg-cyan-400/10 text-cyan-300"><ShieldCheck size={23} /></span><span className="text-base font-bold tracking-tight text-white">AgentSentinel</span></Link>
      <p className="hidden px-5 pb-6 text-xs leading-5 text-slate-400 lg:block">AI incident assistant.<br />Every tool action accountable.</p>
      <nav aria-label="Main navigation" className="grid grid-cols-3 gap-1 p-2 lg:block lg:space-y-2 lg:px-3">{navigation.map(item => {
        const active = item.href === '/lab' ? location.pathname === '/' || location.pathname === '/lab' || location.pathname.startsWith('/playground/') : item.href === '/evidence' ? location.pathname === '/evidence' || location.pathname.startsWith('/runs/') : location.pathname === item.href;
        return <Link key={item.href} to={item.href} aria-current={active ? 'page' : undefined} className={`flex items-center justify-center gap-2 rounded-xl px-3 py-3 text-xs font-semibold transition-colors lg:justify-start lg:text-sm ${active ? 'bg-cyan-400/10 text-cyan-200' : 'text-slate-400 hover:bg-white/5 hover:text-white'}`}><item.icon size={18} />{item.name}</Link>;
      })}</nav>
      <div className="hidden flex-1 lg:block" />
      <details className="advanced-nav mx-3 mb-3 rounded-xl border border-white/10 p-3 text-xs text-slate-300"><summary className="flex cursor-pointer items-center gap-2 font-semibold"><Settings2 size={15} /> Advanced</summary><nav aria-label="Advanced navigation" className="mt-3 grid gap-3 pl-1"><Link to="/overview">Project overview</Link><Link to="/system">Provider & Windows status</Link><Link to="/lab/advanced">Policy probes & layer challenges</Link><Link to="/research">Historical research</Link><a href="https://github.com/Vansh-Anand/AgentSentinel" target="_blank" rel="noreferrer" className="flex gap-1">Source code <ArrowUpRight size={13} /></a></nav></details>
      <div className="hidden border-t border-white/10 px-5 py-4 text-[11px] text-slate-400 lg:block"><span className={`mr-2 inline-block h-1.5 w-1.5 rounded-full ${status === 'connected' ? 'bg-emerald-400' : status === 'unavailable' ? 'bg-rose-400' : 'bg-amber-300'}`} />{status === 'connected' ? 'Local API connected' : status === 'unavailable' ? 'Local API unavailable' : 'Connecting to local API'}</div>
    </aside>
    <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
      <header className="sentinel-topbar flex h-14 shrink-0 items-center justify-between border-b border-white/10 px-4 lg:px-8"><span className="text-xs font-semibold text-slate-200">{location.pathname.startsWith('/runs/') || location.pathname === '/evidence' ? 'Run details' : location.pathname === '/experiments' ? 'Evaluation' : location.pathname === '/' || location.pathname === '/lab' || location.pathname.startsWith('/playground/') ? 'Document workspace' : 'Advanced workspace'}</span><span className="text-[10px] text-slate-400">Local workspace · server-enforced permissions</span></header>
      <main className="min-h-0 flex-1 overflow-y-auto p-3 sm:p-6 lg:px-8"><div className="mx-auto max-w-6xl">{status === 'unavailable' && <div role="alert" className="product-alert mb-4">The local API is unavailable. Start the demo with scripts/start_faculty_demo.ps1. Saved views will reconnect when it is ready.</div>}<Outlet /></div></main>
    </div>
  </div>;
}
