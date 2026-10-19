import React, { useEffect, useState } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { checkHealth } from '../../api/client';
import { Shield, Database, FlaskConical, Server, CheckCircle2, AlertTriangle, Cpu, LayoutDashboard } from 'lucide-react';

const navigation = [
  { name: 'Overview', href: '/overview', icon: LayoutDashboard },
  { name: 'Playground', href: '/lab', icon: Shield },
  { name: 'Runs', href: '/evidence', icon: Database },
  { name: 'Evaluation', href: '/experiments', icon: FlaskConical },
];

export const AppShell: React.FC = () => {
  const [backendStatus, setBackendStatus] = useState<'checking' | 'connected' | 'unavailable'>('checking');
  const location = useLocation();
  const playground = location.pathname === '/' || location.pathname.startsWith('/overview') ||
    location.pathname === '/lab' || location.pathname.startsWith('/playground/') ||
    location.pathname.startsWith('/runs/') || location.pathname === '/evidence';

  useEffect(() => {
    const verifyConnection = async () => {
      try {
        await checkHealth();
        setBackendStatus('connected');
      } catch {
        setBackendStatus('unavailable');
      }
    };
    verifyConnection();
    
    // Check every 30 seconds
    const interval = setInterval(verifyConnection, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className={`flex h-screen flex-col bg-gray-50 overflow-hidden lg:flex-row ${playground ? 'sentinel-shell' : ''}`}>
      {/* Sidebar */}
      <div className="w-full bg-gray-900 text-white flex flex-col flex-shrink-0 lg:w-64">
        <div className="h-12 flex items-center px-4 border-b border-gray-800 lg:h-16 lg:px-6">
          <Cpu className="w-6 h-6 text-blue-500 mr-3" />
          <span className="font-bold text-lg tracking-tight">AgentSentinel</span>
        </div>
        <nav className="grid grid-cols-4 gap-1 px-2 py-2 lg:block lg:flex-1 lg:space-y-1 lg:overflow-y-auto lg:px-4 lg:py-6">
          {navigation.map((item) => {
            const isActive = (item.href === '/overview' && location.pathname === '/') ||
                            (item.href === '/lab' && location.pathname.startsWith('/playground/')) ||
                            (item.href === '/evidence' && location.pathname.startsWith('/runs/')) ||
                            location.pathname === item.href ||
                            (item.href !== '/' && location.pathname.startsWith(item.href));
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`flex min-w-0 items-center gap-2 px-2 py-2.5 text-xs font-medium rounded-md transition-colors lg:px-3 lg:text-sm ${
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <item.icon className={`h-4 w-4 flex-shrink-0 lg:h-5 lg:w-5 ${isActive ? 'text-white' : 'text-gray-400'}`} />
                {item.name}
              </Link>
            );
          })}
        </nav>
        <div className="hidden p-4 border-t border-gray-800 bg-gray-900 lg:block">
          <div className="flex items-center text-xs">
            {backendStatus === 'checking' && (
              <div className="flex items-center text-gray-400">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-pulse mr-2"></div>
                Checking connection...
              </div>
            )}
            {backendStatus === 'connected' && (
              <div className="flex items-center text-emerald-400">
                <CheckCircle2 className="w-4 h-4 mr-1.5" />
                Backend Connected
              </div>
            )}
            {backendStatus === 'unavailable' && (
              <div className="flex items-center text-red-400">
                <AlertTriangle className="w-4 h-4 mr-1.5" />
                Backend Unavailable
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header className={`h-14 bg-white border-b border-gray-200 flex items-center justify-between px-3 flex-shrink-0 lg:h-16 lg:px-6 ${playground ? 'sentinel-topbar' : ''}`}>
          <h1 className="text-lg font-semibold text-gray-800 lg:text-xl">
            {location.pathname === '/' ? 'Overview' : location.pathname.startsWith('/system') ? 'System status' : location.pathname.startsWith('/runs/') ? 'Run inspection' : location.pathname.startsWith('/playground/') ? 'Playground' : navigation.find(n => location.pathname === n.href || location.pathname.startsWith(`${n.href}/`))?.name || 'Research'}
          </h1>
          <Link to="/system" aria-label="System status" className="flex items-center gap-2 rounded-lg px-2 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-100"><Server size={15} /> <span className="hidden sm:inline">System status</span></Link>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-3 sm:p-6">
          <div className="mx-auto max-w-7xl min-w-0">
            {backendStatus === 'unavailable' ? (
              <div className="bg-red-50 border border-red-200 text-red-800 rounded-lg p-6 flex flex-col items-center justify-center text-center mt-12">
                <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
                <h2 className="text-xl font-semibold mb-2">Backend Services Unavailable</h2>
                <p className="max-w-md text-red-700">
                  The AgentSentinel API server could not be reached. Ensure the FastAPI backend is running and the VITE_API_BASE_URL environment variable is configured correctly.
                </p>
              </div>
            ) : (
              <Outlet />
            )}
          </div>
        </main>
      </div>
    </div>
  );
};
