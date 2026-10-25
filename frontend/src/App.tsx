import { lazy, Suspense } from 'react';

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
const OverviewPage = lazy(() => import('./pages/OverviewPage').then(module => ({ default: module.OverviewPage })));
const PipelinePage = lazy(() => import('./pages/PipelinePage').then(module => ({ default: module.PipelinePage })));
const EvidencePage = lazy(() => import('./pages/EvidencePage').then(module => ({ default: module.EvidencePage })));
const AgentChatPage = lazy(() => import('./pages/AgentChatPage').then(module => ({ default: module.AgentChatPage })));
const ExperimentsPage = lazy(() => import('./pages/ExperimentsPage').then(module => ({ default: module.ExperimentsPage })));
const SystemStatusPage = lazy(() => import('./pages/SystemStatusPage').then(module => ({ default: module.SystemStatusPage })));
const PortableSystemStatusPage = lazy(() => import('./pages/PortableSystemStatusPage').then(module => ({ default: module.PortableSystemStatusPage })));
const GatewayDemoPage = lazy(() => import('./pages/GatewayDemoPage').then(module => ({ default: module.GatewayDemoPage })));
const LiveLabPage = lazy(() => import('./pages/LiveLabPage').then(module => ({ default: module.LiveLabPage })));
const ResearchPage = lazy(() => import('./pages/ResearchPage').then(module => ({ default: module.ResearchPage })));
const RunHistoryPage = lazy(() => import('./pages/RunHistoryPage').then(module => ({ default: module.RunHistoryPage })));
const SecureLabPage = lazy(() => import('./pages/SecureLabPage').then(module => ({ default: module.SecureLabPage })));
const LabEvidencePage = lazy(() => import('./pages/SecureLabPage').then(module => ({ default: module.LabEvidencePage })));
const PortablePlaygroundPage = lazy(() => import('./pages/PortablePlaygroundPage').then(module => ({ default: module.PortablePlaygroundPage })));
const LabEvaluationPage = lazy(() => import('./pages/LabEvaluationPage').then(module => ({ default: module.LabEvaluationPage })));
const ProductOverviewPage = lazy(() => import('./pages/ProductOverviewPage').then(module => ({ default: module.ProductOverviewPage })));
import { AgentPlaygroundPage } from './pages/AgentPlaygroundPage';
const RunResultsPage = lazy(() => import('./pages/RunViews').then(module => ({ default: module.RunResultsPage })));
const RunTracePage = lazy(() => import('./pages/RunViews').then(module => ({ default: module.RunTracePage })));

function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<p role="status" className="p-6 text-sm">Loading workspace…</p>}>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<AgentPlaygroundPage />} />
          <Route path="lab" element={<AgentPlaygroundPage />} />
          <Route path="playground/:conversationId" element={<AgentPlaygroundPage />} />
          <Route path="lab/advanced" element={<PortablePlaygroundPage />} />
          <Route path="lab/previous" element={<SecureLabPage />} />
          <Route path="lab/classic" element={<LiveLabPage />} />
          <Route path="overview" element={<ProductOverviewPage />} />
          <Route path="overview/classic" element={<OverviewPage />} />
          <Route path="runs/:runId/trace" element={<RunTracePage />} />
          <Route path="runs/:runId/results" element={<RunResultsPage />} />
          <Route path="research" element={<ResearchPage />} />
          <Route path="pipeline" element={<PipelinePage />} />
          <Route path="agent" element={<AgentChatPage />} />
          <Route path="gateway" element={<Navigate to="/lab" replace />} />
          <Route path="gateway-classic" element={<GatewayDemoPage />} />
          <Route path="evidence" element={<LabEvidencePage />} />
          <Route path="evidence/classic" element={<RunHistoryPage />} />
          <Route path="evidence/research" element={<EvidencePage />} />
          <Route path="experiments" element={<LabEvaluationPage />} />
          <Route path="experiments/classic" element={<ExperimentsPage />} />
          <Route path="system" element={<PortableSystemStatusPage />} />
          <Route path="system/classic" element={<SystemStatusPage />} />
        </Route>
      </Routes>
    </Suspense>
    </BrowserRouter>
  );
}

export default App;
