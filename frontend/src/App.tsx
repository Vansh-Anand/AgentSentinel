
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { PipelinePage } from './pages/PipelinePage';
import { EvidencePage } from './pages/EvidencePage';
import { AgentChatPage } from './pages/AgentChatPage';
import { ExperimentsPage } from './pages/ExperimentsPage';
import { SystemStatusPage } from './pages/SystemStatusPage';
import { PortableSystemStatusPage } from './pages/PortableSystemStatusPage';
import { GatewayDemoPage } from './pages/GatewayDemoPage';
import { LiveLabPage } from './pages/LiveLabPage';
import { ResearchPage } from './pages/ResearchPage';
import { RunHistoryPage } from './pages/RunHistoryPage';
import { SecureLabPage, LabEvidencePage } from './pages/SecureLabPage';
import { PortablePlaygroundPage } from './pages/PortablePlaygroundPage';
import { LabEvaluationPage } from './pages/LabEvaluationPage';
import { ProductOverviewPage } from './pages/ProductOverviewPage';
import { AgentPlaygroundPage } from './pages/AgentPlaygroundPage';
import { RunResultsPage, RunTracePage } from './pages/RunViews';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<ProductOverviewPage />} />
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
    </BrowserRouter>
  );
}

export default App;
