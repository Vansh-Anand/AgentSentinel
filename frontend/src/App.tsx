
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { PipelinePage } from './pages/PipelinePage';
import { EvidencePage } from './pages/EvidencePage';
import { AgentChatPage } from './pages/AgentChatPage';
import { ExperimentsPage } from './pages/ExperimentsPage';
import { SystemStatusPage } from './pages/SystemStatusPage';
import { GatewayDemoPage } from './pages/GatewayDemoPage';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="pipeline" element={<PipelinePage />} />
          <Route path="agent" element={<AgentChatPage />} />
          <Route path="gateway" element={<GatewayDemoPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="experiments" element={<ExperimentsPage />} />
          <Route path="system" element={<SystemStatusPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
