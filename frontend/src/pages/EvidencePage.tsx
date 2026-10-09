import React from 'react';
import { useEvidence } from '../hooks/useEvidence';
import { SessionList } from '../components/evidence/SessionList';
import { EvidenceTimeline } from '../components/evidence/EvidenceTimeline';
import { ChainVerificationPanel } from '../components/evidence/ChainVerificationPanel';
import { ErrorState } from '../components/common/ErrorState';
import { Database, Shield, CheckCircle } from 'lucide-react';

export const EvidencePage: React.FC = () => {
  const evidence = useEvidence();
  const [toastMessage, setToastMessage] = React.useState<string | null>(null);

  React.useEffect(() => {
    const handleNewSession = (e: Event) => {
      const customEvent = e as CustomEvent;
      setToastMessage(`New evidence session recorded — ${customEvent.detail}`);
      // Refresh the sessions list to show the new one
      evidence.refreshSessions();
      
      setTimeout(() => {
        setToastMessage(null);
      }, 3000);
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        evidence.refreshSessions();
      }
    };

    window.addEventListener('eces-new-session', handleNewSession);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      window.removeEventListener('eces-new-session', handleNewSession);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [evidence]);

  return (
    <div className="space-y-6 relative">
      {toastMessage && (
        <div className="fixed bottom-6 right-6 bg-gray-900 text-white px-6 py-4 rounded-lg shadow-2xl border border-gray-700 flex items-center animate-bounce z-50">
          <CheckCircle className="w-5 h-5 text-emerald-400 mr-3" />
          <span className="font-medium">{toastMessage}</span>
        </div>
      )}

      <div className="mb-8 flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 flex items-center">
            <Database className="w-6 h-6 mr-2 text-blue-600" />
            ECES Evidence Chain Inspector
          </h2>
          <p className="mt-2 text-gray-600">Inspect and cryptographically verify the append-only evidence chain.</p>
        </div>
        <button 
          onClick={evidence.refreshSessions}
          className="text-sm font-medium text-blue-600 hover:text-blue-800 transition-colors"
        >
          Refresh Sessions
        </button>
      </div>
      
      {evidence.sessionsError && (
        <ErrorState title="Failed to load sessions" message={evidence.sessionsError} className="mb-6" />
      )}

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        <div className="xl:col-span-1 space-y-6">
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Sessions</h3>
            <SessionList 
              sessions={evidence.sessions} 
              isLoading={evidence.sessionsLoading}
              activeSessionId={evidence.activeSessionId}
              onSelect={evidence.selectSession}
            />
          </div>
          
          <div className="bg-blue-50 p-6 rounded-lg border border-blue-100 text-sm text-blue-800 space-y-3">
            <div className="flex items-center font-semibold mb-1">
              <Shield className="w-4 h-4 mr-2" />
              Security Note
            </div>
            <p>
              The frontend does not perform cryptographic verification itself. Verification remains safely delegated to the backend ECES verification implementation.
            </p>
          </div>
        </div>

        <div className="xl:col-span-3 space-y-6">
          {evidence.activeSessionId ? (
            <>
              <ChainVerificationPanel 
                onVerify={evidence.triggerVerify}
                result={evidence.verifyResult}
                isLoading={evidence.verifyLoading}
                error={evidence.verifyError}
              />
              
              {evidence.detailError && (
                <ErrorState title="Failed to load chain" message={evidence.detailError} />
              )}
              
              {!evidence.detailError && evidence.sessionDetail && (
                <EvidenceTimeline 
                  chain={evidence.sessionDetail.chain} 
                  isVerified={evidence.verifyResult ? evidence.verifyResult.valid : undefined}
                />
              )}
              
              {evidence.detailLoading && (
                <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 flex justify-center items-center">
                  <div className="animate-pulse flex space-x-2 items-center text-gray-500">
                    <Database className="w-5 h-5" />
                    <span>Loading chain evidence...</span>
                  </div>
                </div>
              )}
            </>
          ) : evidence.sessions.length === 0 ? (
            <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 border-dashed flex flex-col items-center justify-center text-center h-full min-h-[400px]">
              <Database className="w-16 h-16 text-gray-300 mb-4" />
              <h3 className="text-lg font-medium text-gray-900">No Evidence Found</h3>
              <p className="mt-2 text-sm text-gray-500 max-w-sm">No evidence sessions yet. Run an attack scenario in the Security Pipeline to generate cryptographic evidence chains.</p>
            </div>
          ) : (
            <div className="bg-white p-12 rounded-lg shadow-sm border border-gray-200 border-dashed flex flex-col items-center justify-center text-center h-full min-h-[400px]">
              <Database className="w-16 h-16 text-gray-300 mb-4" />
              <h3 className="text-lg font-medium text-gray-900">No Session Selected</h3>
              <p className="mt-2 text-sm text-gray-500 max-w-sm">Select an evidence session from the left panel to inspect its cryptographic trace.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
