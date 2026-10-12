import React from 'react';
import type { VerifyResponse } from '../../types/api';
import { ShieldCheck, ShieldAlert, Loader2, Play } from 'lucide-react';

interface ChainVerificationPanelProps {
  onVerify: () => void;
  result: VerifyResponse | null;
  isLoading: boolean;
  error: string | null;
}

export const ChainVerificationPanel: React.FC<ChainVerificationPanelProps> = ({ onVerify, result, isLoading, error }) => {
  const hashesOnly = Boolean(result?.hash_chain_valid && !result.valid);
  const resultColor = result?.valid ? 'emerald' : hashesOnly ? 'amber' : 'red';
  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold text-gray-900">Chain Verification</h3>
        <button
          onClick={onVerify}
          disabled={isLoading}
          className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded font-medium disabled:opacity-50 transition-colors"
        >
          {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          <span>Verify Chain</span>
        </button>
      </div>
      
      <p className="text-sm text-gray-600 mb-6">
        Checks the global hash chain from genesis through all records. Signature authentication is reported separately when a trusted public key is available.
      </p>

      {error && (
        <div className="bg-red-50 text-red-700 p-4 rounded-lg border border-red-200 text-sm">
          Chain verification is currently unavailable. {error}
        </div>
      )}

      {result && (
        <div className={`p-6 rounded-lg border ${resultColor === 'emerald' ? 'bg-emerald-50 border-emerald-200' : resultColor === 'amber' ? 'bg-amber-50 border-amber-200' : 'bg-red-50 border-red-200'}`}>
          <div className="flex items-center space-x-4 mb-4">
            {result.valid ? (
              <ShieldCheck className="w-10 h-10 text-emerald-500" />
            ) : (
              <ShieldAlert className={`w-10 h-10 ${hashesOnly ? 'text-amber-500' : 'text-red-500'}`} />
            )}
            <div>
              <h4 className={`text-xl font-bold uppercase tracking-wider ${resultColor === 'emerald' ? 'text-emerald-700' : resultColor === 'amber' ? 'text-amber-700' : 'text-red-700'}`}>
                {result.valid ? 'Chain Verified' : hashesOnly ? 'Hash chain intact; signatures unverified' : 'Chain Integrity Failure'}
              </h4>
              <p className={`text-sm ${resultColor === 'emerald' ? 'text-emerald-600' : resultColor === 'amber' ? 'text-amber-700' : 'text-red-600'}`}>
                {result.valid 
                  ? 'Hash links and record signatures verified against a trusted key.'
                  : hashesOnly
                    ? 'Hash links match, but the research replay did not retain the signing public keys. This is a structural integrity check only.'
                    : `Verification failed. Reason: ${result.failure || 'UNKNOWN'}`}
              </p>
            </div>
          </div>
          
          <div className={`text-sm font-mono p-3 rounded ${resultColor === 'emerald' ? 'bg-emerald-100 text-emerald-800' : resultColor === 'amber' ? 'bg-amber-100 text-amber-800' : 'bg-red-100 text-red-800'}`}>
            Records Checked: {result.records_checked} · Signature status: {result.signature_status || 'UNKNOWN'}
          </div>
        </div>
      )}
      
      {!result && !error && !isLoading && (
        <div className="bg-gray-50 border border-gray-200 rounded p-4 text-center text-sm text-gray-500">
          Click "Verify Chain" to check hash links and report signature status.
        </div>
      )}
    </div>
  );
};
