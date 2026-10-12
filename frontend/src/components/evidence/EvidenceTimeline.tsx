import React, { useState } from 'react';
import type { ChainRecord } from '../../types/api';
import { ChevronRight, Download } from 'lucide-react';

interface EvidenceTimelineProps {
  chain: ChainRecord[];
  isHashChainValid?: boolean;
}

export const EvidenceTimeline: React.FC<EvidenceTimelineProps> = ({ chain, isHashChainValid }) => {
  const [selectedRecordIndex, setSelectedRecordIndex] = useState<number | null>(0);

  if (chain.length === 0) {
    return (
      <div className="bg-gray-50 border border-dashed border-gray-300 rounded-lg p-6 text-center text-gray-500">
        This session contains no evidence records.
      </div>
    );
  }

  const selectedRecord = selectedRecordIndex !== null ? chain[selectedRecordIndex] : null;

  const truncateHash = (hash: string) => {
    if (!hash || hash.length <= 16) return hash;
    return `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}`;
  };

  const handleExport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(chain, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `eces_evidence_${chain[0].timestamp_ns}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* TIMELINE COLUMN */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="flex justify-between items-center mb-6 border-b border-gray-100 pb-4">
          <h3 className="text-lg font-semibold text-gray-900">Hash Chain</h3>
          <button 
            onClick={handleExport}
            className="flex items-center space-x-1 text-sm text-blue-600 hover:text-blue-800 bg-blue-50 px-3 py-1 rounded"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON</span>
          </button>
        </div>

        <div className="space-y-0 relative">
          <div className="flex flex-col items-center">
            <div className="bg-gray-800 text-white text-xs font-mono px-3 py-1 rounded-full shadow-sm">
              GENESIS HASH
            </div>
          </div>
          
          <div className="flex justify-center py-2 h-10">
            <div className="w-0.5 h-full bg-gray-300"></div>
          </div>

          {chain.map((record, index) => (
            <React.Fragment key={record.sequence_number}>
              <div 
                className={`relative border rounded-lg p-4 cursor-pointer transition-all duration-200 ${
                  selectedRecordIndex === index 
                    ? 'border-blue-500 bg-blue-50 shadow-md ring-1 ring-blue-500 z-10' 
                    : 'border-gray-200 bg-white hover:border-blue-300'
                }`}
                onClick={() => setSelectedRecordIndex(index)}
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-1">
                      Seq {record.sequence_number} • {record.source_layer}
                    </div>
                    <div className="font-semibold text-gray-900">
                      {record.event_type}
                    </div>
                  </div>
                  {selectedRecordIndex === index && (
                    <ChevronRight className="w-5 h-5 text-blue-500" />
                  )}
                </div>
                
                <div className="mt-3 text-xs text-gray-500 space-y-1 font-mono">
                  <div className="flex items-center" title={record.previous_hash}>
                    <span className="text-gray-400 mr-2">Prev:</span>
                    <span className="truncate">{truncateHash(record.previous_hash)}</span>
                  </div>
                  <div className="flex items-center text-blue-700 font-semibold" title={record.event_hash}>
                    <span className="text-gray-400 font-normal mr-2">Hash:</span>
                    <span className="truncate">{truncateHash(record.event_hash)}</span>
                  </div>
                </div>
              </div>

              {index < chain.length - 1 && (
                <div className="flex justify-center py-2 h-10 relative">
                  <div className={`w-0.5 h-full ${isHashChainValid === false ? 'bg-red-400' : 'bg-gray-300'}`}></div>
                  {isHashChainValid === false && index === selectedRecordIndex && (
                    <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-red-100 text-red-600 text-[10px] font-bold px-2 py-0.5 rounded shadow whitespace-nowrap">
                      INTEGRITY FAILURE
                    </div>
                  )}
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* DETAIL COLUMN */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 h-fit sticky top-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-6 border-b border-gray-100 pb-4">Record Inspector</h3>
        
        {selectedRecord ? (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-xs text-gray-500 uppercase font-semibold">Sequence</div>
                <div className="font-mono text-gray-900">{selectedRecord.sequence_number}</div>
              </div>
              <div>
                <div className="text-xs text-gray-500 uppercase font-semibold">Layer</div>
                <div className="text-gray-900">{selectedRecord.source_layer}</div>
              </div>
              <div className="col-span-2">
                <div className="text-xs text-gray-500 uppercase font-semibold">Event ID</div>
                <div className="font-mono text-gray-900">{selectedRecord.event_id}</div>
              </div>
              <div className="col-span-2">
                <div className="text-xs text-gray-500 uppercase font-semibold">Timestamp</div>
                <div className="text-gray-900">{new Date(selectedRecord.timestamp_ns / 1_000_000).toISOString()}</div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs text-gray-500 uppercase font-semibold">Cryptographic Hashes</div>
              <div className="bg-gray-50 p-3 rounded border border-gray-200 overflow-x-auto text-xs font-mono space-y-2">
                <div>
                  <span className="text-gray-400 select-none">Previous: </span>
                  <span className="text-gray-700">{selectedRecord.previous_hash}</span>
                </div>
                <div>
                  <span className="text-gray-400 select-none">Current:  </span>
                  <span className="text-blue-700 font-semibold">{selectedRecord.event_hash}</span>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs text-gray-500 uppercase font-semibold flex justify-between">
                <span>Serialized Payload</span>
                <span className="text-[10px] text-blue-500 font-normal normal-case">Direct from SQLite</span>
              </div>
              <div className="bg-gray-900 rounded border border-gray-700 overflow-hidden">
                <pre className="p-4 text-[11px] text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedRecord.payload, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-gray-500 text-sm text-center py-12">
            Select a record from the timeline to inspect details.
          </div>
        )}
      </div>
    </div>
  );
};
