import { useEffect, useState } from 'react';
import { labDelete, labRequest } from '../../api/secureLab';

export type WorkspaceDocument = { id: string; name: string; bytes: number; sha256: string; source_id: string };

export function WorkspaceDocuments({ selected, onSelect, disabled }: {
  selected: string[]; onSelect: (ids: string[]) => void; disabled: boolean;
}) {
  const [documents, setDocuments] = useState<WorkspaceDocument[]>([]);
  const [error, setError] = useState('');
  const [uploading, setUploading] = useState(false);
  async function load() {
    const value = await labRequest<{ documents: WorkspaceDocument[] }>('/documents');
    setDocuments(value.documents);
  }
  useEffect(() => { void load().catch(cause => setError(cause.message)); }, []);
  async function upload(file?: File) {
    if (!file) return;
    setError(''); setUploading(true);
    try {
      if (file.size > 16384) throw new Error('Each document must be at most 16 KiB.');
      const content = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      const value = await labRequest<WorkspaceDocument>('/documents', { name: file.name, content });
      await load(); onSelect([...selected, value.id]);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Upload failed.'); }
    finally { setUploading(false); }
  }
  return <details className="mb-3 rounded-xl border border-white/10 p-3" open={documents.length > 0 || undefined}>
    <summary className="cursor-pointer text-xs font-semibold text-slate-200">Your documents · {selected.length} selected</summary>
    <p className="mt-2 text-[11px] leading-5 text-slate-400">UTF-8 .txt, .md, .csv · 16 KiB each · 16 documents / 128 KiB per local session. Each run keeps a versioned snapshot. Deleting an upload retains prior run snapshots; delete those conversations separately.</p>
    <label className="mt-3 block text-xs text-cyan-200">{uploading ? 'Uploading…' : 'Upload a document'}<input aria-label="Upload a document" type="file" accept=".txt,.md,.csv" disabled={disabled || uploading} className="mt-2 block w-full text-xs text-slate-300" onChange={event => { void upload(event.target.files?.[0]); event.target.value = ''; }} /></label>
    <div className="mt-3 space-y-2">{documents.map(document => <div key={document.id} className="flex items-center gap-2 text-xs text-slate-300"><label className="flex min-w-0 flex-1 items-center gap-2"><input type="checkbox" disabled={disabled} checked={selected.includes(document.id)} onChange={event => onSelect(event.target.checked ? [...selected, document.id] : selected.filter(id => id !== document.id))} /><span className="truncate" title={`${document.source_id} · SHA-256 ${document.sha256}`}>{document.name} · {document.bytes} bytes</span></label><button type="button" disabled={disabled} aria-label={`Delete ${document.name}`} className="text-slate-400 hover:text-rose-300" onClick={() => { void labDelete(`/documents/${document.id}`).then(() => { onSelect(selected.filter(id => id !== document.id)); return load(); }).catch(cause => setError(cause.message)); }}>Delete</button></div>)}</div>
    {error && <p role="alert" className="mt-2 text-xs text-rose-200">{error}</p>}
  </details>;
}
