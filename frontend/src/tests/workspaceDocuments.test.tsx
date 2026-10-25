import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { WorkspaceDocuments } from '../components/lab/WorkspaceDocuments';
import { LayerResponsibilities } from '../components/lab/LayerResponsibilities';
import { labRequest } from '../api/secureLab';

vi.mock('../api/secureLab', () => ({ labRequest: vi.fn(), labDelete: vi.fn() }));

describe('Live document boundaries in the interface', () => {
  beforeEach(() => vi.clearAllMocks());
  it('shows only resources returned by the scoped API and selects opaque IDs', async () => {
    vi.mocked(labRequest).mockResolvedValue({ documents: [{ id: 'opaque-id', name: 'notes.md', bytes: 32, sha256: 'hash', source_id: 'SRC-OPAQUE' }] });
    const select = vi.fn();
    render(<WorkspaceDocuments selected={[]} onSelect={select} disabled={false} />);
    const checkbox = await screen.findByRole('checkbox');
    fireEvent.click(checkbox);
    expect(select).toHaveBeenCalledWith(['opaque-id']);
    expect(screen.getByText(/notes.md/)).toBeInTheDocument();
  });
  it('rejects oversized files before transmission', async () => {
    vi.mocked(labRequest).mockResolvedValue({ documents: [] });
    render(<WorkspaceDocuments selected={[]} onSelect={vi.fn()} disabled={false} />);
    fireEvent.change(screen.getByLabelText('Upload a document'), { target: { files: [new File(['x'.repeat(16385)], 'large.txt')] } });
    expect(await screen.findByRole('alert')).toHaveTextContent('16 KiB');
    await waitFor(() => expect(labRequest).toHaveBeenCalledTimes(1));
  });
  it('does not imply unrecorded layers passed', () => {
    render(<LayerResponsibilities events={[]} />);
    expect(screen.getAllByText('Not reached')).toHaveLength(7);
  });
});
