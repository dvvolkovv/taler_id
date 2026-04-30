import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { deleteClient, type OAuthClient } from '../api';

export function DeleteClientModal({
  client, onClose, onDeleted,
}: { client: OAuthClient; onClose: () => void; onDeleted: () => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [confirmText, setConfirmText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await deleteClient(getAccessToken, client.client_id);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Delete {client.client_name}?</h2>
        <p style={{ color: 'var(--fg-muted)' }}>
          This permanently deletes the OAuth client. Any deployed integration using <code>{client.client_id}</code> will immediately stop working.
        </p>
        <div className="field">
          <label htmlFor="del-conf">Type the client name to confirm: <code>{client.client_name}</code></label>
          <input id="del-conf" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} />
        </div>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="btn-danger" onClick={submit} disabled={submitting || confirmText !== client.client_name}>
            {submitting ? 'Deleting…' : 'Delete forever'}
          </button>
        </div>
      </div>
    </div>
  );
}
