import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { rotateSecret, type OAuthClient, type RotateResponse } from '../api';

export function RotateSecretModal({
  client, onClose, onRotated,
}: { client: OAuthClient; onClose: () => void; onRotated: (resp: RotateResponse) => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const result = await rotateSecret(getAccessToken, client.client_id);
      onRotated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Rotate secret for {client.client_name}?</h2>
        <p style={{ color: 'var(--fg-muted)' }}>
          Rotating invalidates the current secret immediately. Any deployed app using the old secret will fail until you update it with the new one.
        </p>
        <p style={{ color: 'var(--fg-muted)' }}>
          You'll see the new secret only once on the next screen. Copy it before closing.
        </p>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button className="btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? 'Rotating…' : 'Rotate secret'}
          </button>
        </div>
      </div>
    </div>
  );
}
