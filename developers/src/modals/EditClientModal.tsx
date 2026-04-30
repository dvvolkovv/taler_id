import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { updateClient, type OAuthClient } from '../api';

const ALLOWED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

export function EditClientModal({
  client, onClose, onSaved,
}: { client: OAuthClient; onClose: () => void; onSaved: () => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [name, setName] = useState(client.client_name);
  const [redirectUris, setRedirectUris] = useState(client.redirect_uris.join('\n'));
  const [logoUri, setLogoUri] = useState(client.logo_uri ?? '');
  const [scopes, setScopes] = useState<string[]>(client.scope.split(' ').filter(Boolean));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await updateClient(getAccessToken, client.client_id, {
        client_name: name.trim(),
        redirect_uris: redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
        scope: scopes.join(' '),
        logo_uri: logoUri.trim() || undefined,
      });
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleScope = (s: string) => {
    setScopes((cur) => cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]);
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Edit {client.client_name}</h2>
        <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 16 }}>
          Client ID: <code>{client.client_id}</code>
        </div>
        <div className="field">
          <label htmlFor="ec-name">Client name</label>
          <input id="ec-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </div>
        <div className="field">
          <label htmlFor="ec-uris">Redirect URIs (one per line)</label>
          <textarea id="ec-uris" value={redirectUris} onChange={(e) => setRedirectUris(e.target.value)} rows={3} />
        </div>
        <div className="field">
          <label htmlFor="ec-logo">Logo URL (optional)</label>
          <input id="ec-logo" value={logoUri} onChange={(e) => setLogoUri(e.target.value)} />
        </div>
        <div className="field">
          <label>Scopes</label>
          {ALLOWED_SCOPES.map((s) => (
            <label key={s} style={{ display: 'inline-flex', alignItems: 'center', marginRight: 12, fontSize: 13 }}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} />
              <code style={{ marginLeft: 4 }}>{s}</code>
            </label>
          ))}
        </div>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
