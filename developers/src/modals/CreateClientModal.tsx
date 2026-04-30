import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { registerClient, type RegisterResponse } from '../api';

const ALLOWED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

export function CreateClientModal({
  onClose, onCreated,
}: { onClose: () => void; onCreated: (resp: RegisterResponse) => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [name, setName] = useState('');
  const [redirectUris, setRedirectUris] = useState('');
  const [logoUri, setLogoUri] = useState('');
  const [scopes, setScopes] = useState<string[]>(['openid', 'profile', 'email']);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const result = await registerClient(getAccessToken, {
        client_name: name.trim(),
        redirect_uris: redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
        scope: scopes.join(' '),
        logo_uri: logoUri.trim() || undefined,
      });
      onCreated(result);
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
        <h2 className="modal-title">Register new OAuth client</h2>
        <div className="field">
          <label htmlFor="cc-name">Client name</label>
          <input id="cc-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </div>
        <div className="field">
          <label htmlFor="cc-uris">Redirect URIs (one per line)</label>
          <textarea id="cc-uris" value={redirectUris} onChange={(e) => setRedirectUris(e.target.value)} rows={3} />
        </div>
        <div className="field">
          <label htmlFor="cc-logo">Logo URL (optional)</label>
          <input id="cc-logo" value={logoUri} onChange={(e) => setLogoUri(e.target.value)} placeholder="https://example.com/logo.png" />
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
          <button
            className="btn-primary"
            onClick={submit}
            disabled={submitting || !name.trim() || !redirectUris.trim()}
          >
            {submitting ? 'Registering…' : 'Register'}
          </button>
        </div>
      </div>
    </div>
  );
}
