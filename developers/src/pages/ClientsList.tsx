import { useEffect, useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { listClients, type OAuthClient } from '../api';
import { CreateClientModal } from '../modals/CreateClientModal';
import { EditClientModal } from '../modals/EditClientModal';
import { DeleteClientModal } from '../modals/DeleteClientModal';
import { RotateSecretModal } from '../modals/RotateSecretModal';
import { SecretRevealModal } from '../modals/SecretRevealModal';

export function ClientsList() {
  const { user, logout, getAccessToken } = useTalerIdAuth();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<OAuthClient | null>(null);
  const [deleting, setDeleting] = useState<OAuthClient | null>(null);
  const [rotating, setRotating] = useState<OAuthClient | null>(null);
  const [secret, setSecret] = useState<{ client_id: string; client_secret: string } | null>(null);

  const refresh = async () => {
    try {
      const data = await listClients(getAccessToken);
      setClients(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load clients');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const formatRelative = (issuedAt: number) => {
    const ago = Math.floor((Date.now() / 1000) - issuedAt);
    if (ago < 60) return 'just now';
    if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
    if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
    return `${Math.floor(ago / 86400)} days ago`;
  };

  return (
    <div style={{ minHeight: '100vh' }}>
      <div style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)', padding: '16px 24px' }}>
        <div style={{ maxWidth: 960, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <strong style={{ fontSize: 16 }}>Taler ID — Developer Portal</strong>
          <div style={{ fontSize: 13, color: 'var(--fg-muted)' }}>
            <span style={{ marginRight: 16 }}>{(user?.email as string) ?? user?.sub}</span>
            <button className="btn-secondary" onClick={() => logout({ returnTo: window.location.origin + '/developers/' })}>Logout</button>
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: '0 auto', padding: '32px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 22 }}>Your OAuth clients</h1>
            <p style={{ color: 'var(--fg-muted)', marginTop: 4, marginBottom: 0, fontSize: 13 }}>
              {clients.length} of 10 used. Email-verified accounts only.
            </p>
          </div>
          <button className="btn-primary" onClick={() => setCreateOpen(true)}>+ Register new client</button>
        </div>

        {loading && <div style={{ color: 'var(--fg-muted)' }}>Loading…</div>}
        {error && <div style={{ color: 'var(--danger)', padding: 12, background: 'var(--bg-elevated)', borderRadius: 6 }}>{error}</div>}

        {!loading && !error && clients.length === 0 && (
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: 32, textAlign: 'center' }}>
            <p style={{ marginTop: 0 }}>No OAuth clients yet.</p>
            <button className="btn-primary" onClick={() => setCreateOpen(true)}>Register your first client</button>
          </div>
        )}

        {!loading && clients.length > 0 && (
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr 1fr 160px', gap: 12, padding: '12px 16px', background: 'var(--bg-deep)', fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              <div>Name</div><div>Client ID</div><div>Redirect URIs</div><div>Created</div><div>Actions</div>
            </div>
            {clients.map((c) => (
              <ClientRow
                key={c.client_id}
                client={c}
                formatRelative={formatRelative}
                onEdit={() => setEditing(c)}
                onDelete={() => setDeleting(c)}
                onRotate={() => setRotating(c)}
              />
            ))}
          </div>
        )}

        <div style={{ marginTop: 32, padding: 16, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13, color: 'var(--fg-muted)' }}>
          <strong style={{ color: 'var(--fg)' }}>Need help integrating?</strong>
          {' '}
          <a href="/oauth-guide.html">Integration guide →</a>
          {' · '}
          <a href="/brand">Brand assets →</a>
          {' · '}
          <a href="https://www.npmjs.com/package/@taler-id/oauth-client" target="_blank" rel="noopener">JS SDK →</a>
          {' · '}
          <a href="https://pub.dev/packages/talerid_oauth" target="_blank" rel="noopener">Flutter SDK →</a>
        </div>
      </div>

      {createOpen && (
        <CreateClientModal
          onClose={() => setCreateOpen(false)}
          onCreated={(secret) => { setCreateOpen(false); setSecret(secret); refresh(); }}
        />
      )}
      {editing && (
        <EditClientModal client={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />
      )}
      {deleting && (
        <DeleteClientModal client={deleting} onClose={() => setDeleting(null)} onDeleted={() => { setDeleting(null); refresh(); }} />
      )}
      {rotating && (
        <RotateSecretModal
          client={rotating}
          onClose={() => setRotating(null)}
          onRotated={(secret) => { setRotating(null); setSecret(secret); }}
        />
      )}
      {secret && (
        <SecretRevealModal
          clientId={secret.client_id}
          clientSecret={secret.client_secret}
          onClose={() => setSecret(null)}
        />
      )}
    </div>
  );
}

function ClientRow({
  client, formatRelative, onEdit, onDelete, onRotate,
}: {
  client: OAuthClient;
  formatRelative: (n: number) => string;
  onEdit: () => void;
  onDelete: () => void;
  onRotate: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr 1fr 160px', gap: 12, padding: '14px 16px', borderTop: '1px solid var(--border)', alignItems: 'center', fontSize: 13, position: 'relative' }}>
      <div><strong>{client.client_name}</strong></div>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--fg-muted)' }}>{client.client_id}</div>
      <div style={{ color: 'var(--fg-muted)' }}>{client.redirect_uris.length} URIs</div>
      <div style={{ color: 'var(--fg-muted)' }}>{formatRelative(client.client_id_issued_at)}</div>
      <div style={{ display: 'flex', gap: 6, position: 'relative' }}>
        <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={onEdit}>Edit</button>
        <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => setMenuOpen((v) => !v)} aria-label="More actions">⋯</button>
        {menuOpen && (
          <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: 4, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, padding: 4, zIndex: 10, minWidth: 140 }}>
            <button className="btn-secondary" style={{ display: 'block', width: '100%', textAlign: 'left', border: 'none' }} onClick={() => { setMenuOpen(false); onRotate(); }}>Rotate secret</button>
            <button className="btn-secondary" style={{ display: 'block', width: '100%', textAlign: 'left', border: 'none', color: 'var(--danger)' }} onClick={() => { setMenuOpen(false); onDelete(); }}>Delete</button>
          </div>
        )}
      </div>
    </div>
  );
}
