import { useState } from 'react';

export function SecretRevealModal({
  clientId, clientSecret, onClose,
}: { clientId: string; clientSecret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [acked, setAcked] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(clientSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore — user can manually select+copy
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ borderColor: 'var(--accent)' }}>
        <h2 className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>⚠️</span>
          Save this client_secret now
        </h2>
        <p style={{ color: 'var(--accent)', fontSize: 13 }}>
          This is the only time you'll see this secret. Once you close this dialog it's gone — you'll need to rotate to get a new one.
        </p>
        <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 8 }}>Client ID</div>
        <div style={{ background: '#05070D', border: '1px solid var(--border)', borderRadius: 6, padding: 10, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, marginBottom: 16, wordBreak: 'break-all' }}>
          {clientId}
        </div>
        <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 8 }}>Client Secret</div>
        <div style={{ background: '#05070D', border: '1px solid var(--border)', borderRadius: 6, padding: 10, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, marginBottom: 8, wordBreak: 'break-all' }}>
          {clientSecret}
        </div>
        <button className="btn-primary" onClick={copy} style={{ fontSize: 12 }}>
          {copied ? '✓ Copied!' : '📋 Copy to clipboard'}
        </button>
        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <input type="checkbox" checked={acked} onChange={(e) => setAcked(e.target.checked)} />
            <span>I've copied the secret to a safe place</span>
          </label>
        </div>
        <div className="modal-actions">
          <button className="btn-primary" onClick={onClose} disabled={!acked}>Done</button>
        </div>
      </div>
    </div>
  );
}
