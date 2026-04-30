import { useTalerIdAuth } from '@taler-id/oauth-client/react';

export function LoginGate() {
  const { login } = useTalerIdAuth();
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center', maxWidth: 360 }}>
        <h1 style={{ fontSize: 28, marginBottom: 8 }}>Taler ID Developer Portal</h1>
        <p style={{ color: 'var(--fg-muted)', marginBottom: 32 }}>
          Manage your OAuth clients. Sign in with your Taler ID account (email-verified accounts only).
        </p>
        <button className="btn-primary" style={{ padding: '12px 24px', fontSize: 15 }} onClick={() => login()}>
          Sign in with Taler ID
        </button>
      </div>
    </div>
  );
}
