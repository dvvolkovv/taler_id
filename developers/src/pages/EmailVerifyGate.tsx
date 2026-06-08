import { useEffect, useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import {
  type AccountInfo,
  confirmEmailVerification,
  getAccount,
  sendEmailVerification,
} from '../api';

type Stage = 'loading' | 'load_error' | 'idle' | 'sending' | 'sent' | 'confirming' | 'confirmed';

/**
 * Wraps the portal once the user is authenticated. Fetches /oauth/account on
 * mount; if emailVerified=true we just render `children`. Otherwise we render
 * a two-step form: send code -> enter code -> confirm. On success we re-fetch
 * the account and unlock `children`.
 */
export function EmailVerifyGate({ children }: { children: React.ReactNode }) {
  const { getAccessToken, logout } = useTalerIdAuth();
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [stage, setStage] = useState<Stage>('loading');
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState('');

  const refreshAccount = async () => {
    setStage('loading');
    setError(null);
    try {
      const info = await getAccount(getAccessToken);
      setAccount(info);
      setStage(info.emailVerified ? 'confirmed' : 'idle');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load account');
      setStage('load_error');
    }
  };

  useEffect(() => {
    refreshAccount();
    /* eslint-disable-next-line react-hooks/exhaustive-deps */
  }, []);

  if (stage === 'loading') {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fg-muted)' }}>
        Loading account…
      </div>
    );
  }

  if (stage === 'load_error') {
    return (
      <Centered>
        <h2 style={{ marginTop: 0 }}>Couldn't load your account</h2>
        <p style={{ color: 'var(--fg-muted)' }}>{error}</p>
        <button className="btn-primary" onClick={refreshAccount}>Retry</button>
      </Centered>
    );
  }

  if (account?.emailVerified) {
    return <>{children}</>;
  }

  const submitSend = async () => {
    setStage('sending');
    setError(null);
    try {
      const r = await sendEmailVerification(getAccessToken);
      if (r.alreadyVerified) {
        await refreshAccount();
        return;
      }
      setStage('sent');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send code');
      setStage('idle');
    }
  };

  const submitConfirm = async () => {
    setStage('confirming');
    setError(null);
    try {
      await confirmEmailVerification(getAccessToken, code.trim());
      await refreshAccount();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid or expired code');
      setStage('sent');
    }
  };

  return (
    <Centered>
      <h2 style={{ marginTop: 0 }}>Verify your email</h2>
      <p style={{ color: 'var(--fg-muted)', marginBottom: 24 }}>
        OAuth client registration is only available to accounts with a
        verified email. We'll send a 6-digit code to{' '}
        <strong>{account?.email ?? 'your address'}</strong>.
      </p>

      {stage === 'idle' && (
        <button className="btn-primary" onClick={submitSend}>Send verification code</button>
      )}

      {stage === 'sending' && (
        <button className="btn-primary" disabled>Sending…</button>
      )}

      {(stage === 'sent' || stage === 'confirming') && (
        <div className="field">
          <label htmlFor="evg-code">Enter the 6-digit code from your inbox</label>
          <input
            id="evg-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            style={{ letterSpacing: '0.3em', fontSize: 18 }}
          />
          <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
            <button
              className="btn-primary"
              onClick={submitConfirm}
              disabled={stage === 'confirming' || code.trim().length < 4}
            >
              {stage === 'confirming' ? 'Confirming…' : 'Confirm'}
            </button>
            <button
              className="btn-secondary"
              onClick={submitSend}
              disabled={stage === 'confirming'}
            >
              Resend code
            </button>
          </div>
        </div>
      )}

      {error && <div className="field-error" style={{ marginTop: 16 }}>{error}</div>}

      <div style={{ marginTop: 32, fontSize: 12, color: 'var(--fg-muted)' }}>
        Wrong account?{' '}
        <button
          className="btn-secondary"
          style={{ padding: '2px 8px', fontSize: 12 }}
          onClick={() => logout({ returnTo: window.location.origin + '/developers/' })}
        >
          Sign out
        </button>
      </div>
    </Centered>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <div style={{ maxWidth: 420, width: '100%', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: 32 }}>
        {children}
      </div>
    </div>
  );
}
