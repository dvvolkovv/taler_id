import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { ClientsList } from './pages/ClientsList';
import { EmailVerifyGate } from './pages/EmailVerifyGate';
import { LoginGate } from './pages/LoginGate';

export function App() {
  const { isAuthenticated, isLoading } = useTalerIdAuth();
  if (isLoading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fg-muted)' }}>
        Loading…
      </div>
    );
  }
  if (!isAuthenticated) return <LoginGate />;
  return (
    <EmailVerifyGate>
      <ClientsList />
    </EmailVerifyGate>
  );
}
