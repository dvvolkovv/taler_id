import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { LoginGate } from './pages/LoginGate';
import { ClientsList } from './pages/ClientsList';

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
  return <ClientsList />;
}
