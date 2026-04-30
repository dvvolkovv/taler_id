import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { TalerIdProvider } from '@taler-id/oauth-client/react';
import './styles.css';
import { App } from './App';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TalerIdProvider
      clientId="taler-id-developers"
      redirectUri={window.location.origin + '/developers/'}
    >
      <App />
    </TalerIdProvider>
  </StrictMode>,
);
