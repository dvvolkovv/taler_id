import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { TalerIdProvider } from '@taler-id/oauth-client/react';
import './styles.css';
import { App } from './App';
import { authConfig } from './auth-config';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TalerIdProvider {...authConfig(window.location.origin)}>
      <App />
    </TalerIdProvider>
  </StrictMode>,
);
