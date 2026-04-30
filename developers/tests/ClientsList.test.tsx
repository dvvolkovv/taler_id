import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { ClientsList } from '../src/pages/ClientsList';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

describe('ClientsList', () => {
  beforeEach(() => {
    cleanup();
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u1', email: 'u@example.com' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('renders rows from the API', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([
        {
          client_id: '4f3c-abc',
          client_name: 'my-app',
          redirect_uris: ['app://cb', 'app://cb2'],
          scope: 'openid profile',
          client_id_issued_at: Math.floor(Date.now() / 1000) - 86400,
          token_endpoint_auth_method: 'client_secret_basic',
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
        },
      ]), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    render(<ClientsList />);
    await waitFor(() => expect(screen.getByText('my-app')).toBeInTheDocument());
    expect(screen.getByText(/2 URIs/i)).toBeInTheDocument();
    expect(screen.getByText(/4f3c-abc/i)).toBeInTheDocument();
  });

  it('shows empty state with CTA when no clients', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    render(<ClientsList />);
    await waitFor(() => expect(screen.getByText(/No OAuth clients yet/i)).toBeInTheDocument());
  });
});
