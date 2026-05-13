import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EditClientModal } from '../src/modals/EditClientModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

const fakeClient = {
  client_id: 'cid',
  client_name: 'old',
  redirect_uris: ['app://cb'],
  scope: 'openid',
  client_id_issued_at: 0,
  token_endpoint_auth_method: 'client_secret_basic',
  grant_types: [],
  response_types: [],
};

describe('EditClientModal', () => {
  beforeEach(() => {
    cleanup();
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u1' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('pre-populates form from client', () => {
    render(<EditClientModal client={fakeClient as any} onClose={() => {}} onSaved={() => {}} />);
    expect((screen.getByLabelText(/Client name/i) as HTMLInputElement).value).toBe('old');
    expect((screen.getByLabelText(/Redirect URIs/i) as HTMLTextAreaElement).value).toContain('app://cb');
  });

  it('submits PATCH and calls onSaved', async () => {
    const onSaved = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<EditClientModal client={fakeClient as any} onClose={() => {}} onSaved={onSaved} />);
    await user.clear(screen.getByLabelText(/Client name/i));
    await user.type(screen.getByLabelText(/Client name/i), 'new');
    await user.click(screen.getByRole('button', { name: /Save/i }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
  });
});
