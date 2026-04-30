import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RotateSecretModal } from '../src/modals/RotateSecretModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

const fakeClient = {
  client_id: 'cid',
  client_name: 'my-app',
  redirect_uris: [],
  scope: '',
  client_id_issued_at: 0,
  token_endpoint_auth_method: 'client_secret_basic',
  grant_types: [],
  response_types: [],
};

describe('RotateSecretModal', () => {
  beforeEach(() => {
    cleanup();
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('warns about old secret invalidation', () => {
    render(<RotateSecretModal client={fakeClient as any} onClose={() => {}} onRotated={() => {}} />);
    expect(screen.getByText(/old secret will fail/i)).toBeInTheDocument();
  });

  it('on confirm calls API and onRotated with new secret', async () => {
    const onRotated = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ client_id: 'cid', client_secret: 'NEW_SECRET', client_secret_rotated_at: 1234567890 }), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<RotateSecretModal client={fakeClient as any} onClose={() => {}} onRotated={onRotated} />);
    await user.click(screen.getByRole('button', { name: /Rotate secret/i }));
    await waitFor(() => expect(onRotated).toHaveBeenCalledWith(expect.objectContaining({ client_secret: 'NEW_SECRET' })));
  });
});
