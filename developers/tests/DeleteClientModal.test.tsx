import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeleteClientModal } from '../src/modals/DeleteClientModal';
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

describe('DeleteClientModal', () => {
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

  it('Delete button is disabled until user types client name', async () => {
    const user = userEvent.setup();
    render(<DeleteClientModal client={fakeClient as any} onClose={() => {}} onDeleted={() => {}} />);
    const btn = screen.getByRole('button', { name: /Delete forever/i });
    expect(btn).toBeDisabled();
    await user.type(screen.getByLabelText(/Type the client name/i), 'my-app');
    expect(btn).toBeEnabled();
  });

  it('submits DELETE and calls onDeleted', async () => {
    const onDeleted = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(null, { status: 204, statusText: 'No Content' }),
    );
    const user = userEvent.setup();
    render(<DeleteClientModal client={fakeClient as any} onClose={() => {}} onDeleted={onDeleted} />);
    await user.type(screen.getByLabelText(/Type the client name/i), 'my-app');
    await user.click(screen.getByRole('button', { name: /Delete forever/i }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalled());
  });
});
