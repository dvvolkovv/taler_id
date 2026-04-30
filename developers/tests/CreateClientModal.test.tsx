import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CreateClientModal } from '../src/modals/CreateClientModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

describe('CreateClientModal', () => {
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

  it('renders form fields', () => {
    render(<CreateClientModal onClose={() => {}} onCreated={() => {}} />);
    expect(screen.getByRole('heading', { name: /Register new OAuth client/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Client name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Redirect URIs/i)).toBeInTheDocument();
  });

  it('submits and calls onCreated with client_id + client_secret', async () => {
    const onCreated = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        client_id: 'cid', client_secret: 'sec',
      }), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<CreateClientModal onClose={() => {}} onCreated={onCreated} />);
    await user.type(screen.getByLabelText(/Client name/i), 'my-app');
    await user.type(screen.getByLabelText(/Redirect URIs/i), 'app://cb');
    await user.click(screen.getByRole('button', { name: /Register/i }));
    await waitFor(() =>
      expect(onCreated).toHaveBeenCalledWith(expect.objectContaining({ client_id: 'cid', client_secret: 'sec' })),
    );
  });

  it('shows error when API fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'bad' }), { status: 400 }),
    );
    const user = userEvent.setup();
    render(<CreateClientModal onClose={() => {}} onCreated={() => {}} />);
    await user.type(screen.getByLabelText(/Client name/i), 'x');
    await user.type(screen.getByLabelText(/Redirect URIs/i), 'app://cb');
    await user.click(screen.getByRole('button', { name: /Register/i }));
    await waitFor(() => expect(screen.getByText(/HTTP 400/i)).toBeInTheDocument());
  });
});
