import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

vi.mock('@taler-id/oauth-client/react', () => ({
  useTalerIdAuth: vi.fn(),
  TalerIdProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
import * as sdk from '@taler-id/oauth-client/react';
import { App } from '../src/App';

const mockUseTalerIdAuth = vi.mocked(sdk.useTalerIdAuth);

describe('App', () => {
  beforeEach(() => {
    cleanup();
    mockUseTalerIdAuth.mockReset();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
  });

  it('renders LoginGate when not authenticated', () => {
    mockUseTalerIdAuth.mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn(),
    } as any);
    render(<App />);
    expect(screen.getByRole('button', { name: /Sign in with Taler ID/i })).toBeInTheDocument();
  });

  it('renders ClientsList when authenticated', () => {
    mockUseTalerIdAuth.mockReturnValue({
      user: { sub: 'u1' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    } as any);
    render(<App />);
    expect(screen.queryByRole('button', { name: /Sign in with Taler ID/i })).not.toBeInTheDocument();
  });

  it('renders loading state when isLoading', () => {
    mockUseTalerIdAuth.mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: true,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn(),
    } as any);
    render(<App />);
    expect(screen.getByText(/Loading/i)).toBeInTheDocument();
  });
});
