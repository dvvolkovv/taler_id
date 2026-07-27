import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { OidcBearerGuard } from './oidc-bearer.guard';

// Regression cover for the 2026-07-27 audit finding: the guard accepted any
// unexpired OIDC access token, so a narrowly-scoped MCP integration could
// manage the user's OAuth clients and read their account.
describe('OidcBearerGuard', () => {
  let guard: OidcBearerGuard;
  let find: jest.Mock;

  const ctxFor = (authHeader?: string) => {
    const request: any = {
      headers: authHeader ? { authorization: authHeader } : {},
    };
    return {
      switchToHttp: () => ({ getRequest: () => request }),
      __request: request,
    } as any;
  };

  beforeEach(() => {
    find = jest.fn();
    guard = new OidcBearerGuard({
      getProvider: () => ({ AccessToken: { find } }),
    } as any);
  });

  it('admits a Developer Portal token', async () => {
    find.mockResolvedValue({
      accountId: 'user-1',
      clientId: 'taler-id-developers',
      isExpired: false,
    });

    const ctx = ctxFor('Bearer good-token');
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(ctx.__request.user).toEqual({ sub: 'user-1' });
  });

  it('refuses a token issued to an MCP integration', async () => {
    find.mockResolvedValue({
      accountId: 'user-1',
      clientId: 'some-mcp-client',
      scope: 'openid mcp:calendar',
      isExpired: false,
    });

    await expect(guard.canActivate(ctxFor('Bearer mcp-token'))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('refuses a token from a self-registered third-party client', async () => {
    find.mockResolvedValue({
      accountId: 'user-1',
      clientId: 'someones-app',
      scope: 'openid profile email',
      isExpired: false,
    });

    await expect(guard.canActivate(ctxFor('Bearer other'))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('still rejects missing, empty, unknown and expired tokens', async () => {
    await expect(guard.canActivate(ctxFor())).rejects.toThrow(
      UnauthorizedException,
    );
    await expect(guard.canActivate(ctxFor('Bearer '))).rejects.toThrow(
      UnauthorizedException,
    );

    find.mockResolvedValue(null);
    await expect(guard.canActivate(ctxFor('Bearer nope'))).rejects.toThrow(
      UnauthorizedException,
    );

    find.mockResolvedValue({
      accountId: 'user-1',
      clientId: 'taler-id-developers',
      isExpired: true,
    });
    await expect(guard.canActivate(ctxFor('Bearer old'))).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
