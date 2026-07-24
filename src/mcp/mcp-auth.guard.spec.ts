import { ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { McpAuthGuard } from './mcp-auth.guard';

function ctx(authHeader?: string) {
  const req: any = { headers: { authorization: authHeader } };
  const res = { setHeader: jest.fn() };
  return {
    ctx: {
      switchToHttp: () => ({
        getRequest: () => req,
        getResponse: () => res,
      }),
    } as any,
    req,
    res,
  };
}

describe('McpAuthGuard', () => {
  const provider: any = { AccessToken: { find: jest.fn() } };
  const guard = new McpAuthGuard(provider);

  beforeEach(() => jest.clearAllMocks());

  it('rejects missing bearer with WWW-Authenticate header', async () => {
    const { ctx: c, res } = ctx(undefined);
    await expect(guard.canActivate(c)).rejects.toThrow(UnauthorizedException);
    expect(res.setHeader).toHaveBeenCalledWith(
      'WWW-Authenticate',
      expect.stringContaining('oauth-protected-resource'),
    );
  });

  it('rejects unknown/expired token', async () => {
    provider.AccessToken.find.mockResolvedValue(undefined);
    const { ctx: c } = ctx('Bearer nope');
    await expect(guard.canActivate(c)).rejects.toThrow(UnauthorizedException);
  });

  it('maps provider/adapter failure to 503, not 401', async () => {
    provider.AccessToken.find.mockRejectedValue(new Error('redis down'));
    const { ctx: c } = ctx('Bearer any');
    await expect(guard.canActivate(c)).rejects.toThrow(ServiceUnavailableException);
  });

  it('rejects token flagged isExpired', async () => {
    provider.AccessToken.find.mockResolvedValue({
      accountId: 'user-1', clientId: 'c', scope: 'mcp:calendar', isExpired: true,
    });
    const { ctx: c } = ctx('Bearer stale');
    await expect(guard.canActivate(c)).rejects.toThrow(UnauthorizedException);
  });

  it('attaches mcpAuth on valid token', async () => {
    provider.AccessToken.find.mockResolvedValue({
      accountId: 'user-1',
      clientId: 'client-1',
      scope: 'openid mcp:calendar mcp:messages.read',
    });
    const { ctx: c, req } = ctx('Bearer good');
    await expect(guard.canActivate(c)).resolves.toBe(true);
    expect(req.mcpAuth).toEqual({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid', 'mcp:calendar', 'mcp:messages.read'],
    });
  });
});
