import { PrismaClientAdapter } from './prisma-client-adapter';

describe('PrismaClientAdapter DCR', () => {
  const prisma: any = {
    oAuthClient: {
      findUnique: jest.fn(),
      upsert: jest.fn(),
      deleteMany: jest.fn(),
    },
  };
  const adapter = new PrismaClientAdapter(prisma, 'walletx-secret');

  beforeEach(() => jest.clearAllMocks());

  it('upsert stores dynamic client and strips offline_access from scope', async () => {
    await adapter.upsert('dyn-client-1', {
      client_name: 'Claude',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      token_endpoint_auth_method: 'none',
      scope: 'openid mcp:calendar offline_access',
    }, 0);
    const call = prisma.oAuthClient.upsert.mock.calls[0][0];
    expect(call.where).toEqual({ clientId: 'dyn-client-1' });
    expect(call.create.isDynamic).toBe(true);
    expect(call.create.dcrMetadata.scope).toBe('openid mcp:calendar');
  });

  it('find returns dcrMetadata for dynamic client', async () => {
    prisma.oAuthClient.findUnique.mockResolvedValue({
      clientId: 'dyn-client-1',
      isDynamic: true,
      dcrMetadata: { client_id: 'dyn-client-1', client_name: 'Claude' },
    });
    const result = await adapter.find('dyn-client-1');
    expect(result).toEqual({ client_id: 'dyn-client-1', client_name: 'Claude' });
  });

  it('destroy deletes only dynamic clients', async () => {
    await adapter.destroy('dyn-client-1');
    expect(prisma.oAuthClient.deleteMany).toHaveBeenCalledWith({
      where: { clientId: 'dyn-client-1', isDynamic: true },
    });
  });
});

describe('PrismaClientAdapter.find', () => {
  const buildPrismaMock = (returnValue: any) => ({
    oAuthClient: { findUnique: jest.fn().mockResolvedValue(returnValue) },
  } as any);

  it('returns AdapterPayload for an existing client', async () => {
    const prisma = buildPrismaMock({
      clientId: 'demo-app',
      clientSecret: 'secret-123',
      name: 'Demo App',
      redirectUris: ['https://demo.example/cb'],
      allowedScopes: ['openid', 'profile', 'email'],
      logoUri: 'https://demo.example/logo.png',
    });
    const adapter = new PrismaClientAdapter(prisma, 'walletx-override');
    const out = await adapter.find('demo-app');

    expect(out).toEqual({
      client_id: 'demo-app',
      client_secret: 'secret-123',
      client_name: 'Demo App',
      redirect_uris: ['https://demo.example/cb'],
      scope: 'openid profile email',
      logo_uri: 'https://demo.example/logo.png',
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    });
  });

  it('overrides walletx secret with the env-supplied value', async () => {
    const prisma = buildPrismaMock({
      clientId: 'walletx',
      clientSecret: 'STALE_DB_SECRET',
      name: 'WalletX',
      redirectUris: ['http://localhost:3001/auth/callback'],
      allowedScopes: ['openid', 'profile', 'email', 'wallet'],
      logoUri: null,
    });
    const adapter = new PrismaClientAdapter(prisma, 'env-walletx-secret');
    const out = await adapter.find('walletx');

    expect(out?.client_secret).toBe('env-walletx-secret');
    expect(out?.logo_uri).toBeUndefined();
  });

  it('returns undefined for a missing client', async () => {
    const prisma = buildPrismaMock(null);
    const adapter = new PrismaClientAdapter(prisma, 'unused');
    const out = await adapter.find('does-not-exist');
    expect(out).toBeUndefined();
  });
});
