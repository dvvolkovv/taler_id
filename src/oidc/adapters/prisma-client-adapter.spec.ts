import { PrismaClientAdapter } from './prisma-client-adapter';

describe('PrismaClientAdapter DCR', () => {
  const prisma: any = {
    oAuthClient: {
      findUnique: jest.fn(),
      upsert: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      deleteMany: jest.fn(),
    },
  };
  const adapter = new PrismaClientAdapter(prisma, 'walletx-secret');

  beforeEach(() => jest.clearAllMocks());

  it('upsert stores dynamic client and strips offline_access from scope', async () => {
    // No existing row → findUnique returns null → create path
    prisma.oAuthClient.findUnique.mockResolvedValue(null);
    await adapter.upsert('dyn-client-1', {
      client_name: 'Claude',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      token_endpoint_auth_method: 'none',
      scope: 'openid mcp:calendar offline_access',
    }, 0);
    const createCall = prisma.oAuthClient.create.mock.calls[0][0];
    expect(createCall.data.clientId).toBe('dyn-client-1');
    expect(createCall.data.isDynamic).toBe(true);
    expect(createCall.data.dcrMetadata.scope).toBe('openid mcp:calendar');
  });

  it('upsert strips the partner-only messenger scope from dynamic clients', async () => {
    // Токен со scope messenger пускает в чужие переписки. Выдавать его может
    // только партнёрский API, а не любой, кто зарегистрировался через DCR.
    prisma.oAuthClient.findUnique.mockResolvedValue(null);
    await adapter.upsert('dyn-client-2', {
      client_name: 'Someone',
      redirect_uris: ['https://example.com/cb'],
      token_endpoint_auth_method: 'none',
      scope: 'openid messenger mcp:calendar',
    }, 0);
    const createCall = prisma.oAuthClient.create.mock.calls[0][0];
    expect(createCall.data.dcrMetadata.scope).toBe('openid mcp:calendar');
    expect(createCall.data.allowedScopes).toEqual(['openid', 'mcp:calendar']);
  });

  it('upsert strips companies: company data only for clients granted it by hand', async () => {
    prisma.oAuthClient.findUnique.mockResolvedValue(null);
    await adapter.upsert(
      'dyn-client-3',
      {
        client_name: 'Someone',
        redirect_uris: ['https://example.com/cb'],
        token_endpoint_auth_method: 'none',
        scope: 'openid companies profile',
      },
      0,
    );
    const createCall = prisma.oAuthClient.create.mock.calls[0][0];
    expect(createCall.data.dcrMetadata.scope).toBe('openid profile');
    expect(createCall.data.allowedScopes).toEqual(['openid', 'profile']);
  });

  it('upsert strips companies when an existing dynamic client re-registers', async () => {
    // PUT /reg/:clientId от уже зарегистрированного клиента — та же граница:
    // companies не дописать себе и через обновление.
    prisma.oAuthClient.findUnique.mockResolvedValue({ isDynamic: true });
    await adapter.upsert(
      'dyn-client-3',
      {
        client_name: 'Someone',
        redirect_uris: ['https://example.com/cb'],
        token_endpoint_auth_method: 'none',
        scope: 'openid companies',
      },
      0,
    );
    expect(prisma.oAuthClient.create).not.toHaveBeenCalled();
    const updateCall = prisma.oAuthClient.update.mock.calls[0][0];
    expect(updateCall.where).toEqual({ clientId: 'dyn-client-3' });
    expect(updateCall.data.dcrMetadata.scope).toBe('openid');
  });

  it('find returns dcrMetadata for dynamic client', async () => {
    prisma.oAuthClient.findUnique.mockResolvedValue({
      clientId: 'dyn-client-1',
      isDynamic: true,
      dcrMetadata: { client_name: 'Claude' },
    });
    const result = await adapter.find('dyn-client-1');
    expect(result).toEqual({ client_name: 'Claude', client_id: 'dyn-client-1' });
  });

  it('upsert never modifies a static client', async () => {
    // Existing row is a static client (isDynamic: false)
    prisma.oAuthClient.findUnique.mockResolvedValue({ isDynamic: false });
    await expect(
      adapter.upsert('walletx', {
        client_name: 'Evil',
        redirect_uris: ['https://evil.example/steal'],
        scope: 'openid',
      }, 0),
    ).rejects.toThrow('Refusing DCR upsert over static client walletx');
    expect(prisma.oAuthClient.update).not.toHaveBeenCalled();
    expect(prisma.oAuthClient.create).not.toHaveBeenCalled();
  });

  it('find injects canonical client_id for dynamic clients', async () => {
    prisma.oAuthClient.findUnique.mockResolvedValue({
      clientId: 'dyn-1',
      isDynamic: true,
      dcrMetadata: { client_name: 'X' },
    });
    const result = await adapter.find('dyn-1');
    expect(result).toEqual({ client_name: 'X', client_id: 'dyn-1' });
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

  it('lets the Developer Portal log out to the same pages it logs in from', async () => {
    // Портал возвращается после выхода туда же, куда после входа. Адреса
    // берутся из строки клиента: в коде были зашиты только aeza, и на PROD
    // выход на talerid.io/developers/ отклонялся бы.
    const prisma = buildPrismaMock({
      clientId: 'taler-id-developers',
      clientSecret: 'unused',
      name: 'Taler ID Developer Portal',
      redirectUris: ['https://talerid.io/developers/', 'https://api.talerid.io/developers/'],
      allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
      logoUri: null,
    });
    const adapter = new PrismaClientAdapter(prisma, 'unused');
    const out = await adapter.find('taler-id-developers');

    expect(out?.token_endpoint_auth_method).toBe('none');
    expect(out?.post_logout_redirect_uris).toEqual([
      'https://talerid.io/developers/',
      'https://api.talerid.io/developers/',
    ]);
  });

  it('returns undefined for a missing client', async () => {
    const prisma = buildPrismaMock(null);
    const adapter = new PrismaClientAdapter(prisma, 'unused');
    const out = await adapter.find('does-not-exist');
    expect(out).toBeUndefined();
  });
});
