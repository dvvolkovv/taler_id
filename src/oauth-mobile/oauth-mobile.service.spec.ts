import { Test } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { OAuthMobileService, mergeScopes, validateRedirectUri } from './oauth-mobile.service';
import { OidcService } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';
import { CompanyConsentService } from '../companies/company-consent.service';

describe('validateRedirectUri', () => {
  it('accepts exact-match registered URI for non-desktop client', () => {
    const client = { redirectUris: ['https://example.com/cb'], isDesktopClient: false };
    expect(validateRedirectUri(client, 'https://example.com/cb')).toBe(true);
  });

  it('rejects unknown redirect_uri for non-desktop client', () => {
    const client = { redirectUris: ['https://example.com/cb'], isDesktopClient: false };
    expect(validateRedirectUri(client, 'http://127.0.0.1:54321/cb')).toBe(false);
  });

  it('accepts any 127.0.0.1 port for desktop client', () => {
    const client = { redirectUris: [], isDesktopClient: true };
    expect(validateRedirectUri(client, 'http://127.0.0.1:54321/cb')).toBe(true);
    expect(validateRedirectUri(client, 'http://127.0.0.1:1/cb')).toBe(true);
    expect(validateRedirectUri(client, 'http://127.0.0.1:65535/cb')).toBe(true);
  });

  it('rejects HTTPS loopback for desktop client (RFC 8252 specifies HTTP only)', () => {
    const client = { redirectUris: [], isDesktopClient: true };
    expect(validateRedirectUri(client, 'https://127.0.0.1:54321/cb')).toBe(false);
  });

  it('rejects non-loopback for desktop client', () => {
    const client = { redirectUris: [], isDesktopClient: true };
    expect(validateRedirectUri(client, 'http://example.com/cb')).toBe(false);
    expect(validateRedirectUri(client, 'http://localhost/cb')).toBe(false);
    expect(validateRedirectUri(client, 'http://192.168.1.1:54321/cb')).toBe(false);
  });

  it('rejects malformed URI', () => {
    const client = { redirectUris: [], isDesktopClient: true };
    expect(validateRedirectUri(client, 'not-a-url')).toBe(false);
  });

  it('accepts exact-match registered URI for desktop client (fallback)', () => {
    const client = {
      redirectUris: ['https://myapp.example.com/callback'],
      isDesktopClient: true,
    };
    expect(validateRedirectUri(client, 'https://myapp.example.com/callback')).toBe(true);
  });
});

describe('OAuthMobileService.getGrantInfo', () => {
  let svc: OAuthMobileService;
  let oidc: jest.Mocked<OidcService>;
  let prisma: jest.Mocked<PrismaService>;
  let providerMock: any;
  let companies: any;

  beforeEach(async () => {
    providerMock = {
      Client: { find: jest.fn() },
    };
    oidc = { getProvider: jest.fn(() => providerMock) } as any;
    prisma = {
      oAuthGrant: { findFirst: jest.fn() },
      oAuthClient: { findUnique: jest.fn().mockResolvedValue({ isDesktopClient: false }) },
    } as any;
    companies = {
      consentBlock: jest.fn(),
      validate: jest
        .fn()
        .mockResolvedValue({ actAsTenantId: null, sharedTenantIds: [] }),
      save: jest.fn().mockResolvedValue(undefined),
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        OAuthMobileService,
        { provide: OidcService, useValue: oidc },
        { provide: PrismaService, useValue: prisma },
        { provide: CompanyConsentService, useValue: companies },
      ],
    }).compile();
    svc = moduleRef.get(OAuthMobileService);
  });

  const baseParams = {
    client_id: 'mybook',
    redirect_uri: 'https://example.com/cb',
    scope: 'profile email',
    response_type: 'code' as const,
  };

  it('throws NotFoundException with error=unknown_client when client not found', async () => {
    providerMock.Client.find.mockResolvedValue(undefined);
    const promise = svc.getGrantInfo('user-1', baseParams);
    await expect(promise).rejects.toBeInstanceOf(NotFoundException);
    await expect(promise).rejects.toMatchObject({ response: { error: 'unknown_client' } });
  });

  it('throws BadRequestException with error=redirect_uri_mismatch when redirect_uri not registered', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://other.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    const promise = svc.getGrantInfo('user-1', baseParams);
    await expect(promise).rejects.toBeInstanceOf(BadRequestException);
    await expect(promise).rejects.toMatchObject({
      response: { error: 'redirect_uri_mismatch' },
    });
  });

  it('allows 127.0.0.1:* redirect for desktop client', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'desktop-app',
      clientName: 'Desktop App',
      redirectUris: [],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthClient as any).findUnique.mockResolvedValue({ isDesktopClient: true });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);

    const result = await svc.getGrantInfo('user-1', {
      ...baseParams,
      client_id: 'desktop-app',
      redirect_uri: 'http://127.0.0.1:52437/cb',
    });
    expect(result.client_name).toBe('Desktop App');
  });

  it('throws BadRequestException with error=invalid_scope when scope not subset of allowed', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile',
      tokenEndpointAuthMethod: 'none',
    });
    const promise = svc.getGrantInfo('user-1', baseParams);
    await expect(promise).rejects.toBeInstanceOf(BadRequestException);
    await expect(promise).rejects.toMatchObject({
      response: { error: 'invalid_scope' },
    });
  });

  it('serves a confidential client (a site with a secret) — PKCE binds the code', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);
    await expect(svc.getGrantInfo('user-1', baseParams)).resolves.toMatchObject(
      { client_name: 'MyBook' },
    );
  });

  it('returns grant info with remembered=false when no existing grant', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      logoUri: 'https://example.com/logo.png',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result).toEqual({
      client_name: 'MyBook',
      client_logo: 'https://example.com/logo.png',
      scopes: [
        { key: 'profile', label: 'Профиль', description: 'Имя, фамилия, аватар' },
        { key: 'email', label: 'Email', description: 'Email адрес' },
      ],
      scopeDescriptions: {},
      remembered: false,
    });
  });

  it('returns remembered=true when existing grant covers requested scopes', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email openid',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue({
      scope: 'profile email openid',
    });

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result.remembered).toBe(true);
  });

  it('returns remembered=false when existing grant has narrower scope', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue({
      scope: 'profile',
    });

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result.remembered).toBe(false);
  });

  it('includes scopeDescriptions for mcp scopes and omits unknown scopes', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mcp-client',
      clientName: 'MCP Client',
      redirectUris: ['https://example.com/cb'],
      scope: 'mcp:calendar mcp:messages.read openid',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);

    const result = await svc.getGrantInfo('user-1', {
      ...baseParams,
      client_id: 'mcp-client',
      scope: 'mcp:calendar mcp:messages.read openid',
    });

    expect(result.scopeDescriptions).toEqual({
      'mcp:calendar': {
        ru: 'Просмотр и управление календарём и напоминаниями',
        en: 'View and manage your calendar and reminders',
      },
      'mcp:messages.read': {
        ru: 'Чтение ваших сообщений и списка контактов',
        en: 'Read your messages and contact list',
      },
    });
    // openid is not an MCP scope — must not appear in scopeDescriptions
    expect(result.scopeDescriptions['openid']).toBeUndefined();
  });

  it('returns empty scopeDescriptions when no mcp scopes requested', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result.scopeDescriptions).toEqual({});
  });

  const companiesClient = {
    clientId: 'mybook',
    clientName: 'MyBook',
    redirectUris: ['https://example.com/cb'],
    scope: 'openid profile companies',
    tokenEndpointAuthMethod: 'client_secret_basic',
  };

  it('carries the companies block and is never "remembered" when a company can be chosen', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue({
      scope: 'openid profile companies',
    });
    companies.consentBlock.mockResolvedValue({
      person: { name: 'Иван' },
      eligible: [{ id: 'a' }],
      unverified: [],
      last_selection: null,
    });
    const info = await svc.getGrantInfo('user-1', {
      ...baseParams,
      scope: 'openid profile companies',
    });
    expect(companies.consentBlock).toHaveBeenCalledWith('user-1', 'mybook');
    expect(info.companies?.eligible).toEqual([{ id: 'a' }]);
    expect(info.remembered).toBe(false);
  });

  it('companies requested but nothing eligible → remembered as before, block still present', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue({
      scope: 'openid profile companies',
    });
    companies.consentBlock.mockResolvedValue({
      person: { name: 'Иван' },
      eligible: [],
      unverified: [{ id: 'b', name: 'Лютик' }],
      last_selection: null,
    });
    const info = await svc.getGrantInfo('user-1', {
      ...baseParams,
      scope: 'openid profile companies',
    });
    expect(info.remembered).toBe(true);
    expect(info.companies?.unverified).toEqual([{ id: 'b', name: 'Лютик' }]);
  });

  it('no companies scope → no block', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);
    const info = await svc.getGrantInfo('user-1', baseParams);
    expect(info.companies).toBeUndefined();
    expect(companies.consentBlock).not.toHaveBeenCalled();
  });
});

describe('OAuthMobileService.approve', () => {
  let svc: OAuthMobileService;
  let oidc: jest.Mocked<OidcService>;
  let prisma: any;
  let providerMock: any;
  let companies: any;

  const baseParams = {
    client_id: 'mybook',
    redirect_uri: 'https://example.com/cb',
    scope: 'profile email',
    response_type: 'code' as const,
    code_challenge: 'CHALLENGE_ABC',
    code_challenge_method: 'S256' as const,
    state: 'state-123',
    nonce: 'nonce-456',
  };

  beforeEach(async () => {
    const grantSaveSpy = jest.fn().mockResolvedValue('grant-jti-789');
    const grantInstance = {
      addOIDCScope: jest.fn(),
      save: grantSaveSpy,
      jti: 'grant-jti-789',
    };
    const codeSaveSpy = jest.fn().mockResolvedValue('code-value-XYZ');
    const codeInstance = { save: codeSaveSpy };

    providerMock = {
      Client: {
        find: jest.fn().mockResolvedValue({
          clientId: 'mybook',
          clientName: 'MyBook',
          redirectUris: ['https://example.com/cb'],
          scope: 'profile email openid',
          tokenEndpointAuthMethod: 'none',
        }),
      },
      Grant: jest.fn(() => grantInstance),
      AuthorizationCode: jest.fn(() => codeInstance),
      _grantSpy: grantSaveSpy,
      _codeSpy: codeSaveSpy,
      _grantInstance: grantInstance,
      _codeInstance: codeInstance,
    };
    oidc = { getProvider: jest.fn(() => providerMock) } as any;
    prisma = {
      oAuthGrant: {
        findFirst: jest.fn().mockResolvedValue(null),
        upsert: jest.fn().mockResolvedValue({ id: 'grant-row-1' }),
      },
      oAuthClient: {
        findUnique: jest.fn().mockResolvedValue({ isDesktopClient: false }),
      },
    };
    companies = {
      consentBlock: jest.fn(),
      validate: jest
        .fn()
        .mockResolvedValue({ actAsTenantId: null, sharedTenantIds: [] }),
      save: jest.fn().mockResolvedValue(undefined),
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        OAuthMobileService,
        { provide: OidcService, useValue: oidc },
        { provide: PrismaService, useValue: prisma },
        { provide: CompanyConsentService, useValue: companies },
      ],
    }).compile();
    svc = moduleRef.get(OAuthMobileService);
  });

  it('creates grant and authorization code, returns redirect_uri with code+state', async () => {
    const result = await svc.approve('user-1', baseParams);

    expect(providerMock.Grant).toHaveBeenCalledWith({
      accountId: 'user-1',
      clientId: 'mybook',
    });
    expect(providerMock._grantInstance.addOIDCScope).toHaveBeenCalledWith('profile email');
    expect(providerMock._grantSpy).toHaveBeenCalled();

    expect(providerMock.AuthorizationCode).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: 'user-1',
        clientId: 'mybook',
        redirectUri: 'https://example.com/cb',
        scope: 'profile email',
        grantId: 'grant-jti-789',
        codeChallenge: 'CHALLENGE_ABC',
        codeChallengeMethod: 'S256',
        nonce: 'nonce-456',
      }),
    );
    expect(providerMock._codeSpy).toHaveBeenCalled();

    expect(result.redirect_uri).toBe(
      'https://example.com/cb?code=code-value-XYZ&state=state-123',
    );
  });

  it('persists grant in OAuthGrant table for remembered logic', async () => {
    await svc.approve('user-1', baseParams);
    expect(prisma.oAuthGrant.upsert).toHaveBeenCalledWith({
      where: { userId_clientId: { userId: 'user-1', clientId: 'mybook' } },
      create: { userId: 'user-1', clientId: 'mybook', scope: 'profile email' },
      update: { scope: 'profile email' },
    });
  });

  it('merges scopes with existing grant on repeat approve', async () => {
    prisma.oAuthGrant.findFirst.mockResolvedValue({ scope: 'profile' });
    await svc.approve('user-1', { ...baseParams, scope: 'email' });
    expect(prisma.oAuthGrant.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: { scope: expect.stringMatching(/profile.*email|email.*profile/) },
      }),
    );
  });

  it('omits state from redirect_uri when not provided', async () => {
    const { state, ...paramsNoState } = baseParams;
    const result = await svc.approve('user-1', paramsNoState as any);
    expect(result.redirect_uri).toBe('https://example.com/cb?code=code-value-XYZ');
  });

  it('approves for a confidential client too', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    const out = await svc.approve('user-1', baseParams);
    expect(out.redirect_uri).toContain('code=code-value-XYZ');
  });

  it('rejects invalid redirect_uri', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://other.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    const promise = svc.approve('user-1', baseParams);
    await expect(promise).rejects.toBeInstanceOf(BadRequestException);
    await expect(promise).rejects.toMatchObject({
      response: { error: 'redirect_uri_mismatch' },
    });
  });

  it('accepts 127.0.0.1 loopback redirect for desktop client in approve', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'desktop-app',
      clientName: 'Desktop App',
      redirectUris: [],
      scope: 'profile email openid',
      tokenEndpointAuthMethod: 'none',
    });
    prisma.oAuthClient.findUnique.mockResolvedValue({ isDesktopClient: true });
    prisma.oAuthGrant.findFirst.mockResolvedValue(null);

    const result = await svc.approve('user-1', {
      ...baseParams,
      client_id: 'desktop-app',
      redirect_uri: 'http://127.0.0.1:52437/cb',
    });
    expect(result.redirect_uri).toMatch(/^http:\/\/127\.0\.0\.1:52437\/cb\?code=/);
  });

  const companiesClient = {
    clientId: 'mybook',
    clientName: 'MyBook',
    redirectUris: ['https://example.com/cb'],
    scope: 'openid companies',
    tokenEndpointAuthMethod: 'client_secret_basic',
  };

  it('validates the company choice before the grant and stores it under the grant', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    companies.validate.mockResolvedValue({
      actAsTenantId: 'a',
      sharedTenantIds: ['a'],
    });
    await svc.approve('user-1', {
      ...baseParams,
      scope: 'openid companies',
      act_as: 'a',
      company_ids: ['a'],
    });
    expect(companies.validate).toHaveBeenCalledWith('user-1', {
      actAs: 'a',
      companyIds: ['a'],
    });
    expect(companies.save).toHaveBeenCalledWith({
      grantId: 'grant-jti-789',
      userId: 'user-1',
      clientId: 'mybook',
      selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
    expect(companies.validate.mock.invocationCallOrder[0]).toBeLessThan(
      providerMock._grantSpy.mock.invocationCallOrder[0],
    );
  });

  it('a forged company: 400 and no grant', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    companies.validate.mockRejectedValue(
      new BadRequestException('company is not available'),
    );
    await expect(
      svc.approve('user-1', {
        ...baseParams,
        scope: 'openid companies',
        act_as: 'zzz',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(companies.validate).toHaveBeenCalled();
    expect(providerMock._grantSpy).not.toHaveBeenCalled();
  });

  it('companies not requested → no validation, no selection stored', async () => {
    await svc.approve('user-1', { ...baseParams, act_as: 'a' } as any);
    expect(companies.validate).not.toHaveBeenCalled();
    expect(companies.save).not.toHaveBeenCalled();
  });

  // Старая версия приложения выбора не присылает → физлицо, ничего не передаётся.
  it('companies requested without a choice (old app) → validated as person', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    await svc.approve('user-1', { ...baseParams, scope: 'openid companies' });
    expect(companies.validate).toHaveBeenCalledWith('user-1', {
      actAs: undefined,
      companyIds: undefined,
    });
    expect(companies.save).toHaveBeenCalled();
  });

  it('storing the selection fails → no code is returned', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    companies.save.mockRejectedValue(new Error('db down'));
    await expect(
      svc.approve('user-1', { ...baseParams, scope: 'openid companies' }),
    ).rejects.toThrow('db down');
    expect(providerMock._codeSpy).not.toHaveBeenCalled();
    expect(prisma.oAuthGrant.upsert).not.toHaveBeenCalled();
  });
});

describe('mergeScopes', () => {
  it('returns added scopes when existing is empty', () => {
    expect(mergeScopes('', 'profile email')).toBe('profile email');
  });

  it('returns existing scopes when added is empty', () => {
    expect(mergeScopes('profile email', '')).toBe('profile email');
  });

  it('preserves order with existing first then new additions', () => {
    expect(mergeScopes('profile', 'email')).toBe('profile email');
  });

  it('deduplicates overlapping scopes', () => {
    expect(mergeScopes('profile email', 'email openid')).toBe('profile email openid');
  });

  it('handles extra whitespace and empty tokens', () => {
    expect(mergeScopes('  profile   email ', ' email  openid ')).toBe(
      'profile email openid',
    );
  });
});
