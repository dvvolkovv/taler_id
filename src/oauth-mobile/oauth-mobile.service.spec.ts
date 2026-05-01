import { Test } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { OAuthMobileService } from './oauth-mobile.service';
import { OidcService } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';

describe('OAuthMobileService.getGrantInfo', () => {
  let svc: OAuthMobileService;
  let oidc: jest.Mocked<OidcService>;
  let prisma: jest.Mocked<PrismaService>;
  let providerMock: any;

  beforeEach(async () => {
    providerMock = {
      Client: { find: jest.fn() },
    };
    oidc = { getProvider: jest.fn(() => providerMock) } as any;
    prisma = { oAuthGrant: { findFirst: jest.fn() } } as any;
    const moduleRef = await Test.createTestingModule({
      providers: [
        OAuthMobileService,
        { provide: OidcService, useValue: oidc },
        { provide: PrismaService, useValue: prisma },
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

  it('throws BadRequestException with error=confidential_client_not_supported_via_mobile for confidential client', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    const promise = svc.getGrantInfo('user-1', baseParams);
    await expect(promise).rejects.toBeInstanceOf(BadRequestException);
    await expect(promise).rejects.toMatchObject({
      response: { error: 'confidential_client_not_supported_via_mobile' },
    });
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
});

describe('OAuthMobileService.approve', () => {
  let svc: OAuthMobileService;
  let oidc: jest.Mocked<OidcService>;
  let prisma: any;
  let providerMock: any;

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
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        OAuthMobileService,
        { provide: OidcService, useValue: oidc },
        { provide: PrismaService, useValue: prisma },
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
      update: { scope: expect.stringMatching(/profile|email/) },
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

  it('rejects confidential client', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    const promise = svc.approve('user-1', baseParams);
    await expect(promise).rejects.toBeInstanceOf(BadRequestException);
    await expect(promise).rejects.toMatchObject({
      response: { error: 'confidential_client_not_supported_via_mobile' },
    });
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
});
