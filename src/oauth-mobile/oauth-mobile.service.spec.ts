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
