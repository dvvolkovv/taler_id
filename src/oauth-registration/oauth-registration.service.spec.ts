import { ForbiddenException, NotFoundException, ConflictException } from '@nestjs/common';
import { OAuthRegistrationService, MAX_CLIENTS_PER_USER, SELF_REGISTRATION_ALLOWED_SCOPES } from './oauth-registration.service';

const buildPrismaMock = (overrides: Partial<{
  user: any;
  count: number;
  createdRow: any;
  findFirstRow: any;
  updatedRow: any;
}> = {}) => {
  const findUnique = jest.fn().mockResolvedValue(overrides.user ?? { emailVerified: true });
  const count = jest.fn().mockResolvedValue(overrides.count ?? 0);
  const create = jest.fn().mockImplementation(async ({ data }) => ({
    ...overrides.createdRow,
    ...data,
    id: 'row-id',
    createdAt: new Date('2026-04-28T10:00:00Z'),
    updatedAt: new Date('2026-04-28T10:00:00Z'),
  }));
  const findFirst = jest.fn().mockResolvedValue(overrides.findFirstRow ?? null);
  const update = jest.fn().mockResolvedValue(overrides.updatedRow ?? null);
  const del = jest.fn().mockResolvedValue(undefined);
  const findMany = jest.fn().mockResolvedValue([]);

  return {
    user: { findUnique },
    oAuthClient: { count, create, findFirst, findMany, update, delete: del },
    auditLog: { create: jest.fn().mockResolvedValue(undefined) },
  } as any;
};

describe('OAuthRegistrationService', () => {
  describe('register', () => {
    it('persists row and returns RFC 7591 shape for verified user', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.register(
        'user-1',
        { client_name: 'Demo', redirect_uris: ['https://demo.example/cb'] },
        '127.0.0.1',
        'jest',
      );

      expect(out.client_name).toBe('Demo');
      expect(out.redirect_uris).toEqual(['https://demo.example/cb']);
      expect(out.scope).toBe('openid profile email offline_access');
      expect(out.client_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(out.client_secret).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(out.client_secret_expires_at).toBe(0);
      expect(out.token_endpoint_auth_method).toBe('client_secret_basic');
      expect(out.grant_types).toEqual(['authorization_code', 'refresh_token']);
      expect(out.response_types).toEqual(['code']);
      expect(prisma.oAuthClient.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          name: 'Demo',
          userId: 'user-1',
          allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
        }),
      });
    });

    it('rejects email-unverified user', async () => {
      const prisma = buildPrismaMock({ user: { emailVerified: false } });
      const svc = new OAuthRegistrationService(prisma);

      await expect(
        svc.register('user-1', { client_name: 'Demo', redirect_uris: ['https://x/cb'] }, '127.0.0.1', 'jest'),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('treats missing user row as unverified (defensive)', async () => {
      const prisma = buildPrismaMock();
      prisma.user.findUnique.mockResolvedValueOnce(null);
      const svc = new OAuthRegistrationService(prisma);

      await expect(
        svc.register('user-1', { client_name: 'Demo', redirect_uris: ['https://x/cb'] }, '127.0.0.1', 'jest'),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('rejects when user already has MAX_CLIENTS_PER_USER clients', async () => {
      const prisma = buildPrismaMock({ count: MAX_CLIENTS_PER_USER });
      const svc = new OAuthRegistrationService(prisma);

      await expect(
        svc.register('user-1', { client_name: 'Demo', redirect_uris: ['https://x/cb'] }, '127.0.0.1', 'jest'),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('rejects scope outside whitelist', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      await expect(
        svc.register(
          'user-1',
          { client_name: 'Demo', redirect_uris: ['https://x/cb'], scope: 'openid kyc' },
          '127.0.0.1',
          'jest',
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('accepts custom subset of allowed scopes', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.register(
        'user-1',
        { client_name: 'Demo', redirect_uris: ['https://x/cb'], scope: 'openid email' },
        '127.0.0.1',
        'jest',
      );

      expect(out.scope).toBe('openid email');
      expect(prisma.oAuthClient.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          allowedScopes: ['openid', 'email'],
        }),
      });
    });

    it('writes an audit log row on successful registration', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      await svc.register(
        'user-1',
        { client_name: 'Demo', redirect_uris: ['https://x/cb'] },
        '203.0.113.1',
        'curl/8.0',
      );

      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: 'user-1',
          action: 'OAUTH_CLIENT_REGISTERED',
          ipAddress: '203.0.113.1',
          userAgent: 'curl/8.0',
        }),
      });
    });

    it('includes logo_uri when provided in register response', async () => {
      const prisma = buildPrismaMock({
        createdRow: { logoUri: 'https://example.com/logo.png' },
      });
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.register(
        'user-1',
        {
          client_name: 'Demo',
          redirect_uris: ['https://x/cb'],
          logo_uri: 'https://example.com/logo.png',
        },
        '127.0.0.1',
        'jest',
      );

      expect(out.logo_uri).toBe('https://example.com/logo.png');
    });
  });

  describe('listMine', () => {
    it('returns clients without client_secret', async () => {
      const prisma = buildPrismaMock({
        findFirstRow: [
          {
            id: 'row-id-1',
            clientId: 'demo-1',
            clientSecret: 'should-not-leak-1',
            name: 'Demo 1',
            redirectUris: ['https://x/cb'],
            allowedScopes: ['openid'],
            logoUri: null,
            userId: 'user-1',
            createdAt: new Date('2026-04-28T10:00:00Z'),
            updatedAt: new Date('2026-04-28T10:00:00Z'),
          },
        ],
      });
      prisma.oAuthClient.findMany = jest.fn().mockResolvedValue([
        {
          id: 'row-id-1',
          clientId: 'demo-1',
          clientSecret: 'should-not-leak-1',
          name: 'Demo 1',
          redirectUris: ['https://x/cb'],
          allowedScopes: ['openid'],
          logoUri: null,
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T10:00:00Z'),
        },
      ]);
      const svc = new OAuthRegistrationService(prisma);
      const out: any = await svc.listMine('user-1');

      expect(out).toHaveLength(1);
      expect(out[0].client_id).toBe('demo-1');
      expect((out[0] as any).client_secret).toBeUndefined();
      expect(out[0].client_name).toBe('Demo 1');
    });

    it('returns empty list for user with no clients', async () => {
      const prisma = buildPrismaMock();
      prisma.oAuthClient.findMany = jest.fn().mockResolvedValue([]);
      const svc = new OAuthRegistrationService(prisma);
      const out = await svc.listMine('user-1');
      expect(out).toEqual([]);
    });
  });

  describe('getMine', () => {
    it('returns client without client_secret', async () => {
      const prisma = buildPrismaMock({
        findFirstRow: {
          id: 'row-id',
          clientId: 'demo',
          clientSecret: 'should-not-leak',
          name: 'Demo',
          redirectUris: ['https://x/cb'],
          allowedScopes: ['openid'],
          logoUri: null,
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T10:00:00Z'),
        },
      });
      const svc = new OAuthRegistrationService(prisma);
      const out: any = await svc.getMine('user-1', 'demo');

      expect(out.client_id).toBe('demo');
      expect((out as any).client_secret).toBeUndefined();
      expect(out.client_name).toBe('Demo');
      expect(out.scope).toBe('openid');
    });

    it('throws NotFound when client is not owned by user', async () => {
      const prisma = buildPrismaMock({ findFirstRow: null });
      const svc = new OAuthRegistrationService(prisma);

      await expect(svc.getMine('user-1', 'someone-elses')).rejects.toBeInstanceOf(NotFoundException);
    });

    it('throws NotFound when client does not exist', async () => {
      const prisma = buildPrismaMock({ findFirstRow: null });
      const svc = new OAuthRegistrationService(prisma);

      await expect(svc.getMine('user-1', 'nonexistent')).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('updateMine', () => {
    it('updates client and writes audit log', async () => {
      const prisma = buildPrismaMock({
        findFirstRow: {
          id: 'row-id',
          clientId: 'demo',
          clientSecret: 'secret',
          name: 'Old Name',
          redirectUris: ['https://old/cb'],
          allowedScopes: ['openid'],
          logoUri: null,
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T10:00:00Z'),
        },
        updatedRow: {
          id: 'row-id',
          clientId: 'demo',
          clientSecret: 'secret',
          name: 'New Name',
          redirectUris: ['https://new/cb'],
          allowedScopes: ['openid', 'profile'],
          logoUri: null,
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T11:00:00Z'),
        },
      });
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.updateMine(
        'user-1',
        'demo',
        { client_name: 'New Name', redirect_uris: ['https://new/cb'], scope: 'openid profile' },
        '127.0.0.1',
        'jest',
      );

      expect(out.client_name).toBe('New Name');
      expect(out.redirect_uris).toEqual(['https://new/cb']);
      expect(out.scope).toBe('openid profile');
      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: 'user-1',
          action: 'OAUTH_CLIENT_UPDATED',
        }),
      });
    });

    it('throws NotFound when updating non-owned client', async () => {
      const prisma = buildPrismaMock({ findFirstRow: null });
      const svc = new OAuthRegistrationService(prisma);

      await expect(
        svc.updateMine('user-1', 'foreign', { client_name: 'New' }, '127.0.0.1', 'jest'),
      ).rejects.toBeInstanceOf(NotFoundException);
    });

    it('preserves existing fields when only partial update provided', async () => {
      const prisma = buildPrismaMock({
        findFirstRow: {
          id: 'row-id',
          clientId: 'demo',
          clientSecret: 'secret',
          name: 'Original',
          redirectUris: ['https://x/cb'],
          allowedScopes: ['openid', 'email'],
          logoUri: 'https://logo.png',
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T10:00:00Z'),
        },
        updatedRow: {
          id: 'row-id',
          clientId: 'demo',
          clientSecret: 'secret',
          name: 'Updated',
          redirectUris: ['https://x/cb'],
          allowedScopes: ['openid', 'email'],
          logoUri: 'https://logo.png',
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T11:00:00Z'),
        },
      });
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.updateMine(
        'user-1',
        'demo',
        { client_name: 'Updated' },
        '127.0.0.1',
        'jest',
      );

      expect(out.client_name).toBe('Updated');
      expect(out.redirect_uris).toEqual(['https://x/cb']);
      expect(out.scope).toBe('openid email');
      expect(out.logo_uri).toBe('https://logo.png');
    });
  });

  describe('deleteMine', () => {
    it('deletes client and writes audit log', async () => {
      const prisma = buildPrismaMock({
        findFirstRow: {
          id: 'row-id',
          clientId: 'demo',
          clientSecret: 'secret',
          name: 'Demo',
          redirectUris: ['https://x/cb'],
          allowedScopes: ['openid'],
          logoUri: null,
          userId: 'user-1',
          createdAt: new Date('2026-04-28T10:00:00Z'),
          updatedAt: new Date('2026-04-28T10:00:00Z'),
        },
      });
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.deleteMine('user-1', 'demo', '127.0.0.1', 'jest');

      expect(out.deleted).toBe(true);
      expect(out.client_id).toBe('demo');
      expect(prisma.oAuthClient.delete).toHaveBeenCalledWith({ where: { id: 'row-id' } });
      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: 'user-1',
          action: 'OAUTH_CLIENT_DELETED',
          ipAddress: '127.0.0.1',
        }),
      });
    });

    it('throws NotFound when deleting non-owned client', async () => {
      const prisma = buildPrismaMock({ findFirstRow: null });
      const svc = new OAuthRegistrationService(prisma);

      await expect(svc.deleteMine('user-1', 'foreign', '127.0.0.1', 'jest')).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('scope validation', () => {
    it('parses space-separated scopes correctly', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.register(
        'user-1',
        {
          client_name: 'Demo',
          redirect_uris: ['https://x/cb'],
          scope: '  openid   profile  ',
        },
        '127.0.0.1',
        'jest',
      );

      expect(out.scope).toBe('openid profile');
    });

    it('rejects mixed valid and invalid scopes', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      await expect(
        svc.register(
          'user-1',
          {
            client_name: 'Demo',
            redirect_uris: ['https://x/cb'],
            scope: 'openid kyc profile',
          },
          '127.0.0.1',
          'jest',
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('defaults to all allowed scopes when scope not provided', async () => {
      const prisma = buildPrismaMock();
      const svc = new OAuthRegistrationService(prisma);

      const out = await svc.register(
        'user-1',
        {
          client_name: 'Demo',
          redirect_uris: ['https://x/cb'],
        },
        '127.0.0.1',
        'jest',
      );

      expect(out.scope).toBe('openid profile email offline_access');
    });
  });
});
