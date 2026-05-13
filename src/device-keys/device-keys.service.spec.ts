import { Test, TestingModule } from '@nestjs/testing';
import { DeviceKeysService } from './device-keys.service';
import { PrismaService } from '../prisma/prisma.service';
import { FcmService } from '../common/fcm.service';
import { BadRequestException, NotFoundException } from '@nestjs/common';

describe('DeviceKeysService', () => {
  let service: DeviceKeysService;
  let prisma: jest.Mocked<PrismaService>;
  let fcm: jest.Mocked<FcmService>;

  beforeEach(async () => {
    const prismaMock = {
      deviceKey: {
        create: jest.fn(),
        findMany: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
      },
      user: {
        findUnique: jest.fn(),
      },
    };
    const fcmMock = {
      sendKeyUpdate: jest.fn().mockResolvedValue(undefined),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeviceKeysService,
        { provide: PrismaService, useValue: prismaMock },
        { provide: FcmService, useValue: fcmMock },
      ],
    }).compile();

    service = module.get<DeviceKeysService>(DeviceKeysService);
    prisma = module.get(PrismaService);
    fcm = module.get(FcmService);
  });

  describe('register', () => {
    const validDto = {
      devicePk: 'a'.repeat(64),
      algorithm: 'X25519',
      validUntilEpochMs: Date.now() + 30 * 86_400_000,
      signature: 'f'.repeat(128),
      certificate: JSON.stringify({
        algorithm: 'X25519',
        devicePk: 'a'.repeat(64),
        userId: 'user-1',
        validUntilEpochMs: Date.now() + 30 * 86_400_000,
      }),
    };

    it('rejects unsupported algorithm', async () => {
      await expect(
        service.register('user-1', { ...validDto, algorithm: 'ED25519' }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('rejects expired validUntil', async () => {
      await expect(
        service.register('user-1', {
          ...validDto,
          validUntilEpochMs: Date.now() - 1000,
        }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('creates device key record and returns response DTO', async () => {
      const created = {
        id: 'dk-1',
        userId: 'user-1',
        devicePk: validDto.devicePk,
        algorithm: validDto.algorithm,
        validUntil: new Date(validDto.validUntilEpochMs),
        certificate: validDto.certificate,
        signature: validDto.signature,
        revokedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      (prisma.deviceKey.create as any).mockResolvedValue(created);

      const result = await service.register('user-1', validDto);

      expect(prisma.deviceKey.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: 'user-1',
          devicePk: validDto.devicePk,
          algorithm: 'X25519',
        }),
      });
      expect(result.devicePk).toBe(validDto.devicePk);
      expect(result.revokedAt).toBeNull();
    });

    it('extracts userPk from certificate JSON and persists it', async () => {
      const validUntil = Date.now() + 30 * 86_400_000;
      const userPk = 'c'.repeat(64);
      const certJson = JSON.stringify({
        algorithm: 'X25519',
        devicePk: 'a'.repeat(64),
        userId: 'user-1',
        userPk,
        validUntilEpochMs: validUntil,
      });
      prisma.deviceKey.create.mockResolvedValue({
        id: 'dk-2',
        userId: 'user-1',
        devicePk: 'a'.repeat(64),
        userPk,
        algorithm: 'X25519',
        validUntil: new Date(validUntil),
        certificate: certJson,
        signature: 'f'.repeat(128),
        revokedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      const result = await service.register('user-1', {
        devicePk: 'a'.repeat(64),
        algorithm: 'X25519',
        validUntilEpochMs: validUntil,
        signature: 'f'.repeat(128),
        certificate: certJson,
      });

      expect(prisma.deviceKey.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: 'user-1',
          devicePk: 'a'.repeat(64),
          userPk,
          algorithm: 'X25519',
        }),
      });
      expect(result.userPk).toBe(userPk);
    });

    it('tolerates cert without userPk (Phase 1b compat)', async () => {
      const validUntil = Date.now() + 30 * 86_400_000;
      const certJson = JSON.stringify({
        algorithm: 'X25519',
        devicePk: 'a'.repeat(64),
        userId: 'user-1',
        validUntilEpochMs: validUntil,
      });
      prisma.deviceKey.create.mockResolvedValue({
        id: 'dk-3',
        userId: 'user-1',
        devicePk: 'a'.repeat(64),
        userPk: null,
        algorithm: 'X25519',
        validUntil: new Date(validUntil),
        certificate: certJson,
        signature: 'f'.repeat(128),
        revokedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      const result = await service.register('user-1', {
        devicePk: 'a'.repeat(64),
        algorithm: 'X25519',
        validUntilEpochMs: validUntil,
        signature: 'f'.repeat(128),
        certificate: certJson,
      });

      expect(prisma.deviceKey.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userPk: null,
        }),
      });
      expect(result.userPk).toBeNull();
    });

    it('tolerates malformed cert JSON (stores userPk=null)', async () => {
      const validUntil = Date.now() + 30 * 86_400_000;
      prisma.deviceKey.create.mockResolvedValue({
        id: 'dk-4',
        userId: 'user-1',
        devicePk: 'a'.repeat(64),
        userPk: null,
        algorithm: 'X25519',
        validUntil: new Date(validUntil),
        certificate: 'not-json',
        signature: 'f'.repeat(128),
        revokedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      await service.register('user-1', {
        devicePk: 'a'.repeat(64),
        algorithm: 'X25519',
        validUntilEpochMs: validUntil,
        signature: 'f'.repeat(128),
        certificate: 'not-json',
      });

      expect(prisma.deviceKey.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ userPk: null }),
      });
    });
  });

  describe('listForContact', () => {
    it('returns only non-revoked keys', async () => {
      (prisma.user.findUnique as any).mockResolvedValue({ id: 'user-2' });
      (prisma.deviceKey.findMany as any).mockResolvedValue([
        {
          id: 'dk-2',
          userId: 'user-2',
          devicePk: 'b'.repeat(64),
          algorithm: 'X25519',
          validUntil: new Date(Date.now() + 86_400_000),
          certificate: '{}',
          signature: 'c'.repeat(128),
          revokedAt: null,
          createdAt: new Date(),
        },
      ]);

      const keys = await service.listForContact('user-1', 'user-2');

      expect(keys).toHaveLength(1);
      expect(prisma.deviceKey.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            userId: 'user-2',
            revokedAt: null,
            validUntil: { gt: expect.any(Date) },
          }),
        }),
      );
    });

    it('throws NotFound when user does not exist', async () => {
      (prisma.user.findUnique as any).mockResolvedValue(null);
      await expect(
        service.listForContact('user-1', 'missing'),
      ).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('revoke', () => {
    it('marks key revoked and pushes update', async () => {
      (prisma.deviceKey.findUnique as any).mockResolvedValue({
        id: 'dk-1',
        userId: 'user-1',
        revokedAt: null,
      });
      (prisma.deviceKey.update as any).mockResolvedValue({
        id: 'dk-1',
        userId: 'user-1',
        devicePk: 'a'.repeat(64),
        algorithm: 'X25519',
        validUntil: new Date(Date.now() + 86_400_000),
        certificate: '{}',
        signature: 'f'.repeat(128),
        revokedAt: new Date(),
        createdAt: new Date(),
      });

      await service.revoke('user-1', 'dk-1', {});

      expect(prisma.deviceKey.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'dk-1' },
          data: expect.objectContaining({ revokedAt: expect.any(Date) }),
        }),
      );
      // sendKeyUpdate is fire-and-forget — await microtask flush before assertion
      await new Promise((r) => setImmediate(r));
      expect(fcm.sendKeyUpdate).toHaveBeenCalledWith('user-1');
    });

    it('refuses to revoke key owned by another user', async () => {
      (prisma.deviceKey.findUnique as any).mockResolvedValue({
        id: 'dk-1',
        userId: 'other-user',
      });
      await expect(service.revoke('user-1', 'dk-1', {})).rejects.toBeInstanceOf(
        NotFoundException,
      );
    });
  });
});
