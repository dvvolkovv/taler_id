import { Test, TestingModule } from '@nestjs/testing';
import { PresenceService } from './presence.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';

describe('PresenceService', () => {
  let service: PresenceService;

  const mockRedis = {
    setEx: jest.fn().mockResolvedValue(undefined),
    get: jest.fn(),
    getClient: jest.fn(),
  };

  const mockExists = jest.fn();
  const mockSet = jest.fn();

  const mockPrisma = {
    profile: {
      findUnique: jest.fn(),
      update: jest.fn().mockResolvedValue({}),
    },
    contactRequest: {
      findFirst: jest.fn(),
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    // Re-bind the redis client mock each test so a future
    // jest.resetAllMocks() wouldn't strip the return value.
    mockRedis.getClient.mockReturnValue({ exists: mockExists, set: mockSet });
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PresenceService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: RedisService, useValue: mockRedis },
      ],
    }).compile();
    service = module.get(PresenceService);
  });

  describe('ping', () => {
    it('sets Redis online key with 90s TTL', async () => {
      mockSet.mockResolvedValue('OK');
      await service.ping('user-a');
      expect(mockRedis.setEx).toHaveBeenCalledWith('presence:online:user-a', 90, '1');
    });

    it('writes Profile.lastSeenAt + atomically acquires dbwrite throttle key on first call', async () => {
      mockSet.mockResolvedValue('OK');
      await service.ping('user-a');
      expect(mockSet).toHaveBeenCalledWith('presence:dbwrite:user-a', '1', 'EX', 60, 'NX');
      expect(mockPrisma.profile.update).toHaveBeenCalledWith({
        where: { userId: 'user-a' },
        data: { lastSeenAt: expect.any(Date) },
      });
    });

    it('skips Profile update when atomic SET NX returns null (throttle key already exists)', async () => {
      mockSet.mockResolvedValue(null);
      await service.ping('user-a');
      expect(mockPrisma.profile.update).not.toHaveBeenCalled();
    });
  });

  describe('getPresence', () => {
    it('returns real data when target privacy is EVERYONE', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({
        lastSeenPrivacy: 'EVERYONE',
        lastSeenAt: new Date('2026-05-14T07:00:00Z'),
      });
      mockExists.mockResolvedValue(1);
      const r = await service.getPresence('viewer', 'target');
      expect(r).toEqual({ isOnline: true, lastSeenAt: '2026-05-14T07:00:00.000Z', hidden: false });
    });

    it('returns real data when target=CONTACTS and accepted contact exists', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({
        lastSeenPrivacy: 'CONTACTS',
        lastSeenAt: new Date('2026-05-14T07:00:00Z'),
      });
      mockPrisma.contactRequest.findFirst.mockResolvedValue({ id: 'cr-1' });
      mockExists.mockResolvedValue(0);
      const r = await service.getPresence('viewer', 'target');
      expect(r.hidden).toBe(false);
      expect(r.isOnline).toBe(false);
    });

    it('returns hidden=true when target=CONTACTS and no accepted contact', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({
        lastSeenPrivacy: 'CONTACTS',
        lastSeenAt: new Date(),
      });
      mockPrisma.contactRequest.findFirst.mockResolvedValue(null);
      const r = await service.getPresence('viewer', 'target');
      expect(r).toEqual({ isOnline: null, lastSeenAt: null, hidden: true });
    });

    it('returns hidden=true when target=NOBODY', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({
        lastSeenPrivacy: 'NOBODY',
        lastSeenAt: new Date(),
      });
      const r = await service.getPresence('viewer', 'target');
      expect(r).toEqual({ isOnline: null, lastSeenAt: null, hidden: true });
    });

    it('bypasses privacy when viewer === target (self)', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({
        lastSeenPrivacy: 'NOBODY',
        lastSeenAt: new Date('2026-05-14T07:00:00Z'),
      });
      mockExists.mockResolvedValue(1);
      const r = await service.getPresence('user-a', 'user-a');
      expect(r.hidden).toBe(false);
      expect(r.isOnline).toBe(true);
    });

    it('returns isOnline=false when Redis key absent but Profile has lastSeenAt', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({
        lastSeenPrivacy: 'EVERYONE',
        lastSeenAt: new Date('2026-05-14T07:00:00Z'),
      });
      mockExists.mockResolvedValue(0);
      const r = await service.getPresence('viewer', 'target');
      expect(r.isOnline).toBe(false);
      expect(r.lastSeenAt).toBe('2026-05-14T07:00:00.000Z');
    });

    it('returns hidden=true when target profile not found', async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);
      const r = await service.getPresence('viewer', 'target');
      expect(r).toEqual({ isOnline: null, lastSeenAt: null, hidden: true });
    });
  });
});
