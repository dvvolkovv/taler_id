import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InviteService } from './invite.service';

describe('InviteService', () => {
  let service: InviteService;
  let prisma: any;

  const conv = (over: any = {}) => ({ id: 'conv-1', type: 'GROUP', isSystem: false, ...over });

  beforeEach(() => {
    prisma = {
      conversation: {
        findUnique: jest.fn().mockResolvedValue(conv()),
        findFirst: jest.fn().mockResolvedValue(null),
        update: jest.fn().mockResolvedValue({}),
      },
      conversationParticipant: {
        findUnique: jest.fn().mockResolvedValue({ role: 'OWNER' }),
        create: jest.fn().mockResolvedValue({}),
      },
      conversationInvite: {
        count: jest.fn().mockResolvedValue(0),
        create: jest.fn().mockImplementation(({ data }: any) => ({ id: 'inv-1', uses: 0, ...data })),
        findUnique: jest.fn(),
        findMany: jest.fn().mockResolvedValue([]),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      user: { findFirst: jest.fn().mockResolvedValue(null) },
    };
    service = new InviteService(prisma);
  });

  describe('creating', () => {
    it('creates an invite with a link', async () => {
      const out = await service.createInvite('conv-1', 'u-owner');
      expect(out.code).toBeTruthy();
      expect(out.url).toContain(`/invite/${out.code}`);
    });

    it('refuses a plain member', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
      await expect(service.createInvite('conv-1', 'u-member'))
        .rejects.toThrow(ForbiddenException);
    });

    it('refuses someone outside the conversation', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);
      await expect(service.createInvite('conv-1', 'u-stranger'))
        .rejects.toThrow(ForbiddenException);
    });

    it('refuses a direct conversation', async () => {
      // Позвать третьего в личную переписку — это уже другая беседа.
      prisma.conversation.findUnique.mockResolvedValue(conv({ type: 'DIRECT' }));
      await expect(service.createInvite('conv-1', 'u-owner'))
        .rejects.toThrow(BadRequestException);
    });

    it('caps the number of live invites', async () => {
      prisma.conversationInvite.count.mockResolvedValue(20);
      await expect(service.createInvite('conv-1', 'u-owner'))
        .rejects.toThrow(BadRequestException);
    });

    it('rejects nonsensical limits', async () => {
      await expect(service.createInvite('conv-1', 'u-owner', { maxUses: 0 }))
        .rejects.toThrow(BadRequestException);
      await expect(service.createInvite('conv-1', 'u-owner', { expiresInHours: -1 }))
        .rejects.toThrow(BadRequestException);
    });
  });

  describe('joining', () => {
    const invite = (over: any = {}) => ({
      id: 'inv-1', code: 'CODE', conversationId: 'conv-1',
      revokedAt: null, expiresAt: null, maxUses: null, uses: 0, ...over,
    });

    it('adds the caller to the conversation', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(invite());
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      const out = await service.joinByInvite('CODE', 'u-new');

      expect(out).toEqual({ conversationId: 'conv-1', joined: true, already: false });
      expect(prisma.conversationParticipant.create).toHaveBeenCalledWith({
        data: { conversationId: 'conv-1', userId: 'u-new', role: 'MEMBER' },
      });
    });

    it('makes a channel joiner a subscriber, not a member', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(invite());
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);
      prisma.conversation.findUnique.mockResolvedValue(conv({ type: 'CHANNEL' }));

      await service.joinByInvite('CODE', 'u-new');

      expect(prisma.conversationParticipant.create).toHaveBeenCalledWith({
        data: { conversationId: 'conv-1', userId: 'u-new', role: 'SUBSCRIBER' },
      });
    });

    it('does not burn a use when the caller is already in', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(invite({ maxUses: 1 }));
      prisma.conversationParticipant.findUnique.mockResolvedValue({ id: 'p-1' });

      const out = await service.joinByInvite('CODE', 'u-old');

      expect(out.already).toBe(true);
      expect(prisma.conversationInvite.updateMany).not.toHaveBeenCalled();
      expect(prisma.conversationParticipant.create).not.toHaveBeenCalled();
    });

    it('refuses a revoked invite', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(invite({ revokedAt: new Date() }));
      await expect(service.joinByInvite('CODE', 'u-new')).rejects.toThrow(/revoked/);
    });

    it('refuses an expired invite', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(
        invite({ expiresAt: new Date(Date.now() - 1000) }),
      );
      await expect(service.joinByInvite('CODE', 'u-new')).rejects.toThrow(/expired/);
    });

    it('claims the last seat atomically', async () => {
      // Две одновременные попытки на одно место: побеждает та, чей UPDATE
      // прошёл по условию, вторая получает отказ, а не тихо просачивается.
      prisma.conversationInvite.findUnique.mockResolvedValue(invite({ maxUses: 1, uses: 0 }));
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);
      prisma.conversationInvite.updateMany.mockResolvedValue({ count: 0 });

      await expect(service.joinByInvite('CODE', 'u-slow')).rejects.toThrow(/exhausted/);
      expect(prisma.conversationParticipant.create).not.toHaveBeenCalled();
    });

    it('increments through a predicate, not a read-then-write', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(invite({ maxUses: 5, uses: 2 }));
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await service.joinByInvite('CODE', 'u-new');

      expect(prisma.conversationInvite.updateMany).toHaveBeenCalledWith({
        where: { id: 'inv-1', uses: { lt: 5 }, revokedAt: null },
        data: { uses: { increment: 1 } },
      });
    });

    it('reports an unknown code', async () => {
      prisma.conversationInvite.findUnique.mockResolvedValue(null);
      await expect(service.joinByInvite('NOPE', 'u-new')).rejects.toThrow(NotFoundException);
    });
  });

  describe('public username', () => {
    it('stores a normalized handle', async () => {
      const out = await service.setPublicUsername('conv-1', 'u-owner', '@TalerNews');
      expect(out.publicUsername).toBe('talernews');
      expect(prisma.conversation.update).toHaveBeenCalledWith({
        where: { id: 'conv-1' },
        data: { publicUsername: 'talernews' },
      });
    });

    it('refuses a handle already used by a person', async () => {
      // Пространство имён одно: @name не должно означать то группу, то человека.
      prisma.user.findFirst.mockResolvedValue({ id: 'u-anna' });
      await expect(service.setPublicUsername('conv-1', 'u-owner', 'anna_k'))
        .rejects.toThrow(ConflictException);
    });

    it('refuses a handle already used by another conversation', async () => {
      prisma.conversation.findFirst.mockResolvedValue({ id: 'conv-2' });
      await expect(service.setPublicUsername('conv-1', 'u-owner', 'talernews'))
        .rejects.toThrow(ConflictException);
    });

    it('refuses a malformed handle', async () => {
      await expect(service.setPublicUsername('conv-1', 'u-owner', 'no'))
        .rejects.toThrow(BadRequestException);
      await expect(service.setPublicUsername('conv-1', 'u-owner', '2026news'))
        .rejects.toThrow(BadRequestException);
    });

    it('clears the handle on empty input', async () => {
      const out = await service.setPublicUsername('conv-1', 'u-owner', '');
      expect(out.publicUsername).toBeNull();
      expect(prisma.conversation.update).toHaveBeenCalledWith({
        where: { id: 'conv-1' },
        data: { publicUsername: null },
      });
    });

    it('refuses a plain member changing it', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
      await expect(service.setPublicUsername('conv-1', 'u-member', 'talernews'))
        .rejects.toThrow(ForbiddenException);
    });
  });
});
