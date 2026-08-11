import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { ReadReceiptsService } from './read-receipts.service';

describe('ReadReceiptsService', () => {
  let service: ReadReceiptsService;
  let prisma: any;

  const t = (iso: string) => new Date(iso);

  beforeEach(() => {
    prisma = {
      conversationParticipant: {
        findMany: jest.fn().mockResolvedValue([]),
        findUnique: jest.fn().mockResolvedValue({ id: 'p-me' }),
        count: jest.fn().mockResolvedValue(0),
      },
      message: { findUnique: jest.fn() },
      user: { findMany: jest.fn().mockResolvedValue([]) },
    };
    service = new ReadReceiptsService(prisma);
  });

  describe('viewCountsFor', () => {
    const msg = (id: string, iso: string, senderId = 'u-author') => ({
      id, sentAt: t(iso), senderId,
    });

    it('counts only cursors that reached the message', async () => {
      prisma.conversationParticipant.findMany.mockResolvedValue([
        { userId: 'u-1', lastReadAt: t('2026-08-11T12:00:00Z') },
        { userId: 'u-2', lastReadAt: t('2026-08-11T10:00:00Z') },
      ]);

      const out = await service.viewCountsFor('conv-1', [msg('m1', '2026-08-11T11:00:00Z')]);

      expect(out.m1).toBe(1);
    });

    it('counts a cursor exactly at the send time', async () => {
      prisma.conversationParticipant.findMany.mockResolvedValue([
        { userId: 'u-1', lastReadAt: t('2026-08-11T11:00:00Z') },
      ]);

      const out = await service.viewCountsFor('conv-1', [msg('m1', '2026-08-11T11:00:00Z')]);

      expect(out.m1).toBe(1);
    });

    it('never counts the author as a viewer of their own post', async () => {
      prisma.conversationParticipant.findMany.mockResolvedValue([
        { userId: 'u-author', lastReadAt: t('2026-08-11T23:00:00Z') },
        { userId: 'u-1', lastReadAt: t('2026-08-11T23:00:00Z') },
      ]);

      const out = await service.viewCountsFor('conv-1', [msg('m1', '2026-08-11T11:00:00Z')]);

      expect(out.m1).toBe(1);
    });

    it('handles a page of messages with one query, not one per message', async () => {
      // У системного канала двенадцать тысяч подписчиков: запрос на каждое
      // сообщение страницы означал бы тридцать проходов по ним.
      prisma.conversationParticipant.findMany.mockResolvedValue([
        { userId: 'u-1', lastReadAt: t('2026-08-11T12:00:00Z') },
      ]);

      const out = await service.viewCountsFor('conv-1', [
        msg('m1', '2026-08-11T11:00:00Z'),
        msg('m2', '2026-08-11T13:00:00Z'),
      ]);

      expect(prisma.conversationParticipant.findMany).toHaveBeenCalledTimes(1);
      expect(out).toEqual({ m1: 1, m2: 0 });
    });

    it('does not query at all for an empty page', async () => {
      expect(await service.viewCountsFor('conv-1', [])).toEqual({});
      expect(prisma.conversationParticipant.findMany).not.toHaveBeenCalled();
    });
  });

  describe('readersOf', () => {
    beforeEach(() => {
      prisma.message.findUnique.mockResolvedValue({
        id: 'm1',
        conversationId: 'conv-1',
        sentAt: t('2026-08-11T11:00:00Z'),
        senderId: 'u-author',
        deletedAt: null,
      });
    });

    it('lists readers with names', async () => {
      prisma.conversationParticipant.count.mockResolvedValue(1);
      prisma.conversationParticipant.findMany.mockResolvedValue([
        { userId: 'u-1', lastReadAt: t('2026-08-11T12:00:00Z') },
      ]);
      prisma.user.findMany.mockResolvedValue([
        { id: 'u-1', username: 'anna', profile: { firstName: 'Аня', lastName: 'А', avatarUrl: null } },
      ]);

      const out = await service.readersOf('m1', 'u-author');

      expect(out.total).toBe(1);
      expect(out.readers[0].name).toBe('Аня А');
      expect(out.truncated).toBe(false);
    });

    it('excludes the author from the query', async () => {
      await service.readersOf('m1', 'u-author');

      expect(prisma.conversationParticipant.count).toHaveBeenCalledWith({
        where: expect.objectContaining({ NOT: { userId: 'u-author' } }),
      });
    });

    it('says the list is truncated when there are more readers than shown', async () => {
      prisma.conversationParticipant.count.mockResolvedValue(500);
      prisma.conversationParticipant.findMany.mockResolvedValue(
        Array.from({ length: 50 }, (_, i) => ({ userId: `u-${i}`, lastReadAt: t('2026-08-11T12:00:00Z') })),
      );

      const out = await service.readersOf('m1', 'u-author');

      expect(out.total).toBe(500);
      expect(out.readers).toHaveLength(50);
      expect(out.truncated).toBe(true);
    });

    it('refuses someone outside the conversation', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(service.readersOf('m1', 'u-stranger')).rejects.toThrow(ForbiddenException);
    });

    it('refuses a deleted message', async () => {
      prisma.message.findUnique.mockResolvedValue({
        id: 'm1', conversationId: 'conv-1', sentAt: t('2026-08-11T11:00:00Z'),
        senderId: 'u-author', deletedAt: new Date(),
      });

      await expect(service.readersOf('m1', 'u-author')).rejects.toThrow(NotFoundException);
    });

    it('falls back to the username when there is no name', async () => {
      prisma.conversationParticipant.count.mockResolvedValue(1);
      prisma.conversationParticipant.findMany.mockResolvedValue([
        { userId: 'u-1', lastReadAt: t('2026-08-11T12:00:00Z') },
      ]);
      prisma.user.findMany.mockResolvedValue([
        { id: 'u-1', username: 'anna', profile: null },
      ]);

      const out = await service.readersOf('m1', 'u-author');

      expect(out.readers[0].name).toBe('anna');
    });
  });
});
