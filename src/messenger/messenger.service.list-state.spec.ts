import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

/**
 * Черновик, архив и закрепление беседы — персональное состояние участника.
 * До этого оно лежало в локальном Hive и на втором устройстве человека просто
 * не существовало.
 */
describe('MessengerService conversation list state', () => {
  let service: MessengerService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      conversationParticipant: {
        findUnique: jest.fn().mockResolvedValue({ role: 'MEMBER' }),
        update: jest.fn().mockImplementation(({ data }: any) => ({ ...data })),
      },
    };
    service = new MessengerService(prisma, {} as any);
  });

  const whereMine = {
    conversationId_userId: { conversationId: 'conv-1', userId: 'u-1' },
  };

  describe('draft', () => {
    it('stores the text against the participant, not the conversation', async () => {
      await service.setDraft('conv-1', 'u-1', 'недописанное');

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { draft: 'недописанное', draftAt: expect.any(Date) },
      });
    });

    it('clears the draft when the text is emptied', async () => {
      await service.setDraft('conv-1', 'u-1', '');

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { draft: null, draftAt: null },
      });
    });

    it('treats whitespace as empty', async () => {
      // Иначе «стёр текст, остался пробел» оставлял бы чат с вечным черновиком.
      await service.setDraft('conv-1', 'u-1', '   \n  ');

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { draft: null, draftAt: null },
      });
    });

    it('refuses a draft in a conversation the user is not in', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(
        service.setDraft('conv-1', 'u-stranger', 'подсматриваю'),
      ).rejects.toThrow(ForbiddenException);
      expect(prisma.conversationParticipant.update).not.toHaveBeenCalled();
    });

    it('rejects a draft longer than the message limit', async () => {
      await expect(
        service.setDraft('conv-1', 'u-1', 'я'.repeat(20001)),
      ).rejects.toThrow(BadRequestException);
      expect(prisma.conversationParticipant.update).not.toHaveBeenCalled();
    });
  });

  describe('archive', () => {
    it('archives with a timestamp rather than a flag', async () => {
      await service.setArchived('conv-1', 'u-1', true);

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { archivedAt: expect.any(Date) },
      });
    });

    it('unarchives by clearing it', async () => {
      await service.setArchived('conv-1', 'u-1', false);

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { archivedAt: null },
      });
    });

    it('refuses to archive a conversation the user is not in', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(
        service.setArchived('conv-1', 'u-stranger', true),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('chat pin', () => {
    it('pins with a timestamp so the order of pinned chats is defined', async () => {
      await service.setChatPinned('conv-1', 'u-1', true);

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { chatPinnedAt: expect.any(Date) },
      });
    });

    it('unpins by clearing it', async () => {
      await service.setChatPinned('conv-1', 'u-1', false);

      expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
        where: whereMine,
        data: { chatPinnedAt: null },
      });
    });

    it('is independent from message pinning', async () => {
      // Закрепление чата в списке и закрепление сообщения внутри чата —
      // разные вещи с похожими именами; лезть в Message здесь нечего.
      await service.setChatPinned('conv-1', 'u-1', true);

      expect(prisma.message).toBeUndefined();
    });
  });
});
