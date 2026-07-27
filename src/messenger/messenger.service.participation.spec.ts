import { ForbiddenException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

// Regression cover for the write-path authorisation holes found in the
// 2026-07-27 audit: createMessage and sendThreadReply accepted any
// conversationId from an authenticated caller without checking membership.
describe('MessengerService write-path participation checks', () => {
  let service: MessengerService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      conversationParticipant: { findUnique: jest.fn() },
      message: { create: jest.fn(), findUnique: jest.fn(), findFirst: jest.fn() },
    };

    // Only the collaborators these two paths touch are needed.
    service = new MessengerService(
      prisma,
      { get: jest.fn(), setEx: jest.fn(), del: jest.fn() } as any,
      {} as any,
      {} as any,
      {} as any,
    );
  });

  describe('createMessage', () => {
    it('refuses to write into a conversation the sender does not belong to', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(
        service.createMessage('someone-elses-conv', 'intruder', 'hello'),
      ).rejects.toThrow(ForbiddenException);

      expect(prisma.message.create).not.toHaveBeenCalled();
    });

    it('checks membership before any write happens', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(
        service.createMessage('conv-1', 'intruder', 'x'.repeat(30)),
      ).rejects.toThrow(ForbiddenException);

      // The dedup lookup must not run either — nothing about the conversation
      // should be observable to a non-participant.
      expect(prisma.message.findFirst).not.toHaveBeenCalled();
    });
  });

  describe('sendThreadReply', () => {
    it('refuses a thread reply from a non-participant', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(
        service.sendThreadReply('conv-1', 'intruder', 'reply', 'parent-1'),
      ).rejects.toThrow(ForbiddenException);

      expect(prisma.message.create).not.toHaveBeenCalled();
    });

    it('does not leak whether the parent message exists', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue(null);

      await expect(
        service.sendThreadReply('conv-1', 'intruder', 'reply', 'parent-1'),
      ).rejects.toThrow(ForbiddenException);

      // Membership is asserted before the parent lookup, so a non-participant
      // cannot probe message ids.
      expect(prisma.message.findUnique).not.toHaveBeenCalled();
    });

    it('proceeds for a genuine participant', async () => {
      prisma.conversationParticipant.findUnique.mockResolvedValue({
        conversationId: 'conv-1',
        userId: 'member',
        role: 'MEMBER',
      });
      prisma.message.findUnique.mockResolvedValue({
        id: 'parent-1',
        conversationId: 'conv-1',
      });
      prisma.message.create.mockResolvedValue({ id: 'msg-1' });

      const msg = await service.sendThreadReply(
        'conv-1',
        'member',
        'reply',
        'parent-1',
      );

      expect(msg).toEqual({ id: 'msg-1' });
      expect(prisma.message.create).toHaveBeenCalled();
    });
  });
});
