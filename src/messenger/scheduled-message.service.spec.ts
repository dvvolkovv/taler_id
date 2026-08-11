import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { ScheduledMessageService } from './scheduled-message.service';

describe('ScheduledMessageService', () => {
  let service: ScheduledMessageService;
  let prisma: any;
  let messenger: any;
  let gateway: any;

  const inAnHour = () => new Date(Date.now() + 3600_000).toISOString();

  beforeEach(() => {
    prisma = {
      scheduledMessage: {
        count: jest.fn().mockResolvedValue(0),
        create: jest.fn().mockImplementation(({ data }: any) => ({ id: 's-1', ...data })),
        findUnique: jest.fn(),
        findMany: jest.fn().mockResolvedValue([]),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
    };
    messenger = {
      assertParticipant: jest.fn().mockResolvedValue({}),
      createMessage: jest.fn().mockResolvedValue({ id: 'm-1', conversationId: 'conv-1' }),
      getUserDisplayName: jest.fn().mockResolvedValue('Аня'),
      loadReplyPreview: jest.fn().mockResolvedValue(null),
    };
    gateway = {
      broadcastNewMessage: jest.fn(),
      fanOutToParticipants: jest.fn().mockResolvedValue(undefined),
    };
    service = new ScheduledMessageService(prisma, messenger, gateway);
  });

  describe('scheduling', () => {
    it('stores a scheduled message', async () => {
      const out = await service.schedule('conv-1', 'u-1', {
        content: 'позже', sendAt: inAnHour(),
      });
      expect(out.content).toBe('позже');
      expect(prisma.scheduledMessage.create).toHaveBeenCalled();
    });

    it('checks the right to post now, not at send time', async () => {
      // Узнать об отказе через сутки — худшее из возможного.
      messenger.assertParticipant.mockRejectedValue(new ForbiddenException());
      await expect(service.schedule('conv-1', 'u-stranger', {
        content: 'позже', sendAt: inAnHour(),
      })).rejects.toThrow(ForbiddenException);
      expect(prisma.scheduledMessage.create).not.toHaveBeenCalled();
    });

    it('refuses a time in the past', async () => {
      await expect(service.schedule('conv-1', 'u-1', {
        content: 'x', sendAt: new Date(Date.now() - 1000).toISOString(),
      })).rejects.toThrow(BadRequestException);
    });

    it('refuses an almost-now time', async () => {
      // «Отложить на пять секунд» — это обычная отправка.
      await expect(service.schedule('conv-1', 'u-1', {
        content: 'x', sendAt: new Date(Date.now() + 5_000).toISOString(),
      })).rejects.toThrow(BadRequestException);
    });

    it('refuses an absurdly distant time', async () => {
      await expect(service.schedule('conv-1', 'u-1', {
        content: 'x', sendAt: new Date(Date.now() + 400 * 24 * 3600_000).toISOString(),
      })).rejects.toThrow(BadRequestException);
    });

    it('refuses a broken date', async () => {
      await expect(service.schedule('conv-1', 'u-1', {
        content: 'x', sendAt: 'когда-нибудь',
      })).rejects.toThrow(BadRequestException);
    });

    it('refuses an empty message with no file', async () => {
      await expect(service.schedule('conv-1', 'u-1', {
        content: '   ', sendAt: inAnHour(),
      })).rejects.toThrow(BadRequestException);
    });

    it('allows an empty caption when a file is attached', async () => {
      await expect(service.schedule('conv-1', 'u-1', {
        content: '', sendAt: inAnHour(), fileUrl: 'https://s3/x.png',
      })).resolves.toBeTruthy();
    });

    it('caps how many can be pending', async () => {
      prisma.scheduledMessage.count.mockResolvedValue(100);
      await expect(service.schedule('conv-1', 'u-1', {
        content: 'x', sendAt: inAnHour(),
      })).rejects.toThrow(BadRequestException);
    });
  });

  describe('cancelling', () => {
    it('cancels own message', async () => {
      prisma.scheduledMessage.findUnique.mockResolvedValue({
        id: 's-1', senderId: 'u-1', sentAt: null, cancelledAt: null,
      });
      const out = await service.cancel('s-1', 'u-1');
      expect(out.cancelled).toBe(true);
    });

    it('refuses to cancel somebody else’s', async () => {
      prisma.scheduledMessage.findUnique.mockResolvedValue({
        id: 's-1', senderId: 'u-other', sentAt: null, cancelledAt: null,
      });
      await expect(service.cancel('s-1', 'u-1')).rejects.toThrow(ForbiddenException);
    });

    it('refuses to cancel one already sent', async () => {
      prisma.scheduledMessage.findUnique.mockResolvedValue({
        id: 's-1', senderId: 'u-1', sentAt: new Date(), cancelledAt: null,
      });
      await expect(service.cancel('s-1', 'u-1')).rejects.toThrow(BadRequestException);
    });

    it('reports an unknown id', async () => {
      prisma.scheduledMessage.findUnique.mockResolvedValue(null);
      await expect(service.cancel('nope', 'u-1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('dispatching', () => {
    const due = (over: any = {}) => ({
      id: 's-1', conversationId: 'conv-1', senderId: 'u-1', content: 'позже',
      fileUrl: null, fileName: null, fileSize: null, fileType: null, s3Key: null,
      topicId: null, replyToId: null, silent: false, sentAt: null, cancelledAt: null,
      ...over,
    });

    it('sends what is due, through the normal delivery path', async () => {
      prisma.scheduledMessage.findMany.mockResolvedValue([due()]);

      await service.dispatchDue();

      expect(messenger.createMessage).toHaveBeenCalled();
      expect(gateway.broadcastNewMessage).toHaveBeenCalled();
      expect(gateway.fanOutToParticipants).toHaveBeenCalled();
    });

    it('claims each row before sending it', async () => {
      // На PROD две ноды: обе увидят одну строку, и без захвата сообщение
      // ушло бы дважды.
      prisma.scheduledMessage.findMany.mockResolvedValue([due()]);

      await service.dispatchDue();

      expect(prisma.scheduledMessage.updateMany).toHaveBeenCalledWith({
        where: { id: 's-1', sentAt: null, cancelledAt: null },
        data: { sentAt: expect.any(Date) },
      });
    });

    it('skips a row another node already claimed', async () => {
      prisma.scheduledMessage.findMany.mockResolvedValue([due()]);
      prisma.scheduledMessage.updateMany.mockResolvedValue({ count: 0 });

      await service.dispatchDue();

      expect(messenger.createMessage).not.toHaveBeenCalled();
    });

    it('carries the silent flag into delivery', async () => {
      prisma.scheduledMessage.findMany.mockResolvedValue([due({ silent: true })]);

      await service.dispatchDue();

      expect(gateway.fanOutToParticipants).toHaveBeenCalledWith(
        expect.anything(), 'u-1', 'conv-1',
        expect.objectContaining({ silent: true }),
      );
    });

    it('returns a failed row to the queue instead of losing it', async () => {
      prisma.scheduledMessage.findMany.mockResolvedValue([due()]);
      messenger.createMessage.mockRejectedValue(new Error('boom'));

      await service.dispatchDue();

      expect(prisma.scheduledMessage.update).toHaveBeenCalledWith({
        where: { id: 's-1' },
        data: { sentAt: null, lastError: expect.stringContaining('boom') },
      });
    });

    it('does nothing when there is nothing due', async () => {
      await service.dispatchDue();
      expect(prisma.scheduledMessage.updateMany).not.toHaveBeenCalled();
    });
  });
});
