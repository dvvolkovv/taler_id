import { Test } from '@nestjs/testing';
import { AssistantChatService } from './assistant-chat.service';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { FcmService } from '../common/fcm.service';
import { MessengerService } from '../messenger/messenger.service';

describe('AssistantChatService', () => {
  let service: AssistantChatService;

  const prisma = {
    conversation: { findFirst: jest.fn(), create: jest.fn() },
    message: { create: jest.fn(), findMany: jest.fn() },
  };
  const emitToUser = jest.fn();
  const gateway = { server: { to: jest.fn(() => ({ emit: emitToUser })) } };
  const fcm = { sendNewMessage: jest.fn() };
  const messengerService = { getFcmTokensForUser: jest.fn().mockResolvedValue([]) };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module = await Test.createTestingModule({
      providers: [
        AssistantChatService,
        { provide: PrismaService, useValue: prisma },
        { provide: MessengerGateway, useValue: gateway },
        { provide: FcmService, useValue: fcm },
        { provide: MessengerService, useValue: messengerService },
      ],
    }).compile();
    service = module.get(AssistantChatService);
  });

  describe('getOrCreateThread', () => {
    it('returns existing AI_ASSISTANT conversation', async () => {
      prisma.conversation.findFirst.mockResolvedValue({ id: 'conv-1' });
      const id = await service.getOrCreateThread('user-1');
      expect(id).toBe('conv-1');
      expect(prisma.conversation.findFirst).toHaveBeenCalledWith({
        where: { type: 'AI_ASSISTANT', participants: { some: { userId: 'user-1' } } },
      });
      expect(prisma.conversation.create).not.toHaveBeenCalled();
    });

    it('creates conversation when missing', async () => {
      prisma.conversation.findFirst.mockResolvedValue(null);
      prisma.conversation.create.mockResolvedValue({ id: 'conv-new' });
      const id = await service.getOrCreateThread('user-1');
      expect(id).toBe('conv-new');
      expect(prisma.conversation.create).toHaveBeenCalledWith({
        data: {
          type: 'AI_ASSISTANT',
          name: 'AI Ассистент',
          createdById: 'user-1',
          participants: { create: { userId: 'user-1', role: 'OWNER' } },
        },
      });
    });
  });

  describe('appendEntries', () => {
    it('persists entries with metadata and emits new_message', async () => {
      prisma.conversation.findFirst.mockResolvedValue({ id: 'conv-1' });
      prisma.message.create
        .mockResolvedValueOnce({ id: 'm1', conversationId: 'conv-1' })
        .mockResolvedValueOnce({ id: 'm2', conversationId: 'conv-1' });

      await service.appendEntries('user-1', [
        { role: 'user', source: 'voice', text: 'Отправь сообщение Ивану' },
        {
          role: 'assistant',
          source: 'voice',
          text: 'Готово, сообщение отправлено',
          action: {
            type: 'message_sent',
            entityId: 'msg-77',
            conversationId: 'conv-ivan',
            title: 'Сообщение для Ивана',
          },
        },
      ]);

      expect(prisma.message.create).toHaveBeenCalledTimes(2);
      expect(prisma.message.create.mock.calls[0][0]).toEqual({
        data: {
          conversationId: 'conv-1',
          senderId: 'user-1',
          content: 'Отправь сообщение Ивану',
          isSystem: false,
          metadata: { assistantRole: 'user', source: 'voice' },
        },
      });
      expect(prisma.message.create.mock.calls[1][0]).toEqual({
        data: {
          conversationId: 'conv-1',
          senderId: 'user-1',
          content: 'Готово, сообщение отправлено',
          isSystem: true,
          metadata: {
            assistantRole: 'assistant',
            source: 'voice',
            action: {
              type: 'message_sent',
              entityId: 'msg-77',
              conversationId: 'conv-ivan',
              title: 'Сообщение для Ивана',
            },
          },
        },
      });
      expect(gateway.server.to).toHaveBeenCalledWith('user:user-1');
      expect(emitToUser).toHaveBeenCalledTimes(2);
      expect(emitToUser).toHaveBeenCalledWith('new_message', expect.objectContaining({ id: 'm1' }));
    });
  });

  describe('appendAnalystReply', () => {
    it('writes truncated bubble with analyst_reply action, emits and pushes', async () => {
      prisma.conversation.findFirst.mockResolvedValue({ id: 'conv-1' });
      prisma.message.create.mockResolvedValue({ id: 'm3', conversationId: 'conv-1' });
      messengerService.getFcmTokensForUser.mockResolvedValue(['tok-1']);

      const longText = 'А'.repeat(900);
      await service.appendAnalystReply('user-1', longText, 'analyst-conv-9');

      const created = prisma.message.create.mock.calls[0][0].data;
      expect(created.content.length).toBeLessThanOrEqual(501); // 500 + ellipsis
      expect(created.isSystem).toBe(true);
      expect(created.metadata.action).toEqual({
        type: 'analyst_reply',
        entityId: 'analyst-conv-9',
        title: 'Ответ AI Аналитика',
      });
      expect(emitToUser).toHaveBeenCalledWith('new_message', expect.objectContaining({ id: 'm3' }));
      expect(fcm.sendNewMessage).toHaveBeenCalledWith(
        'tok-1',
        'AI Ассистент',
        expect.any(String),
        'conv-1',
      );
    });
  });
});
