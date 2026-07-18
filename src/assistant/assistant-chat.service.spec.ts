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

  describe('textTurn', () => {
    beforeEach(() => {
      prisma.conversation.findFirst.mockResolvedValue({ id: 'conv-1' });
      prisma.message.findMany.mockResolvedValue([]);
    });

    it('persists user text, returns final answer and persists it', async () => {
      prisma.message.create
        .mockResolvedValueOnce({ id: 'u1', conversationId: 'conv-1' }) // user msg
        .mockResolvedValueOnce({ id: 'a1', conversationId: 'conv-1' }); // assistant msg
      jest.spyOn(service as any, 'callOpenAI').mockResolvedValue({
        content: 'Привет! Чем помочь?',
        tool_calls: undefined,
      });

      const res = await service.textTurn('user-1', {
        text: 'Привет',
        instructions: 'Ты — ассистент Taler ID',
        tools: [],
      });

      expect(res).toEqual({ status: 'final', text: 'Привет! Чем помочь?', messageId: 'a1' });
      expect(prisma.message.create.mock.calls[0][0].data.metadata).toEqual({
        assistantRole: 'user',
        source: 'text',
      });
      expect(prisma.message.create.mock.calls[1][0].data.isSystem).toBe(true);
      expect(emitToUser).toHaveBeenCalledWith('new_message', expect.objectContaining({ id: 'a1' }));
    });

    it('returns tool_calls without persisting an assistant message', async () => {
      prisma.message.create.mockResolvedValueOnce({ id: 'u1', conversationId: 'conv-1' });
      const toolCalls = [
        { id: 'call_1', type: 'function', function: { name: 'send_message', arguments: '{}' } },
      ];
      jest.spyOn(service as any, 'callOpenAI').mockResolvedValue({
        content: null,
        tool_calls: toolCalls,
      });

      const res = await service.textTurn('user-1', {
        text: 'Отправь сообщение Ивану',
        instructions: 'sys',
        tools: [{ type: 'function', function: { name: 'send_message' } }],
      });

      expect(res.status).toBe('tool_calls');
      expect(res.toolCalls).toEqual(toolCalls);
      expect(prisma.message.create).toHaveBeenCalledTimes(1);
    });

    it('feeds toolResults back and persists the final message', async () => {
      prisma.message.create.mockResolvedValueOnce({ id: 'a2', conversationId: 'conv-1' });
      const spy = jest.spyOn(service as any, 'callOpenAI').mockResolvedValue({
        content: 'Сообщение отправлено',
        tool_calls: undefined,
      });
      const pending = {
        role: 'assistant',
        tool_calls: [
          { id: 'call_1', type: 'function', function: { name: 'send_message', arguments: '{}' } },
        ],
      };

      const res = await service.textTurn('user-1', {
        instructions: 'sys',
        tools: [],
        pendingAssistantMessage: pending,
        toolResults: [{ tool_call_id: 'call_1', output: '{"ok":true}' }],
      });

      expect(res.status).toBe('final');
      const sentMessages = spy.mock.calls[0][0].messages;
      expect(sentMessages).toEqual(
        expect.arrayContaining([
          pending,
          { role: 'tool', tool_call_id: 'call_1', content: '{"ok":true}' },
        ]),
      );
    });

    it('maps thread history into the OpenAI context', async () => {
      prisma.message.findMany.mockResolvedValue([
        // findMany returns desc; service must reverse to chronological
        { content: 'Ответ', metadata: { assistantRole: 'assistant' }, isSystem: true },
        { content: 'Вопрос', metadata: { assistantRole: 'user' }, isSystem: false },
      ]);
      prisma.message.create
        .mockResolvedValueOnce({ id: 'u1', conversationId: 'conv-1' })
        .mockResolvedValueOnce({ id: 'a1', conversationId: 'conv-1' });
      const spy = jest.spyOn(service as any, 'callOpenAI').mockResolvedValue({
        content: 'ok',
        tool_calls: undefined,
      });

      await service.textTurn('user-1', { text: 'Ещё', instructions: 'sys', tools: [] });

      const msgs = spy.mock.calls[0][0].messages;
      expect(msgs[0]).toEqual({ role: 'system', content: 'sys' });
      expect(msgs[1]).toEqual({ role: 'user', content: 'Вопрос' });
      expect(msgs[2]).toEqual({ role: 'assistant', content: 'Ответ' });
      expect(msgs[msgs.length - 1]).toEqual({ role: 'user', content: 'Ещё' });
    });
  });
});
