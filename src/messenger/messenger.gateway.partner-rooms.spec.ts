import { Test } from '@nestjs/testing';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { AssistantChatService } from '../assistant/assistant-chat.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import { ConfigService } from '@nestjs/config';
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { partnerUserRoom } from '../partner-core/partner.constants';
import { PartnerConversationScope } from './partner-conversation-scope.service';

/**
 * «Закрыто по умолчанию»: партнёрский сокет больше не сидит в `user:<id>` —
 * там летит всё подряд (AI-ассистент, звонки, биллинг, «Избранное»). Эти
 * тесты проверяют, что события личных чатов и групп явно продублированы в
 * `puser:<id>` (чтобы партнёрский сокет их всё-таки получил), а всё остальное
 * (CHANNEL/SAVED/AI-беседы) туда не попадает.
 */
describe('MessengerGateway partner room isolation', () => {
  let gateway: MessengerGateway;
  let mockMessenger: any;
  let mockPrisma: any;
  let emitted: Array<{ room: string; event: string; data: any }> = [];
  let socketsByRoom: Record<string, Array<{ data: { userId: string } }>> = {};

  function makeMockServer() {
    return {
      to: (room: string) => ({
        emit: (event: string, data: any) => {
          emitted.push({ room, event, data });
        },
      }),
      in: (room: string | string[]) => ({
        fetchSockets: async () => {
          const rooms = Array.isArray(room) ? room : [room];
          return rooms.flatMap((r) => socketsByRoom[r] ?? []);
        },
        socketsLeave: jest.fn(),
      }),
    };
  }

  beforeEach(async () => {
    emitted = [];
    socketsByRoom = {};
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        {
          provide: MessengerService,
          useValue: {
            getParticipants: jest.fn().mockResolvedValue([
              { userId: 'sender' },
              { userId: 'recipient' },
            ]),
            markDelivered: jest.fn().mockResolvedValue(undefined),
            isParticipantMuted: jest.fn().mockResolvedValue(false),
            getFcmTokens: jest.fn().mockResolvedValue([]),
            getFcmTokensForUser: jest.fn().mockResolvedValue([]),
            toggleReaction: jest.fn().mockResolvedValue([{ emoji: '👍', count: 1 }]),
            advanceReadHorizon: jest.fn().mockResolvedValue({
              lastReadAt: new Date('2026-10-01T00:00:00Z'),
              lastReadMessageId: 'm1',
            }),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
            profile: { findUnique: jest.fn().mockResolvedValue({ language: 'ru' }) },
            conversation: { findUnique: jest.fn().mockResolvedValue({ type: 'DIRECT' }) },
          },
        },
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: { registerEmitters: jest.fn() } },
        { provide: AiAnalystService, useValue: {} },
        { provide: AssistantChatService, useValue: {} },
        {
          provide: FcmService,
          useValue: {
            sendNewMessage: jest.fn().mockResolvedValue(undefined),
            sendReadSync: jest.fn().mockResolvedValue(undefined),
          },
        },
        { provide: ApnsService, useValue: {} },
        { provide: ConfigService, useValue: { get: () => undefined } },
        { provide: PartnerTokensService, useValue: { verify: jest.fn().mockResolvedValue(null) } },
        { provide: PartnerRealtimeService, useValue: { registerDisconnector: jest.fn() } },
        { provide: PartnerConversationScope, useValue: { assertConversation: jest.fn(), assertMessage: jest.fn() } },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
    (gateway as any).server = makeMockServer();
    mockMessenger = mod.get(MessengerService);
    mockPrisma = mod.get(PrismaService);
  });

  function setConvType(type: string | null) {
    mockPrisma.conversation.findUnique.mockResolvedValue(type ? { type } : null);
  }

  describe('emitToUserInConversation (helper)', () => {
    it('mirrors into puser:<id> for DIRECT', () => {
      gateway.emitToUserInConversation('u1', 'DIRECT', 'evt', { x: 1 });
      expect(emitted).toEqual([
        { room: 'user:u1', event: 'evt', data: { x: 1 } },
        { room: partnerUserRoom('u1'), event: 'evt', data: { x: 1 } },
      ]);
    });

    it('mirrors into puser:<id> for GROUP', () => {
      gateway.emitToUserInConversation('u1', 'GROUP', 'evt', { x: 1 });
      expect(emitted.some((e) => e.room === partnerUserRoom('u1'))).toBe(true);
    });

    it('does NOT mirror for CHANNEL', () => {
      gateway.emitToUserInConversation('u1', 'CHANNEL', 'evt', { x: 1 });
      expect(emitted).toEqual([{ room: 'user:u1', event: 'evt', data: { x: 1 } }]);
    });

    it('does NOT mirror for SAVED', () => {
      gateway.emitToUserInConversation('u1', 'SAVED', 'evt', { x: 1 });
      expect(emitted).toEqual([{ room: 'user:u1', event: 'evt', data: { x: 1 } }]);
    });

    it('does NOT mirror when the conversation type is unknown (null)', () => {
      gateway.emitToUserInConversation('u1', null, 'evt', { x: 1 });
      expect(emitted).toEqual([{ room: 'user:u1', event: 'evt', data: { x: 1 } }]);
    });
  });

  describe('fanOutToParticipants mirrors new_message / message_updated by conversation type', () => {
    const enrichedMsg = {
      id: 'msg-1',
      conversationId: 'conv-1',
      senderId: 'sender',
      content: 'hi',
      senderName: 'Alice',
      reactions: [],
    };

    it('DIRECT: new_message reaches both user: and puser: of the recipient', async () => {
      setConvType('DIRECT');
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(emitted.some((e) => e.room === 'user:recipient' && e.event === 'new_message')).toBe(true);
      expect(
        emitted.some((e) => e.room === partnerUserRoom('recipient') && e.event === 'new_message'),
      ).toBe(true);
    });

    it('GROUP: new_message reaches both rooms too', async () => {
      setConvType('GROUP');
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(
        emitted.some((e) => e.room === partnerUserRoom('recipient') && e.event === 'new_message'),
      ).toBe(true);
    });

    it('CHANNEL: new_message stays user:-only, no puser: mirror', async () => {
      setConvType('CHANNEL');
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(emitted.some((e) => e.room === 'user:recipient' && e.event === 'new_message')).toBe(true);
      expect(emitted.some((e) => e.room === partnerUserRoom('recipient'))).toBe(false);
    });

    it('DIRECT: the delivered echo to the sender also mirrors into puser:sender', async () => {
      setConvType('DIRECT');
      socketsByRoom['user:recipient'] = [{ data: { userId: 'recipient' } }];
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(
        emitted.some((e) => e.room === partnerUserRoom('sender') && e.event === 'message_updated'),
      ).toBe(true);
    });

    it('online check counts a recipient socket that only holds the puser: room', async () => {
      setConvType('DIRECT');
      // Recipient has NO socket in user:recipient — only a partner socket in
      // puser:recipient. Delivery must still be marked, or a partner-only
      // reader would never flip the sender's message to "delivered".
      socketsByRoom[partnerUserRoom('recipient')] = [{ data: { userId: 'recipient' } }];
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(mockMessenger.markDelivered).toHaveBeenCalledWith('msg-1');
      expect(
        emitted.some((e) => e.room === 'user:sender' && e.event === 'message_updated'),
      ).toBe(true);
    });
  });

  describe('message_reaction_updated mirrors by conversation type', () => {
    const payload = { conversationId: 'conv-1', messageId: 'm1', emoji: '👍' };
    const client = { data: { userId: 'reactor' }, emit: jest.fn() };

    it('DIRECT: mirrors to puser: for each participant', async () => {
      setConvType('DIRECT');
      await gateway.handleReactMessage(client as any, payload);
      expect(
        emitted.some(
          (e) => e.room === partnerUserRoom('recipient') && e.event === 'message_reaction_updated',
        ),
      ).toBe(true);
    });

    it('CHANNEL: stays user:-only', async () => {
      setConvType('CHANNEL');
      await gateway.handleReactMessage(client as any, payload);
      expect(
        emitted.some((e) => e.room === 'user:recipient' && e.event === 'message_reaction_updated'),
      ).toBe(true);
      expect(emitted.some((e) => e.room === partnerUserRoom('recipient'))).toBe(false);
    });
  });

  describe('mark_read (conversation_read / messages_read) mirrors by conversation type', () => {
    const payload = { conversationId: 'conv-1' };
    const client = { data: { userId: 'sender' }, emit: jest.fn() };

    it('DIRECT: conversation_read to participants and messages_read to the reader both mirror', async () => {
      setConvType('DIRECT');
      await gateway.handleMarkRead(client as any, payload as any);
      expect(
        emitted.some((e) => e.room === partnerUserRoom('recipient') && e.event === 'conversation_read'),
      ).toBe(true);
      expect(
        emitted.some((e) => e.room === partnerUserRoom('sender') && e.event === 'messages_read'),
      ).toBe(true);
    });

    it('SAVED: no puser: mirror for either event', async () => {
      setConvType('SAVED');
      await gateway.handleMarkRead(client as any, payload as any);
      expect(emitted.some((e) => e.event === 'conversation_read')).toBe(true);
      expect(emitted.some((e) => e.room.startsWith('puser:'))).toBe(false);
    });
  });

  describe('evictFromConversationRoom', () => {
    it('evicts both the personal and the partner room of the user', () => {
      const socketsLeave = jest.fn();
      const inSpy = jest.fn().mockReturnValue({ socketsLeave });
      (gateway as any).server.in = inSpy;
      gateway.evictFromConversationRoom('u1', 'conv-1');
      expect(inSpy).toHaveBeenCalledWith(['user:u1', partnerUserRoom('u1')]);
      expect(socketsLeave).toHaveBeenCalledWith('conv-1');
    });
  });
});
