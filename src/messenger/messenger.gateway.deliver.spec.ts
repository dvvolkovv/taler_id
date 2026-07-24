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

/**
 * Tests for the extracted deliverNewMessage(...) method used by both the
 * socket `message` handler and the MCP send_message tool. Verifies delivery
 * parity: room emit, per-participant online/offline handling, block skip,
 * markDelivered + message_updated, FCM push (mute-respecting).
 */
describe('MessengerGateway.deliverNewMessage', () => {
  let gateway: MessengerGateway;
  let mockMessenger: MessengerService;
  let mockPrisma: PrismaService;
  let mockFcm: FcmService;
  let emitted: Array<{ room: string; event: string; data: any }> = [];
  let socketsInConv: Array<{ data: { userId: string } }> = [];
  let socketsInUser: Record<string, Array<{ data: { userId: string } }>> = {};

  beforeEach(async () => {
    emitted = [];
    socketsInConv = [];
    socketsInUser = {};
    const mockServer = {
      to: (room: string) => ({
        emit: (event: string, data: any) => {
          emitted.push({ room, event, data });
        },
      }),
      in: (room: string) => ({
        fetchSockets: async () => {
          if (room.startsWith('user:')) {
            const userId = room.slice(5);
            return socketsInUser[userId] ?? [];
          }
          return socketsInConv;
        },
      }),
    };
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
            getFcmTokens: jest.fn().mockResolvedValue(['tok-a', 'tok-b']),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            blockedUser: {
              findFirst: jest.fn().mockResolvedValue(null),
            },
            profile: {
              findUnique: jest.fn().mockResolvedValue({ language: 'ru' }),
            },
          },
        },
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: { registerEmitters: jest.fn() } },
        { provide: AiAnalystService, useValue: {} },
        { provide: AssistantChatService, useValue: {} },
        {
          provide: FcmService,
          useValue: { sendNewMessage: jest.fn().mockResolvedValue(undefined) },
        },
        { provide: ApnsService, useValue: {} },
        { provide: ConfigService, useValue: { get: () => undefined } },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
    (gateway as any).server = mockServer;
    mockMessenger = mod.get(MessengerService);
    mockPrisma = mod.get(PrismaService);
    mockFcm = mod.get(FcmService);
  });

  const baseMsg = {
    id: 'msg-1',
    conversationId: 'conv-1',
    senderId: 'sender',
    content: 'hello',
    fileUrl: null,
    fileType: null,
    sentAt: new Date(),
    senderName: 'Alice',
    reactions: [],
  };

  it('emits new_message to the conversation room', async () => {
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    const roomBroadcast = emitted.find(
      (e) => e.room === 'conv-1' && e.event === 'new_message',
    );
    expect(roomBroadcast).toBeDefined();
    expect(roomBroadcast!.data.id).toBe('msg-1');
    expect(roomBroadcast!.data.senderName).toBe('Alice');
  });

  it('emits new_message to each other participant user room (skips sender)', async () => {
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    const perUser = emitted.filter(
      (e) => e.room === 'user:recipient' && e.event === 'new_message',
    );
    expect(perUser).toHaveLength(1);
    // Sender should NOT receive the per-user new_message (they get room emit
    // if joined, plus their own echo path).
    const senderEmit = emitted.filter(
      (e) => e.room === 'user:sender' && e.event === 'new_message',
    );
    expect(senderEmit).toHaveLength(0);
  });

  it('skips delivery to a recipient who has blocked the sender', async () => {
    (mockPrisma.blockedUser.findFirst as jest.Mock).mockResolvedValue({
      blockerId: 'recipient',
      blockedId: 'sender',
    });
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    const perUser = emitted.filter(
      (e) => e.room === 'user:recipient' && e.event === 'new_message',
    );
    expect(perUser).toHaveLength(0);
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
    expect(mockMessenger.markDelivered).not.toHaveBeenCalled();
  });

  it('marks delivered + emits message_updated when recipient is online', async () => {
    socketsInUser['recipient'] = [{ data: { userId: 'recipient' } }];
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockMessenger.markDelivered).toHaveBeenCalledWith('msg-1');
    const updated = emitted.find(
      (e) => e.event === 'message_updated' && e.room === 'user:sender',
    );
    expect(updated).toBeDefined();
    expect(updated!.data).toEqual({ id: 'msg-1', isDelivered: true });
  });

  it('does NOT push FCM when recipient is currently viewing the conversation', async () => {
    socketsInConv = [{ data: { userId: 'recipient' } }];
    socketsInUser['recipient'] = [{ data: { userId: 'recipient' } }];
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('pushes FCM to all recipient tokens when offline and unmuted', async () => {
    // no sockets → offline, not in conv
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).toHaveBeenCalledTimes(2);
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-a',
      'Alice',
      'hello',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-b',
      'Alice',
      'hello',
      'conv-1',
    );
  });

  it('skips FCM when the conversation is muted for the recipient', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('skips FCM when opts.silent=true', async () => {
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1', {
      silent: true,
    });
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('uses file emoji in push text for file messages', async () => {
    await gateway.deliverNewMessage(
      { ...baseMsg, content: '', fileUrl: 'https://x/a.png', fileType: 'image' },
      'sender',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-a',
      'Alice',
      '🖼 Фото',
      'conv-1',
    );
  });

  it('uses "Контакт" push text for [CONTACT] messages', async () => {
    await gateway.deliverNewMessage(
      { ...baseMsg, content: '[CONTACT] {"name":"Bob"}' },
      'sender',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-a',
      'Alice',
      '📇 Контакт',
      'conv-1',
    );
  });

  // ── Regression: AI-branch ordering (commit 79c8644) ──────────────────────
  // broadcastNewMessage must NOT call getParticipants or markDelivered.
  // Before the split, deliverNewMessage (which includes fan-out) was called
  // BEFORE the AI_ANALYST / AI_INFORMER early-returns, causing extra DB
  // round-trips per AI message. The socket handler now calls broadcastNewMessage
  // eagerly and fanOutToParticipants only after those early-returns; this test
  // asserts the structural invariant on broadcastNewMessage itself.
  it('broadcastNewMessage does NOT call getParticipants or markDelivered (AI-branch safety)', async () => {
    gateway.broadcastNewMessage(baseMsg, 'conv-1');
    expect(mockMessenger.getParticipants).not.toHaveBeenCalled();
    expect(mockMessenger.markDelivered).not.toHaveBeenCalled();
  });

  it('deliverNewMessage is a composition: broadcastNewMessage + fanOutToParticipants', async () => {
    const broadcastSpy = jest.spyOn(gateway, 'broadcastNewMessage');
    const fanOutSpy = jest.spyOn(gateway, 'fanOutToParticipants');
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(broadcastSpy).toHaveBeenCalledWith(baseMsg, 'conv-1');
    expect(fanOutSpy).toHaveBeenCalledWith(baseMsg, 'sender', 'conv-1', {});
  });

  // ── Critical-news bypass mute (server-scoped via opts.systemPost) ───────────
  it('critical newsType WITH systemPost:true bypasses mute: FCM sent even when muted', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    const criticalMsg = {
      ...baseMsg,
      metadata: { newsType: 'critical' },
    };
    await gateway.deliverNewMessage(criticalMsg, 'sender', 'conv-1', {
      systemPost: true,
    });
    expect(mockFcm.sendNewMessage).toHaveBeenCalled();
  });

  it('critical newsType WITHOUT systemPost (opts omitted) respects mute: FCM NOT sent', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    const criticalMsg = {
      ...baseMsg,
      metadata: { newsType: 'critical' },
    };
    // No opts — client-supplied metadata alone must not trigger bypass
    await gateway.deliverNewMessage(criticalMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('non-critical newsType respects mute regardless of systemPost', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    const newsMsg = {
      ...baseMsg,
      metadata: { newsType: 'news' },
    };
    await gateway.deliverNewMessage(newsMsg, 'sender', 'conv-1', {
      systemPost: true,
    });
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('continues fan-out when one participant fails (resilience)', async () => {
    (mockMessenger.getParticipants as jest.Mock).mockResolvedValue([
      { userId: 'sender' },
      { userId: 'broken' },
      { userId: 'recipient' },
    ]);
    // блок-запрос для broken падает, для recipient — нет
    (mockPrisma.blockedUser.findFirst as jest.Mock).mockImplementation(
      async ({ where }: any) => {
        if (where.blockerId === 'broken') throw new Error('db timeout');
        return null;
      },
    );
    await gateway.fanOutToParticipants(
      { id: 'm1', content: 'hi' },
      'sender',
      'conv-1',
      {},
    );
    // recipient всё равно получил per-user emit
    expect(
      emitted.some((e) => e.room === 'user:recipient' && e.event === 'new_message'),
    ).toBe(true);
  });

  it('conv-level fetchSockets failure does not abort fan-out (everyone treated offline)', async () => {
    socketsInConv = null as any; // заставим общий fetchSockets кинуть
    const origIn = (gateway as any).server.in.bind((gateway as any).server);
    (gateway as any).server.in = (room: string) => {
      if (!room.startsWith('user:')) {
        return { fetchSockets: async () => { throw new Error('cross-node timeout'); } };
      }
      return origIn(room);
    };
    await gateway.fanOutToParticipants(
      { id: 'm2', content: 'hello' },
      'sender',
      'conv-1',
      {},
    );
    // FCM ушёл (recipient оффлайн/вне разговора)
    expect(mockFcm.sendNewMessage).toHaveBeenCalled();
  });
});
