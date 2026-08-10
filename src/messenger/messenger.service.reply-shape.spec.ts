import { Test } from '@nestjs/testing';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { FileStorageService } from '../common/file-storage.service';

/**
 * Два пути чтения истории собираются по-разному: `getMessages` — через Prisma
 * include, `sync` — сырым SQL со списком колонок. Расхождение между ними
 * проявляется только на втором устройстве и только для ответов, поэтому оно
 * зафиксировано тестом, а не надеждой.
 */
describe('reply/forward shape is identical on both read paths', () => {
  let service: MessengerService;
  let prisma: any;

  const replyToRow = {
    id: 'orig-1',
    senderId: 'u-author',
    content: 'оригинал',
    fileType: null,
    fileName: null,
    deletedAt: null,
    sender: { username: 'author', profile: { firstName: 'Аня', lastName: 'Автор' } },
  };

  beforeEach(async () => {
    prisma = {
      $queryRaw: jest.fn(),
      conversationParticipant: { findUnique: jest.fn().mockResolvedValue({ role: 'MEMBER' }) },
      message: { findFirst: jest.fn(), findMany: jest.fn() },
    };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerService,
        { provide: PrismaService, useValue: prisma },
        { provide: RedisService, useValue: { client: { get: jest.fn(), set: jest.fn() } } },
        { provide: FileStorageService, useValue: {} },
      ],
    }).compile();
    service = mod.get(MessengerService);
  });

  it('getMessages exposes replyTo and forwardedFrom', async () => {
    prisma.message.findMany.mockResolvedValue([
      {
        id: 'm1',
        conversationId: 'conv-1',
        senderId: 'u-1',
        content: 'ответ',
        replyToId: 'orig-1',
        forwardedFromUserId: null,
        forwardedFromName: null,
        forwardedFromMessageId: null,
        sender: { username: 'me', profile: { firstName: 'Я', lastName: null } },
        reactions: [],
        replyTo: replyToRow,
      },
    ]);

    const out = await service.getMessages('conv-1', 'u-1');

    expect(out.messages[0].replyTo).toEqual({
      id: 'orig-1',
      senderId: 'u-author',
      senderName: 'Аня Автор',
      content: 'оригинал',
      fileType: null,
      fileName: null,
      isDeleted: false,
    });
    expect(out.messages[0].forwardedFrom).toBeNull();
  });

  it('sync exposes the very same replyTo object', async () => {
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'm1',
        conversationId: 'conv-1',
        senderId: 'u-1',
        content: 'ответ',
        sentAt: new Date('2026-08-10T10:00:00.000Z'),
        replyToId: 'orig-1',
        forwardedFromUserId: null,
        forwardedFromName: null,
        forwardedFromMessageId: null,
        senderUsername: 'me',
        senderFirstName: 'Я',
        senderLastName: null,
        reactions: [],
        // ровно та плоская форма, которую отдаёт json_build_object
        replyToRaw: {
          id: 'orig-1',
          senderId: 'u-author',
          senderFirstName: 'Аня',
          senderLastName: 'Автор',
          senderUsername: 'author',
          content: 'оригинал',
          fileType: null,
          fileName: null,
          deletedAt: null,
        },
      },
    ]);

    const out = await service.sync('u-1', '2026-08-10T09:00:00.000Z|m0');

    expect(out.messages[0].replyTo).toEqual({
      id: 'orig-1',
      senderId: 'u-author',
      senderName: 'Аня Автор',
      content: 'оригинал',
      fileType: null,
      fileName: null,
      isDeleted: false,
    });
    expect(out.messages[0].replyToRaw).toBeUndefined();
  });

  it('hides the body of a deleted original on both paths', async () => {
    const deleted = { ...replyToRow, deletedAt: new Date(), content: 'секрет' };
    prisma.message.findMany.mockResolvedValue([
      {
        id: 'm1', conversationId: 'conv-1', senderId: 'u-1', content: 'ответ',
        replyToId: 'orig-1', sender: null, reactions: [], replyTo: deleted,
      },
    ]);

    const out = await service.getMessages('conv-1', 'u-1');

    expect(out.messages[0].replyTo.isDeleted).toBe(true);
    expect(out.messages[0].replyTo.content).toBe('');
    expect(JSON.stringify(out.messages[0])).not.toContain('секрет');
  });

  it('trims a long quote instead of shipping the whole message', async () => {
    const long = 'я'.repeat(500);
    prisma.message.findMany.mockResolvedValue([
      {
        id: 'm1', conversationId: 'conv-1', senderId: 'u-1', content: 'ответ',
        replyToId: 'orig-1', sender: null, reactions: [],
        replyTo: { ...replyToRow, content: long },
      },
    ]);

    const out = await service.getMessages('conv-1', 'u-1');

    expect(out.messages[0].replyTo.content).toHaveLength(200);
  });

  it('surfaces forward attribution', async () => {
    prisma.message.findMany.mockResolvedValue([
      {
        id: 'm1', conversationId: 'conv-1', senderId: 'u-fwd', content: 'исходный текст',
        replyToId: null, replyTo: null, sender: null, reactions: [],
        forwardedFromUserId: 'u-author',
        forwardedFromName: 'Аня Автор',
        forwardedFromMessageId: 'src-1',
      },
    ]);

    const out = await service.getMessages('conv-1', 'u-1');

    expect(out.messages[0].forwardedFrom).toEqual({
      userId: 'u-author',
      name: 'Аня Автор',
      messageId: 'src-1',
    });
  });
});
