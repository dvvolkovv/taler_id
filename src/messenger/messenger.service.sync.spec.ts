import { Test } from '@nestjs/testing';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { FileStorageService } from '../common/file-storage.service';

describe('MessengerService.sync', () => {
  let service: MessengerService;
  let mockPrisma: { $queryRaw: jest.Mock; message: { findFirst: jest.Mock } };

  beforeEach(async () => {
    mockPrisma = {
      $queryRaw: jest.fn(),
      message: { findFirst: jest.fn() },
    };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: RedisService, useValue: { client: { get: jest.fn(), set: jest.fn() } } },
        { provide: FileStorageService, useValue: {} },
      ],
    }).compile();
    service = mod.get(MessengerService);
  });

  it('initialization (no cursor) returns empty messages and current cursor', async () => {
    mockPrisma.message.findFirst.mockResolvedValue({
      id: 'last-msg-id',
      sentAt: new Date('2026-05-13T10:00:00.000Z'),
    });

    const out = await service.sync('user-1');

    expect(out.messages).toEqual([]);
    expect(out.hasMore).toBe(false);
    expect(out.nextCursor).toBe('2026-05-13T10:00:00.000Z|last-msg-id');
  });

  it('delta (with cursor) returns messages strictly greater than cursor, ordered ascending', async () => {
    const rows = [
      {
        id: 'm2',
        conversationId: 'conv-1',
        senderId: 'user-2',
        content: 'hello',
        sentAt: new Date('2026-05-13T10:05:00.000Z'),
        senderUsername: 'bob',
        senderFirstName: 'Bob',
        senderLastName: null,
        reactions: [],
      },
    ];
    mockPrisma.$queryRaw.mockResolvedValueOnce(rows);

    const out = await service.sync(
      'user-1',
      '2026-05-13T10:00:00.000Z|m1',
      100,
    );

    expect(out.messages).toHaveLength(1);
    expect(out.messages[0].id).toBe('m2');
    expect(out.messages[0].senderName).toBe('Bob');
    expect(out.hasMore).toBe(false);
    expect(out.nextCursor).toBe('2026-05-13T10:05:00.000Z|m2');
  });

  it('delta sets hasMore=true and trims to limit when limit+1 rows returned', async () => {
    const make = (i: number) => ({
      id: `m${i}`,
      conversationId: 'conv-1',
      senderId: 'user-2',
      content: `msg ${i}`,
      sentAt: new Date(`2026-05-13T10:${10 + i}:00.000Z`),
      senderUsername: 'bob',
      senderFirstName: null,
      senderLastName: null,
      reactions: [],
    });
    mockPrisma.$queryRaw.mockResolvedValueOnce([1, 2, 3].map(make));

    const out = await service.sync(
      'user-1',
      '2026-05-13T10:00:00.000Z|m0',
      2,
    );

    expect(out.messages).toHaveLength(2);
    expect(out.hasMore).toBe(true);
    expect(out.nextCursor).toBe('2026-05-13T10:12:00.000Z|m2');
  });
});
