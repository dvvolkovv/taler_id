import { Test } from '@nestjs/testing';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { FileStorageService } from '../common/file-storage.service';

// Phantom-resend guard (2026-07-17 incident): stale pre-1.0.98 clients re-fire
// old outbox entries on every socket reconnect. Two bypass paths existed:
//  A) resend carries a FRESH clientTempId while the original row has none →
//     (senderId, clientTempId) unique index never collides;
//  B) content-dedup fallback only looked 14 days back — the observed ghost
//     ("Я на даче") was 42 days old.
describe('MessengerService.createMessage phantom guard', () => {
  let service: MessengerService;
  let mockPrisma: {
    message: { create: jest.Mock; findFirst: jest.Mock };
    conversationParticipant: { findUnique: jest.Mock };
  };

  const CONV = 'conv-1';
  const SENDER = 'user-1';
  const LONG = 'Дим, привет! Я на даче, телега чета не работает';

  beforeEach(async () => {
    mockPrisma = {
      message: { create: jest.fn(), findFirst: jest.fn() },
      // createMessage asserts conversation membership before anything else.
      conversationParticipant: {
        findUnique: jest
          .fn()
          .mockResolvedValue({ conversationId: CONV, userId: SENDER }),
      },
    };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerService,
        { provide: PrismaService, useValue: mockPrisma },
        {
          provide: RedisService,
          useValue: { client: { get: jest.fn(), set: jest.fn() } },
        },
        { provide: FileStorageService, useValue: {} },
      ],
    }).compile();
    service = mod.get(MessengerService);
  });

  const oldRow = () => ({
    id: 'old-msg',
    conversationId: CONV,
    senderId: SENDER,
    content: LONG,
    sentAt: new Date(Date.now() - 42 * 24 * 3600 * 1000),
  });

  it('blocks a reconnect-drain resend carrying a fresh clientTempId (bypass A)', async () => {
    mockPrisma.message.findFirst.mockResolvedValue(oldRow());
    const out: any = await service.createMessage(
      CONV,
      SENDER,
      LONG,
      undefined,
      undefined,
      undefined,
      undefined,
      'temp_fresh-uuid',
      true, // phantomSuspect: arrived right after socket connect
    );
    expect(out.id).toBe('old-msg');
    expect(out.deduped).toBe(true);
    expect(mockPrisma.message.create).not.toHaveBeenCalled();
  });

  it('does NOT content-dedup a tempId message outside the reconnect-drain window', async () => {
    mockPrisma.message.create.mockResolvedValue({ id: 'new-msg' });
    const out: any = await service.createMessage(
      CONV,
      SENDER,
      LONG,
      undefined,
      undefined,
      undefined,
      undefined,
      'temp_fresh-uuid',
      false,
    );
    expect(out.id).toBe('new-msg');
    expect(out.deduped).toBeUndefined();
    expect(mockPrisma.message.findFirst).not.toHaveBeenCalled();
  });

  it('no-tempId resend: dedup window reaches back at least 90 days (bypass B)', async () => {
    mockPrisma.message.findFirst.mockResolvedValue(oldRow());
    const out: any = await service.createMessage(CONV, SENDER, LONG);
    expect(out.deduped).toBe(true);
    const where = mockPrisma.message.findFirst.mock.calls[0][0].where;
    const windowMs = Date.now() - where.sentAt.gte.getTime();
    expect(windowMs).toBeGreaterThanOrEqual(89 * 24 * 3600 * 1000);
    expect(mockPrisma.message.create).not.toHaveBeenCalled();
  });

  it('marks the P2002 unique-collision path as deduped', async () => {
    mockPrisma.message.findFirst.mockResolvedValueOnce(null); // content dedup miss
    const err: any = new Error('unique');
    err.code = 'P2002';
    mockPrisma.message.create.mockRejectedValue(err);
    mockPrisma.message.findFirst.mockResolvedValueOnce({
      id: 'orig-msg',
      senderId: SENDER,
      clientTempId: 'temp_x',
    });
    const out: any = await service.createMessage(
      CONV,
      SENDER,
      LONG,
      undefined,
      undefined,
      undefined,
      undefined,
      'temp_x',
      true,
    );
    expect(out.id).toBe('orig-msg');
    expect(out.deduped).toBe(true);
  });

  it('short content is never content-deduped', async () => {
    mockPrisma.message.create.mockResolvedValue({ id: 'new-msg' });
    const out: any = await service.createMessage(CONV, SENDER, 'ок');
    expect(out.id).toBe('new-msg');
    expect(mockPrisma.message.findFirst).not.toHaveBeenCalled();
  });
});
