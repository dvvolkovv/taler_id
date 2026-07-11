import { Test } from '@nestjs/testing';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';

describe('MessengerService read-horizon', () => {
  let svc: MessengerService;
  const prisma = {
    message: { findFirst: jest.fn(), count: jest.fn() },
    conversationParticipant: { findUnique: jest.fn(), update: jest.fn(), findMany: jest.fn() },
  } as any;

  beforeEach(async () => {
    const mod = await Test.createTestingModule({
      providers: [
        MessengerService,
        { provide: PrismaService, useValue: prisma },
        { provide: FileStorageService, useValue: {} },
      ],
    }).compile();
    svc = mod.get(MessengerService);
    jest.clearAllMocks();
  });

  it('advances the cursor when upTo is beyond current', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ lastReadAt: new Date('2026-07-01T00:00:00Z') });
    prisma.conversationParticipant.update.mockResolvedValue({});
    const at = new Date('2026-07-02T00:00:00Z');
    const r = await svc.advanceReadHorizon('c1', 'u1', at, 'm2');
    expect(prisma.conversationParticipant.update).toHaveBeenCalled();
    expect(r?.lastReadAt.toISOString()).toBe(at.toISOString());
  });

  it('is a no-op when upTo <= current (monotonic)', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ lastReadAt: new Date('2026-07-03T00:00:00Z') });
    const r = await svc.advanceReadHorizon('c1', 'u1', new Date('2026-07-02T00:00:00Z'), 'm1');
    expect(prisma.conversationParticipant.update).not.toHaveBeenCalled();
    expect(r).toBeNull();
  });

  it('null upToSentAt reads to latest existing message', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ lastReadAt: null });
    prisma.message.findFirst.mockResolvedValue({ id: 'mLatest', sentAt: new Date('2026-07-05T00:00:00Z') });
    prisma.conversationParticipant.update.mockResolvedValue({});
    const r = await svc.advanceReadHorizon('c1', 'u1', null, null);
    expect(r?.lastReadMessageId).toBe('mLatest');
  });
});
