import { Test } from '@nestjs/testing';
import { CalendarService } from './calendar.service';
import { PrismaService } from '../prisma/prisma.service';
import { FcmService } from '../common/fcm.service';
import { ConflictException } from '@nestjs/common';

describe('CalendarService.create', () => {
  let service: CalendarService;
  let prisma: any;

  beforeEach(async () => {
    prisma = {
      calendarEvent: {
        create: jest.fn(),
        findUnique: jest.fn(),
      },
      calendarInvite: { upsert: jest.fn() },
      user: { findUnique: jest.fn().mockResolvedValue(null) },
    };
    const mod = await Test.createTestingModule({
      providers: [
        CalendarService,
        { provide: PrismaService, useValue: prisma },
        { provide: FcmService, useValue: { sendCalendarInvite: jest.fn() } },
      ],
    }).compile();
    service = mod.get(CalendarService);
  });

  const baseInput = {
    title: 'Coffee',
    type: 'EVENT',
    startAt: '2026-05-14T10:00:00.000Z',
  };

  it('without id: creates as before', async () => {
    prisma.calendarEvent.create.mockResolvedValue({ id: 'srv', userId: 'u1', ...baseInput });
    await service.create('u1', baseInput);
    expect(prisma.calendarEvent.create).toHaveBeenCalled();
    const arg = prisma.calendarEvent.create.mock.calls[0][0].data;
    expect(arg.id).toBeUndefined();
  });

  it('with id: passes id through to Prisma', async () => {
    prisma.calendarEvent.findUnique.mockResolvedValue(null);
    prisma.calendarEvent.create.mockResolvedValue({ id: 'mine', userId: 'u1', ...baseInput });
    const out = await service.create('u1', { ...baseInput, id: 'mine' } as any);
    expect(prisma.calendarEvent.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ id: 'mine', userId: 'u1', title: 'Coffee' }),
    });
    expect(out.id).toBe('mine');
  });

  it('with id of an existing event owned by same user: returns existing, idempotent (no double-create)', async () => {
    prisma.calendarEvent.findUnique.mockResolvedValue({ id: 'mine', userId: 'u1', title: 'orig' });
    const out = await service.create('u1', { ...baseInput, id: 'mine' } as any);
    expect(prisma.calendarEvent.create).not.toHaveBeenCalled();
    expect(out).toEqual({ id: 'mine', userId: 'u1', title: 'orig' });
  });

  it('with id of an event owned by another user: throws ConflictException', async () => {
    prisma.calendarEvent.findUnique.mockResolvedValue({ id: 'theirs', userId: 'other' });
    await expect(
      service.create('u1', { ...baseInput, id: 'theirs' } as any),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(prisma.calendarEvent.create).not.toHaveBeenCalled();
  });
});
