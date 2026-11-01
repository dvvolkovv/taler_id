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

describe('CalendarService.update', () => {
  let service: CalendarService;
  let prisma: any;

  beforeEach(async () => {
    prisma = {
      calendarEvent: {
        findUnique: jest.fn(),
        update: jest.fn(),
      },
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

  it('without expectedUpdatedAt: applies update (LWW, back-compat)', async () => {
    const now = new Date('2026-05-14T10:00:00Z');
    prisma.calendarEvent.findUnique.mockResolvedValue({ id: 'e1', userId: 'u1', updatedAt: now });
    prisma.calendarEvent.update.mockResolvedValue({ id: 'e1', userId: 'u1', title: 'new' });
    const out = await service.update('u1', 'e1', { title: 'new' });
    expect(prisma.calendarEvent.update).toHaveBeenCalled();
    expect(out.title).toBe('new');
  });

  it('with matching expectedUpdatedAt: applies update', async () => {
    const now = new Date('2026-05-14T10:00:00Z');
    prisma.calendarEvent.findUnique.mockResolvedValue({ id: 'e1', userId: 'u1', updatedAt: now });
    prisma.calendarEvent.update.mockResolvedValue({ id: 'e1', userId: 'u1', title: 'new' });
    const out = await service.update('u1', 'e1', { title: 'new', expectedUpdatedAt: now.toISOString() });
    expect(prisma.calendarEvent.update).toHaveBeenCalled();
    expect(out.title).toBe('new');
  });

  it('with stale expectedUpdatedAt: throws ConflictException with currentEvent in response', async () => {
    const dbTime = new Date('2026-05-14T10:05:00Z');
    const clientTs = new Date('2026-05-14T10:00:00Z').toISOString();
    const current = { id: 'e1', userId: 'u1', updatedAt: dbTime, title: 'on server' };
    prisma.calendarEvent.findUnique.mockResolvedValue(current);
    let thrown: any;
    try {
      await service.update('u1', 'e1', { title: 'mine', expectedUpdatedAt: clientTs });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(ConflictException);
    const resp = (thrown as ConflictException).getResponse() as any;
    expect(resp.currentEvent).toEqual(current);
    expect(prisma.calendarEvent.update).not.toHaveBeenCalled();
  });

  it('with bogus expectedUpdatedAt string: throws ConflictException', async () => {
    const dbTime = new Date('2026-05-14T10:05:00Z');
    prisma.calendarEvent.findUnique.mockResolvedValue({ id: 'e1', userId: 'u1', updatedAt: dbTime });
    await expect(
      service.update('u1', 'e1', { title: 'mine', expectedUpdatedAt: 'not-a-date' }),
    ).rejects.toBeInstanceOf(ConflictException);
  });
});

describe('CalendarService.processReminders', () => {
  let service: CalendarService;
  let prisma: any;
  let fcm: { sendCalendarReminder: jest.Mock };
  const due = { id: 'ev-1', title: 'Coffee', displayTime: null, user: { fcmToken: 'tok' } };

  beforeEach(async () => {
    prisma = {
      calendarEvent: {
        findMany: jest.fn().mockResolvedValue([due]),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        update: jest.fn(),
      },
    };
    fcm = { sendCalendarReminder: jest.fn().mockResolvedValue(undefined) };
    const mod = await Test.createTestingModule({
      providers: [
        CalendarService,
        { provide: PrismaService, useValue: prisma },
        { provide: FcmService, useValue: fcm },
      ],
    }).compile();
    service = mod.get(CalendarService);
  });

  it('claims the reminder before pushing it', async () => {
    await service.processReminders();

    expect(prisma.calendarEvent.updateMany).toHaveBeenCalledWith({
      where: { id: 'ev-1', reminderSent: false },
      data: { reminderSent: true },
    });
    expect(prisma.calendarEvent.updateMany.mock.invocationCallOrder[0]).toBeLessThan(
      fcm.sendCalendarReminder.mock.invocationCallOrder[0],
    );
    expect(fcm.sendCalendarReminder).toHaveBeenCalledWith('tok', 'Напоминание', 'Coffee', 'ev-1');
  });

  it('pushes nothing when another run claimed it first', async () => {
    // Two app nodes run this every minute and both see the same due event.
    prisma.calendarEvent.updateMany.mockResolvedValue({ count: 0 });

    await service.processReminders();

    expect(fcm.sendCalendarReminder).not.toHaveBeenCalled();
  });

  it('gives the claim back when something throws, so the next minute retries', async () => {
    fcm.sendCalendarReminder.mockRejectedValue(new Error('boom'));
    jest.spyOn((service as any).logger, 'error').mockImplementation(() => undefined);

    await service.processReminders();

    expect(prisma.calendarEvent.updateMany).toHaveBeenLastCalledWith({
      where: { id: 'ev-1' },
      data: { reminderSent: false },
    });
  });
});
