import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { FcmService } from '../common/fcm.service';
import { expandOccurrences } from './recurrence.util';

@Injectable()
export class CalendarService {
  private readonly logger = new Logger(CalendarService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly fcmService: FcmService,
  ) {}

  async findByRange(userId: string, from?: string, to?: string) {
    const startDate = from ? new Date(from) : new Date();
    const endDate = to
      ? new Date(to)
      : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    const include = {
      user: {
        select: {
          id: true,
          username: true,
          profile: {
            select: { firstName: true, lastName: true, avatarUrl: true },
          },
        },
      },
      invites: {
        include: {
          user: {
            select: {
              id: true,
              username: true,
              profile: {
                select: { firstName: true, lastName: true, avatarUrl: true },
              },
            },
          },
        },
      },
    };

    // Fetch: non-recurring events in range + all recurring events that started before endDate
    const events = await this.prisma.calendarEvent.findMany({
      where: {
        OR: [
          { userId },
          {
            invites: {
              some: { userId, status: { in: ['ACCEPTED', 'MAYBE'] } },
            },
          },
        ],
        startAt: { lte: endDate },
      },
      orderBy: { startAt: 'asc' },
      include,
    });

    const result: any[] = [];
    for (const event of events) {
      if ((event as any).recurrence) {
        const occurrences = this.expandRecurrence(event, startDate, endDate);
        result.push(...occurrences);
      } else if (event.startAt >= startDate) {
        result.push(event);
      }
    }

    return result.sort(
      (a: any, b: any) =>
        new Date(a.startAt).getTime() - new Date(b.startAt).getTime(),
    );
  }

  // Expand a (possibly recurring) event into its occurrences within [from, to].
  // Recurrence handling lives in the shared recurrence util (also used by tasks).
  private expandRecurrence(event: any, from: Date, to: Date): any[] {
    const start = new Date(event.startAt);
    const duration = event.endAt
      ? new Date(event.endAt).getTime() - start.getTime()
      : 0;
    return expandOccurrences(start, event.recurrence, from, to).map((d) => ({
      ...event,
      startAt: new Date(d),
      endAt: event.endAt ? new Date(d.getTime() + duration) : null,
    }));
  }

  async findOne(userId: string, id: string) {
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id },
      include: { invites: true },
    });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();
    return event;
  }

  async create(
    userId: string,
    data: {
      id?: string;
      title: string;
      description?: string;
      type: string;
      startAt: string;
      endAt?: string;
      allDay?: boolean;
      reminderAt?: string;
      contactIds?: string[];
      createdBy?: string;
      displayTime?: string;
      // Freeform recurrence JSON. Canonical (spec §3.3):
      // { freq, interval?, byDay?, count?, until? }. Legacy mobile shape
      // { frequency, interval, endAt } is still accepted (see expandRecurrence).
      recurrence?: Record<string, any> | null;
    },
  ) {
    if (data.id) {
      const existing = await this.prisma.calendarEvent.findUnique({
        where: { id: data.id },
      });
      if (existing) {
        if (existing.userId !== userId) {
          throw new ConflictException('Event id already used by another account');
        }
        return existing;
      }
    }

    const event = await this.prisma.calendarEvent.create({
      data: {
        ...(data.id ? { id: data.id } : {}),
        userId,
        title: data.title,
        description: data.description ?? null,
        type: data.type as any,
        startAt: new Date(data.startAt),
        endAt: data.endAt ? new Date(data.endAt) : null,
        allDay: data.allDay ?? false,
        reminderAt: data.reminderAt ? new Date(data.reminderAt) : null,
        displayTime: data.displayTime ?? null,
        recurrence: data.recurrence ?? Prisma.DbNull,
        contactIds: data.contactIds ?? [],
        createdBy: data.createdBy ?? 'MANUAL',
      },
    });

    // Create CalendarInvite records for each participant
    if (data.contactIds && data.contactIds.length > 0) {
      for (const contactId of data.contactIds) {
        await this.prisma.calendarInvite.upsert({
          where: { eventId_userId: { eventId: event.id, userId: contactId } },
          create: { eventId: event.id, userId: contactId, status: 'PENDING' },
          update: { status: 'PENDING' },
        });
      }

      // Send push invites
      const creator = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { profile: { select: { firstName: true, lastName: true } } },
      });
      const creatorName =
        [creator?.profile?.firstName, creator?.profile?.lastName]
          .filter(Boolean)
          .join(' ') || 'Пользователь';
      const startFormatted =
        data.displayTime ||
        new Date(data.startAt).toLocaleString('ru-RU', {
          day: '2-digit',
          month: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
        });

      for (const contactId of data.contactIds) {
        const user = await this.prisma.user.findUnique({
          where: { id: contactId },
          select: { fcmToken: true },
        });
        if (user?.fcmToken) {
          this.fcmService
            .sendCalendarInvite(
              user.fcmToken,
              'Приглашение на встречу',
              creatorName +
                ' приглашает: ' +
                data.title +
                ' (' +
                startFormatted +
                ')',
              event.id,
            )
            .catch(() => {});
        }
      }
    }

    return event;
  }

  async update(userId: string, id: string, data: any) {
    const event = await this.prisma.calendarEvent.findUnique({ where: { id } });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();

    if (data.expectedUpdatedAt !== undefined) {
      const expected = new Date(data.expectedUpdatedAt);
      const sameMs =
        !Number.isNaN(expected.getTime()) &&
        expected.getTime() === event.updatedAt.getTime();
      if (!sameMs) {
        throw new ConflictException({
          message: 'Event updated elsewhere',
          currentEvent: event,
        });
      }
    }

    const updateData: any = {};
    if (data.title !== undefined) updateData.title = data.title;
    if (data.description !== undefined)
      updateData.description = data.description;
    if (data.type !== undefined) updateData.type = data.type;
    if (data.startAt !== undefined) updateData.startAt = new Date(data.startAt);
    if (data.endAt !== undefined) updateData.endAt = new Date(data.endAt);
    if (data.allDay !== undefined) updateData.allDay = data.allDay;
    if (data.reminderAt !== undefined) {
      updateData.reminderAt = new Date(data.reminderAt);
      updateData.reminderSent = false;
    }
    if (data.displayTime !== undefined)
      updateData.displayTime = data.displayTime;
    if (data.recurrence !== undefined)
      updateData.recurrence = data.recurrence ?? Prisma.DbNull;
    if (data.contactIds !== undefined) updateData.contactIds = data.contactIds;
    const updated = await this.prisma.calendarEvent.update({
      where: { id },
      data: updateData,
    });

    // Create invites for new contactIds
    if (data.contactIds && data.contactIds.length > 0) {
      for (const contactId of data.contactIds) {
        await this.prisma.calendarInvite.upsert({
          where: { eventId_userId: { eventId: id, userId: contactId } },
          create: { eventId: id, userId: contactId, status: 'PENDING' },
          update: {},
        });
      }
      // Send push invites for new participants
      const creator = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { profile: { select: { firstName: true, lastName: true } } },
      });
      const creatorName =
        [creator?.profile?.firstName, creator?.profile?.lastName]
          .filter(Boolean)
          .join(' ') || 'User';
      for (const contactId of data.contactIds) {
        const existing = await this.prisma.calendarInvite.findUnique({
          where: { eventId_userId: { eventId: id, userId: contactId } },
        });
        if (existing && existing.status === 'PENDING') {
          const user = await this.prisma.user.findUnique({
            where: { id: contactId },
            select: { fcmToken: true },
          });
          if (user?.fcmToken) {
            this.fcmService
              .sendNewMessage(
                user.fcmToken,
                'Приглашение на встречу',
                creatorName + ' приглашает: ' + event.title,
                '',
              )
              .catch(() => {});
          }
        }
      }
    }

    return updated;
  }

  async remove(userId: string, id: string) {
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id },
      include: {
        invites: {
          include: { user: { select: { id: true, fcmToken: true } } },
        },
      },
    });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();

    // Notify all invited participants about cancellation
    const creator = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { profile: { select: { firstName: true, lastName: true } } },
    });
    const creatorName =
      [creator?.profile?.firstName, creator?.profile?.lastName]
        .filter(Boolean)
        .join(' ') || 'User';
    for (const inv of (event as any).invites || []) {
      if (inv.user?.fcmToken) {
        this.fcmService
          .sendCalendarInvite(
            inv.user.fcmToken,
            'Встреча отменена',
            creatorName + ' отменил: ' + event.title,
            id,
          )
          .catch(() => {});
      }
    }

    return this.prisma.calendarEvent.delete({ where: { id } });
  }

  @Cron('0 * * * * *')
  async processReminders() {
    const pending = await this.prisma.calendarEvent.findMany({
      where: { reminderAt: { lte: new Date() }, reminderSent: false },
      include: { user: { select: { fcmToken: true } } },
    });
    for (const event of pending) {
      try {
        if (event.user?.fcmToken) {
          const body = event.displayTime
            ? `${event.title} — ${event.displayTime}`
            : event.title;
          await this.fcmService.sendCalendarReminder(
            event.user.fcmToken,
            'Напоминание',
            body,
            event.id,
          );
        }
        await this.prisma.calendarEvent.update({
          where: { id: event.id },
          data: { reminderSent: true },
        });
      } catch (e) {
        this.logger.error('Reminder failed: ' + event.id, e);
      }
    }
  }

  // ─── Invites ───

  private async notifyCalendarParticipants(
    eventId: string,
    excludeUserId?: string,
  ) {
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id: eventId },
      include: {
        user: { select: { id: true, fcmToken: true } },
        invites: {
          include: { user: { select: { id: true, fcmToken: true } } },
        },
      },
    });
    if (!event) return;
    const tokens = new Set<string>();
    if (event.user?.fcmToken && event.userId !== excludeUserId)
      tokens.add(event.user.fcmToken);
    for (const inv of event.invites || []) {
      if (inv.user?.fcmToken && inv.userId !== excludeUserId)
        tokens.add(inv.user.fcmToken);
    }
    for (const t of tokens) {
      this.fcmService.sendCalendarUpdated(t).catch(() => {});
    }
  }

  async getMyInvites(userId: string) {
    return this.prisma.calendarInvite.findMany({
      where: { userId, status: 'PENDING' },
      include: {
        event: {
          include: {
            user: {
              select: {
                id: true,
                username: true,
                profile: { select: { firstName: true, lastName: true } },
              },
            },
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async acceptInvite(inviteId: string, userId: string) {
    const invite = await this.prisma.calendarInvite.findUnique({
      where: { id: inviteId },
    });
    if (!invite || invite.userId !== userId) throw new NotFoundException();
    await this.prisma.calendarInvite.update({
      where: { id: inviteId },
      data: { status: 'ACCEPTED' },
    });
    // Notify creator
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id: invite.eventId },
    });
    if (event) {
      const acceptor = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { profile: { select: { firstName: true, lastName: true } } },
      });
      const name =
        [acceptor?.profile?.firstName, acceptor?.profile?.lastName]
          .filter(Boolean)
          .join(' ') || 'Участник';
      const token = await this.prisma.user.findUnique({
        where: { id: event.userId },
        select: { fcmToken: true },
      });
      if (token?.fcmToken)
        this.fcmService
          .sendNewMessage(
            token.fcmToken,
            'Принято',
            name + ' принял(а): ' + event.title,
            '',
          )
          .catch(() => {});
    }
    this.notifyCalendarParticipants(invite.eventId, userId);
    return { ok: true };
  }

  async maybeInvite(inviteId: string, userId: string) {
    const invite = await this.prisma.calendarInvite.findUnique({
      where: { id: inviteId },
    });
    if (!invite || invite.userId !== userId) throw new NotFoundException();
    await this.prisma.calendarInvite.update({
      where: { id: inviteId },
      data: { status: 'MAYBE' },
    });
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id: invite.eventId },
    });
    if (event) {
      const responder = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { profile: { select: { firstName: true, lastName: true } } },
      });
      const name =
        [responder?.profile?.firstName, responder?.profile?.lastName]
          .filter(Boolean)
          .join(' ') || 'Участник';
      const token = await this.prisma.user.findUnique({
        where: { id: event.userId },
        select: { fcmToken: true },
      });
      if (token?.fcmToken)
        this.fcmService
          .sendNewMessage(
            token.fcmToken,
            'Возможно',
            name + ' возможно придёт: ' + event.title,
            '',
          )
          .catch(() => {});
    }
    this.notifyCalendarParticipants(invite.eventId, userId);
    return { ok: true };
  }

  async declineInvite(inviteId: string, userId: string) {
    const invite = await this.prisma.calendarInvite.findUnique({
      where: { id: inviteId },
    });
    if (!invite || invite.userId !== userId) throw new NotFoundException();
    await this.prisma.calendarInvite.update({
      where: { id: inviteId },
      data: { status: 'DECLINED' },
    });
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id: invite.eventId },
    });
    if (event) {
      const decliner = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { profile: { select: { firstName: true, lastName: true } } },
      });
      const name =
        [decliner?.profile?.firstName, decliner?.profile?.lastName]
          .filter(Boolean)
          .join(' ') || 'Участник';
      const token = await this.prisma.user.findUnique({
        where: { id: event.userId },
        select: { fcmToken: true },
      });
      if (token?.fcmToken)
        this.fcmService
          .sendNewMessage(
            token.fcmToken,
            'Отклонено',
            name + ' отклонил(а): ' + event.title,
            '',
          )
          .catch(() => {});
    }
    this.notifyCalendarParticipants(invite.eventId, userId);
    return { ok: true };
  }

  async getEventInvites(eventId: string, userId: string) {
    const event = await this.prisma.calendarEvent.findUnique({
      where: { id: eventId },
    });
    if (!event || event.userId !== userId) throw new NotFoundException();
    return this.prisma.calendarInvite.findMany({
      where: { eventId },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: { firstName: true, lastName: true, avatarUrl: true },
            },
          },
        },
      },
    });
  }
}
