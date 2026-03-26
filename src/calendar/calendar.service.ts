import { Injectable, NotFoundException, ForbiddenException, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { FcmService } from '../common/fcm.service';

@Injectable()
export class CalendarService {
  private readonly logger = new Logger(CalendarService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly fcmService: FcmService,
  ) {}

  async findByRange(userId: string, from?: string, to?: string) {
    const startDate = from ? new Date(from) : new Date();
    const endDate = to ? new Date(to) : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    return this.prisma.calendarEvent.findMany({
      where: { userId, startAt: { gte: startDate, lte: endDate } },
      orderBy: { startAt: 'asc' },
      include: { invites: { include: { user: { select: { id: true, username: true, profile: { select: { firstName: true, lastName: true, avatarUrl: true } } } } } } },
    });
  }

  async findOne(userId: string, id: string) {
    const event = await this.prisma.calendarEvent.findUnique({ where: { id }, include: { invites: true } });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();
    return event;
  }

  async create(userId: string, data: {
    title: string; description?: string; type: string;
    startAt: string; endAt?: string; allDay?: boolean;
    reminderAt?: string; contactIds?: string[]; createdBy?: string;
  }) {
    const event = await this.prisma.calendarEvent.create({
      data: {
        userId,
        title: data.title,
        description: data.description ?? null,
        type: data.type as any,
        startAt: new Date(data.startAt),
        endAt: data.endAt ? new Date(data.endAt) : null,
        allDay: data.allDay ?? false,
        reminderAt: data.reminderAt ? new Date(data.reminderAt) : null,
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
      const creatorName = [creator?.profile?.firstName, creator?.profile?.lastName].filter(Boolean).join(' ') || 'Пользователь';
      const startFormatted = new Date(data.startAt).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

      for (const contactId of data.contactIds) {
        const user = await this.prisma.user.findUnique({ where: { id: contactId }, select: { fcmToken: true } });
        if (user?.fcmToken) {
          this.fcmService.sendNewMessage(user.fcmToken, 'Приглашение на встречу', creatorName + ' приглашает: ' + data.title + ' (' + startFormatted + ')', '').catch(() => {});
        }
      }
    }

    return event;
  }

  async update(userId: string, id: string, data: any) {
    const event = await this.prisma.calendarEvent.findUnique({ where: { id } });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();
    const updateData: any = {};
    if (data.title !== undefined) updateData.title = data.title;
    if (data.description !== undefined) updateData.description = data.description;
    if (data.type !== undefined) updateData.type = data.type;
    if (data.startAt !== undefined) updateData.startAt = new Date(data.startAt);
    if (data.endAt !== undefined) updateData.endAt = new Date(data.endAt);
    if (data.allDay !== undefined) updateData.allDay = data.allDay;
    if (data.reminderAt !== undefined) { updateData.reminderAt = new Date(data.reminderAt); updateData.reminderSent = false; }
    if (data.contactIds !== undefined) updateData.contactIds = data.contactIds;
    return this.prisma.calendarEvent.update({ where: { id }, data: updateData });
  }

  async remove(userId: string, id: string) {
    const event = await this.prisma.calendarEvent.findUnique({ where: { id } });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();
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
          await this.fcmService.sendNewMessage(event.user.fcmToken, 'Напоминание', event.title, '');
        }
        await this.prisma.calendarEvent.update({ where: { id: event.id }, data: { reminderSent: true } });
      } catch (e) {
        this.logger.error('Reminder failed: ' + event.id, e);
      }
    }
  }

  // ─── Invites ───

  async getMyInvites(userId: string) {
    return this.prisma.calendarInvite.findMany({
      where: { userId, status: 'PENDING' },
      include: { event: { include: { user: { select: { id: true, username: true, profile: { select: { firstName: true, lastName: true } } } } } } },
      orderBy: { createdAt: 'desc' },
    });
  }

  async acceptInvite(inviteId: string, userId: string) {
    const invite = await this.prisma.calendarInvite.findUnique({ where: { id: inviteId } });
    if (!invite || invite.userId !== userId) throw new NotFoundException();
    await this.prisma.calendarInvite.update({ where: { id: inviteId }, data: { status: 'ACCEPTED' } });
    // Notify creator
    const event = await this.prisma.calendarEvent.findUnique({ where: { id: invite.eventId } });
    if (event) {
      const acceptor = await this.prisma.user.findUnique({ where: { id: userId }, include: { profile: { select: { firstName: true, lastName: true } } } });
      const name = [acceptor?.profile?.firstName, acceptor?.profile?.lastName].filter(Boolean).join(' ') || 'Участник';
      const token = await this.prisma.user.findUnique({ where: { id: event.userId }, select: { fcmToken: true } });
      if (token?.fcmToken) this.fcmService.sendNewMessage(token.fcmToken, 'Принято', name + ' принял(а): ' + event.title, '').catch(() => {});
    }
    return { ok: true };
  }

  async declineInvite(inviteId: string, userId: string) {
    const invite = await this.prisma.calendarInvite.findUnique({ where: { id: inviteId } });
    if (!invite || invite.userId !== userId) throw new NotFoundException();
    await this.prisma.calendarInvite.update({ where: { id: inviteId }, data: { status: 'DECLINED' } });
    const event = await this.prisma.calendarEvent.findUnique({ where: { id: invite.eventId } });
    if (event) {
      const decliner = await this.prisma.user.findUnique({ where: { id: userId }, include: { profile: { select: { firstName: true, lastName: true } } } });
      const name = [decliner?.profile?.firstName, decliner?.profile?.lastName].filter(Boolean).join(' ') || 'Участник';
      const token = await this.prisma.user.findUnique({ where: { id: event.userId }, select: { fcmToken: true } });
      if (token?.fcmToken) this.fcmService.sendNewMessage(token.fcmToken, 'Отклонено', name + ' отклонил(а): ' + event.title, '').catch(() => {});
    }
    return { ok: true };
  }

  async getEventInvites(eventId: string, userId: string) {
    const event = await this.prisma.calendarEvent.findUnique({ where: { id: eventId } });
    if (!event || event.userId !== userId) throw new NotFoundException();
    return this.prisma.calendarInvite.findMany({
      where: { eventId },
      include: { user: { select: { id: true, username: true, profile: { select: { firstName: true, lastName: true, avatarUrl: true } } } } },
    });
  }
}
