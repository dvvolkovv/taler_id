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
      where: {
        userId,
        startAt: { gte: startDate, lte: endDate },
      },
      orderBy: { startAt: 'asc' },
    });
  }

  async findOne(userId: string, id: string) {
    const event = await this.prisma.calendarEvent.findUnique({ where: { id } });
    if (!event) throw new NotFoundException('Event not found');
    if (event.userId !== userId) throw new ForbiddenException();
    return event;
  }

  async create(userId: string, data: {
    title: string; description?: string; type: string;
    startAt: string; endAt?: string; allDay?: boolean;
    reminderAt?: string; contactIds?: string[]; createdBy?: string;
  }) {
    return this.prisma.calendarEvent.create({
      data: {
        userId,
        title: data.title,
        description: data.description,
        type: data.type as any,
        startAt: new Date(data.startAt),
        endAt: data.endAt ? new Date(data.endAt) : null,
        allDay: data.allDay ?? false,
        reminderAt: data.reminderAt ? new Date(data.reminderAt) : null,
        contactIds: data.contactIds ?? [],
        createdBy: data.createdBy ?? 'MANUAL',
      },
    });
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
    if (data.reminderAt !== undefined) {
      updateData.reminderAt = new Date(data.reminderAt);
      updateData.reminderSent = false;
    }
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
      where: {
        reminderAt: { lte: new Date() },
        reminderSent: false,
      },
      include: { user: { select: { fcmToken: true } } },
    });

    for (const event of pending) {
      try {
        if (event.user?.fcmToken) {
          await this.fcmService.sendNewMessage(
            event.user.fcmToken,
            'Напоминание',
            event.title,
            '',
          );
          this.logger.log('Reminder sent for event ' + event.id);
        }
        await this.prisma.calendarEvent.update({
          where: { id: event.id },
          data: { reminderSent: true },
        });
      } catch (e) {
        this.logger.error('Reminder failed for event ' + event.id, e);
      }
    }
  }
}
