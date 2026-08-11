import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerService } from './messenger.service';
import { MessengerGateway } from './messenger.gateway';

/** Минимальный отступ: «отложить на пять секунд» — это обычная отправка. */
const MIN_LEAD_MS = 30_000;
/** Год вперёд — дальше уже не планирование, а забывание. */
const MAX_LEAD_MS = 365 * 24 * 3600_000;
/** Сколько отложенных держим на человека: защита от накопления мусора. */
const MAX_PENDING_PER_USER = 100;
/** Сколько отправляем за один тик, чтобы не залипнуть на большой пачке. */
const BATCH = 50;

@Injectable()
export class ScheduledMessageService {
  private readonly logger = new Logger(ScheduledMessageService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly messenger: MessengerService,
    private readonly gateway: MessengerGateway,
  ) {}

  async schedule(
    conversationId: string,
    senderId: string,
    input: {
      content: string;
      sendAt: string | Date;
      fileUrl?: string;
      fileName?: string;
      fileSize?: number;
      fileType?: string;
      s3Key?: string;
      topicId?: string;
      replyToId?: string;
      silent?: boolean;
    },
  ) {
    // Право писать в беседу проверяем сразу, а не в момент отправки: узнать об
    // отказе через сутки — худшее из возможного.
    await this.messenger.assertParticipant(conversationId, senderId);

    const when = new Date(input.sendAt);
    if (Number.isNaN(when.getTime())) {
      throw new BadRequestException('sendAt is not a valid date');
    }
    const lead = when.getTime() - Date.now();
    if (lead < MIN_LEAD_MS) {
      throw new BadRequestException('sendAt must be at least 30 seconds ahead');
    }
    if (lead > MAX_LEAD_MS) {
      throw new BadRequestException('sendAt is too far in the future');
    }
    if (!input.content?.trim() && !input.fileUrl) {
      throw new BadRequestException('Nothing to send');
    }

    const pending = await this.prisma.scheduledMessage.count({
      where: { senderId, sentAt: null, cancelledAt: null },
    });
    if (pending >= MAX_PENDING_PER_USER) {
      throw new BadRequestException(
        `Too many scheduled messages (max ${MAX_PENDING_PER_USER})`,
      );
    }

    return this.prisma.scheduledMessage.create({
      data: {
        conversationId,
        senderId,
        content: input.content ?? '',
        sendAt: when,
        fileUrl: input.fileUrl ?? null,
        fileName: input.fileName ?? null,
        fileSize: input.fileSize ?? null,
        fileType: input.fileType ?? null,
        s3Key: input.s3Key ?? null,
        topicId: input.topicId ?? null,
        replyToId: input.replyToId ?? null,
        silent: input.silent ?? false,
      },
    });
  }

  /** Свои отложенные в беседе — чужие не показываем даже участникам. */
  async listForConversation(conversationId: string, userId: string) {
    await this.messenger.assertParticipant(conversationId, userId);
    return this.prisma.scheduledMessage.findMany({
      where: { conversationId, senderId: userId, sentAt: null, cancelledAt: null },
      orderBy: { sendAt: 'asc' },
    });
  }

  async cancel(id: string, userId: string) {
    const row = await this.prisma.scheduledMessage.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('Scheduled message not found');
    if (row.senderId !== userId) throw new ForbiddenException('Not your message');
    if (row.sentAt) throw new BadRequestException('Already sent');
    if (row.cancelledAt) return { cancelled: true, alreadyCancelled: true };
    await this.prisma.scheduledMessage.update({
      where: { id },
      data: { cancelledAt: new Date() },
    });
    return { cancelled: true, alreadyCancelled: false };
  }

  /**
   * Отправляет всё, чему пришло время.
   *
   * Каждая строка захватывается условием `sentAt: null` в WHERE — при двух
   * работающих нодах (а на PROD их две) обе увидят одну и ту же строку, и без
   * захвата сообщение ушло бы дважды.
   */
  @Cron(CronExpression.EVERY_MINUTE)
  async dispatchDue() {
    const due = await this.prisma.scheduledMessage.findMany({
      where: { sendAt: { lte: new Date() }, sentAt: null, cancelledAt: null },
      orderBy: { sendAt: 'asc' },
      take: BATCH,
    });
    if (due.length === 0) return;

    for (const row of due) {
      const claimed = await this.prisma.scheduledMessage.updateMany({
        where: { id: row.id, sentAt: null, cancelledAt: null },
        data: { sentAt: new Date() },
      });
      if (claimed.count === 0) continue; // забрала соседняя нода

      try {
        const msg = await this.messenger.createMessage(
          row.conversationId,
          row.senderId,
          row.content,
          row.fileUrl
            ? {
                fileUrl: row.fileUrl,
                fileName: row.fileName ?? undefined,
                fileSize: row.fileSize ?? undefined,
                fileType: row.fileType ?? undefined,
                s3Key: row.s3Key ?? undefined,
              }
            : undefined,
          row.topicId ?? undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          row.replyToId ? { replyToId: row.replyToId } : undefined,
        );

        const senderName = await this.messenger.getUserDisplayName(row.senderId);
        const enriched = {
          ...msg,
          senderName,
          reactions: [],
          replyTo: await this.messenger.loadReplyPreview(row.replyToId),
        };
        this.gateway.broadcastNewMessage(enriched, row.conversationId);
        await this.gateway.fanOutToParticipants(
          enriched,
          row.senderId,
          row.conversationId,
          { silent: row.silent, senderName },
        );
      } catch (e) {
        // Отправка не удалась — возвращаем строку в очередь и запоминаем
        // причину, иначе сообщение молча исчезнет.
        await this.prisma.scheduledMessage.update({
          where: { id: row.id },
          data: { sentAt: null, lastError: String(e).slice(0, 300) },
        });
        this.logger.warn(`scheduled ${row.id} failed: ${e}`);
      }
    }
  }
}
