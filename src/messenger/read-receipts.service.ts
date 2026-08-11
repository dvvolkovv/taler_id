import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Сколько имён отдаём в списке прочитавших.
 *
 * В большой группе список на сотни человек бесполезен и дорог; показываем
 * первых и общее число.
 */
const READERS_LIMIT = 50;

@Injectable()
export class ReadReceiptsService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Просмотры постов канала.
   *
   * Считается по курсорам чтения, а не по отдельной таблице просмотров: у
   * подписчика канала курсор двигается ровно тогда, когда пост показался на
   * экране, — это и есть просмотр. Отдельная таблица для системного канала
   * означала бы двенадцать тысяч строк на каждый пост.
   *
   * Автор поста из счёта исключается: собственный пост «просмотром» не считают
   * ни в одном мессенджере.
   */
  async viewCountsFor(
    conversationId: string,
    messages: Array<{ id: string; sentAt: Date; senderId: string }>,
  ): Promise<Record<string, number>> {
    if (messages.length === 0) return {};

    const cursors = await this.prisma.conversationParticipant.findMany({
      where: { conversationId, lastReadAt: { not: null } },
      select: { userId: true, lastReadAt: true },
    });

    const out: Record<string, number> = {};
    for (const m of messages) {
      let n = 0;
      for (const c of cursors) {
        if (c.userId === m.senderId) continue;
        if (c.lastReadAt! >= m.sentAt) n++;
      }
      out[m.id] = n;
    }
    return out;
  }

  /**
   * Кто прочитал конкретное сообщение.
   *
   * Прочитавшим считается тот, чей курсор дошёл до момента отправки. Автор в
   * список не попадает: спрашивают всегда про других.
   */
  async readersOf(messageId: string, userId: string) {
    const message = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { id: true, conversationId: true, sentAt: true, senderId: true, deletedAt: true },
    });
    if (!message || message.deletedAt) throw new NotFoundException('Message not found');

    const me = await this.prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: { conversationId: message.conversationId, userId },
      },
      select: { id: true },
    });
    if (!me) throw new ForbiddenException('Not a participant');

    const where = {
      conversationId: message.conversationId,
      lastReadAt: { gte: message.sentAt },
      NOT: { userId: message.senderId },
    };

    const [total, rows] = await Promise.all([
      this.prisma.conversationParticipant.count({ where }),
      this.prisma.conversationParticipant.findMany({
        where,
        orderBy: { lastReadAt: 'asc' },
        take: READERS_LIMIT,
        select: { userId: true, lastReadAt: true },
      }),
    ]);

    const users = await this.prisma.user.findMany({
      where: { id: { in: rows.map((r) => r.userId) } },
      select: {
        id: true,
        username: true,
        profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
      },
    });
    const byId = new Map(users.map((u) => [u.id, u]));

    return {
      total,
      // Урезали ли список — клиенту нужно знать, чтобы честно написать «и ещё N».
      truncated: total > rows.length,
      readers: rows.map((r) => {
        const u = byId.get(r.userId);
        const name =
          [u?.profile?.firstName, u?.profile?.lastName].filter(Boolean).join(' ').trim() ||
          u?.username ||
          null;
        return {
          userId: r.userId,
          name,
          avatarUrl: u?.profile?.avatarUrl ?? null,
          readAt: r.lastReadAt,
        };
      }),
    };
  }
}
