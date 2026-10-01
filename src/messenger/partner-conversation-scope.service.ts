import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  isPartnerConversationType,
  PARTNER_CONVERSATION_TYPES,
  PARTNER_FORBIDDEN,
} from '../partner-core/partner.constants';
import { FORWARD_BATCH_LIMIT } from './messenger.service';

/**
 * Что можно партнёрскому токену в мессенджере сверх обычных прав участника:
 * только личные чаты и группы (канал новостей TalerID, «Избранное» и чаты
 * AI-ассистентов в интерфейс партнёра не попадают) и группы только из своих
 * контактов. Спека: 2026-09-30-partner-messenger-api-design.md
 */
@Injectable()
export class PartnerConversationScope {
  constructor(private readonly prisma: PrismaService) {}

  /** Беседа другого типа — 403. Несуществующая — пропускаем: ответит обработчик. */
  async assertConversation(conversationId: string | undefined): Promise<void> {
    if (!conversationId) return;
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      select: { type: true },
    });
    if (conv && !isPartnerConversationType(conv.type))
      throw new ForbiddenException(PARTNER_FORBIDDEN);
  }

  async assertMessage(messageId: string | undefined): Promise<void> {
    if (!messageId) return;
    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { conversation: { select: { type: true } } },
    });
    if (msg && !isPartnerConversationType(msg.conversation.type)) {
      throw new ForbiddenException(PARTNER_FORBIDDEN);
    }
  }

  /**
   * Строгая проверка для фильтра сокета (socket-gate.ts): в отличие от
   * assertConversation выше — которая пропускает неизвестный id, потому что
   * дальше его встретит REST-обработчик и ответит 404 — у сокета нет такого
   * обработчика. Там либо true (можно кэшировать и пускать пакет), либо
   * false на что угодно нештатное: не нашли беседу, тип не DIRECT/GROUP.
   */
  async isPartnerConversation(conversationId: string): Promise<boolean> {
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      select: { type: true },
    });
    return !!conv && isPartnerConversationType(conv.type);
  }

  /** То же самое для сообщения — см. isPartnerConversation. */
  async isPartnerMessage(messageId: string): Promise<boolean> {
    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { conversation: { select: { type: true } } },
    });
    return !!msg && isPartnerConversationType(msg.conversation.type);
  }

  /**
   * Исходные сообщения пересылки: хоть одно из чужой для партнёра беседы —
   * 403. `messageIds` приходит голым `@Body('messageIds')` без DTO-проверки
   * (controller.ts), так что партнёрский клиент может прислать что угодно —
   * строку, число, массив не строк. Раньше это било TypeError'ом в `new
   * Set(...)`/`.some(...)` (500), теперь — внятный 400.
   */
  async assertMessages(messageIds: string[] | undefined): Promise<void> {
    if (messageIds == null) return;
    if (
      !Array.isArray(messageIds) ||
      messageIds.some((id) => typeof id !== 'string')
    ) {
      throw new BadRequestException('invalid_message_ids');
    }
    // Тот же потолок, что forwardMessages() применяет к самой пересылке —
    // до похода в БД: иначе partner-клиент мог бы прислать произвольно
    // длинный список id и заставить findMany тащить его целиком.
    if (messageIds.length > FORWARD_BATCH_LIMIT) {
      throw new BadRequestException('too_many_messages');
    }
    const ids = [...new Set(messageIds)];
    if (ids.length === 0) return;
    const rows = await this.prisma.message.findMany({
      where: { id: { in: ids } },
      select: { conversation: { select: { type: true } } },
    });
    if (rows.some((m) => !isPartnerConversationType(m.conversation.type))) {
      throw new ForbiddenException(PARTNER_FORBIDDEN);
    }
  }

  /** Беседы пользователя, видимые партнёрскому токену, — для фильтрации списков. */
  async visibleConversationIds(userId: string): Promise<Set<string>> {
    const rows = await this.prisma.conversationParticipant.findMany({
      where: {
        userId,
        conversation: { type: { in: [...PARTNER_CONVERSATION_TYPES] } },
      },
      select: { conversationId: true },
    });
    return new Set(rows.map((r) => r.conversationId));
  }

  /** В группу — только свои контакты (у партнёра это его «друзья»). */
  async assertAllContacts(userId: string, targetIds: string[]): Promise<void> {
    const others = [...new Set(targetIds ?? [])].filter((id) => id !== userId);
    if (others.length === 0) return;
    const rows = await this.prisma.contactRequest.findMany({
      where: {
        status: 'ACCEPTED',
        OR: [
          { senderId: userId, receiverId: { in: others } },
          { receiverId: userId, senderId: { in: others } },
        ],
      },
      select: { senderId: true, receiverId: true },
    });
    const contacts = new Set(
      rows.map((r) => (r.senderId === userId ? r.receiverId : r.senderId)),
    );
    const missing = others.filter((id) => !contacts.has(id));
    if (missing.length > 0)
      throw new ForbiddenException({
        message: 'not_a_contact',
        userIds: missing,
      });
  }
}
