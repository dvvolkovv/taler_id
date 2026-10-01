import type { Socket } from 'socket.io';
import { PARTNER_FORBIDDEN } from '../partner-core/partner.constants';
import type { PartnerConversationScope } from './partner-conversation-scope.service';

/** События, которые принимает сокет с партнёрским токеном. Всё остальное — отказ. */
export const PARTNER_SOCKET_EVENTS: ReadonlySet<string> = new Set([
  'join',
  'message',
  'edit_message',
  'delete_message',
  'typing',
  'react_message',
  'mark_read',
  'thread_reply',
]);

/** Поля пакета, где лежит id сообщения чужой беседы, если клиент хитрит. */
const MESSAGE_ID_FIELDS = ['messageId', 'threadParentId'] as const;

/**
 * Фильтр входящих пакетов сокета мессенджера:
 *  - пока проверяется токен, пакеты ждут — не теряются и не обгоняют друг друга;
 *  - проверка не прошла — пакеты выбрасываются (сокет к этому моменту отключён);
 *  - партнёрский сокет пропускает только PARTNER_SOCKET_EVENTS и только к
 *    личным чатам и группам. Новое событие закрыто для партнёров, пока его не
 *    добавят в список, — так же, как @PartnerAllowed в REST.
 */
export function installSocketGate(
  client: Socket,
  ready: Promise<boolean>,
  scope: PartnerConversationScope,
): void {
  client.use((packet, next) => {
    void ready.then(async (ok) => {
      if (!ok) return;
      if (!client.data.partner) return next();
      const [event, payload] = packet as unknown as [string, any];
      if (PARTNER_SOCKET_EVENTS.has(event) && (await partnerPayloadAllowed(client, payload, scope))) {
        return next();
      }
      client.emit('error', { message: PARTNER_FORBIDDEN, event });
    });
  });
}

async function partnerPayloadAllowed(
  client: Socket,
  payload: any,
  scope: PartnerConversationScope,
): Promise<boolean> {
  try {
    const seen: Set<string> = (client.data.partnerConversations ??= new Set<string>());
    const conversationId = typeof payload?.conversationId === 'string' ? payload.conversationId : undefined;
    // Тип беседы не меняется: проверенную один раз больше не спрашиваем
    // («печатает…» шлётся часто).
    if (conversationId && !seen.has(conversationId)) {
      await scope.assertConversation(conversationId);
      seen.add(conversationId);
    }
    for (const field of MESSAGE_ID_FIELDS) {
      const messageId = typeof payload?.[field] === 'string' ? payload[field] : undefined;
      if (messageId) await scope.assertMessage(messageId);
    }
    return true;
  } catch {
    return false;
  }
}
