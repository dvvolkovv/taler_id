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
 * Беседы, уже подтверждённые для партнёрского сокета как DIRECT/GROUP — не
 * спрашиваем повторно («печатает…» шлётся часто). По сокету, а не в
 * client.data: Set не переживает JSON.stringify (Redis-адаптер сериализует
 * client.data в JSON по запросу fetchSockets() с соседней ноды — Set стал бы
 * пустым объектом `{}` молча, и кэш перестал бы работать без единой ошибки).
 * WeakMap не держит сокет живым дольше, чем он нужен где-то ещё.
 */
const partnerConversationsSeen = new WeakMap<Socket, Set<string>>();

/**
 * Фильтр входящих пакетов сокета мессенджера:
 *  - пока проверяется токен, пакеты ждут — не теряются;
 *  - проверка не прошла — пакеты выбрасываются (сокет к этому моменту отключён);
 *  - партнёрский сокет пропускает только PARTNER_SOCKET_EVENTS и только к
 *    личным чатам и группам, закрыто по умолчанию: id беседы или сообщения,
 *    который присутствует, но не строка, либо не подтверждён как
 *    DIRECT/GROUP (включая несуществующий id) — отказ, а не пропуск. Это
 *    отличается от REST (assertConversation/assertMessage), где неизвестный
 *    id пропускается и 404 отвечает сам обработчик — у сокета обработчика,
 *    которому можно было бы отдать ответственность, нет. Новое событие
 *    закрыто для партнёров, пока его не добавят в список, — так же, как
 *    @PartnerAllowed в REST.
 *
 * Очерёдность: next() для пакета вызывается после того, как для него
 * закончилась проверка (ready + при партнёре — scope), и пакеты одного
 * сокета попадают в обработчик (`@SubscribeMessage`) в том порядке, в
 * котором получили next(). Но это НЕ значит, что они проверяются по очереди:
 * у каждого пакета своя цепочка await — частый случай (беседа уже в кэше)
 * проверяется мгновенно, редкий (первый пакет на новую беседу) ждёт ответ
 * базы, и более быстрый пакет может обогнать более медленный. Так что
 * порядок ВЫЗОВА обработчика не гарантирован относительно порядка ПОЛУЧЕНИЯ
 * — гарантирован только относительно порядка, в котором каждый пакет прошёл
 * СВОЮ проверку.
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
      if (
        PARTNER_SOCKET_EVENTS.has(event) &&
        (await partnerPayloadAllowed(client, payload, scope))
      ) {
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
    const obj = payload != null && typeof payload === 'object' ? payload : {};
    // Все 8 событий из PARTNER_SOCKET_EVENTS несут conversationId — в
    // отличие от messageId/threadParentId ниже, оно не опциональное.
    // Раньше отсутствие поля пропускало проверку вовсе: react_message без
    // conversationId (только messageId) долетал до обработчика, а тот звал
    // getParticipants(undefined) — Prisma читала весь ConversationParticipant
    // (~12.7k строк на PROD) и в ответ уходил текст ошибки Prisma.
    const conversationId = obj.conversationId;
    if (typeof conversationId !== 'string') return false;
    let seen = partnerConversationsSeen.get(client);
    if (!seen) {
      seen = new Set<string>();
      partnerConversationsSeen.set(client, seen);
    }
    if (!seen.has(conversationId)) {
      // Кэшируем только подтверждённые — отказ не запоминается, иначе
      // второй пакет на тот же чужой id прошёл бы без проверки вовсе.
      if (!(await scope.isPartnerConversation(conversationId))) return false;
      seen.add(conversationId);
    }
    for (const field of MESSAGE_ID_FIELDS) {
      if (field in obj) {
        const messageId = obj[field];
        if (typeof messageId !== 'string') return false;
        if (!(await scope.isPartnerMessage(messageId))) return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}
