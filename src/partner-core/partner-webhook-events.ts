import { createHmac, randomUUID, timingSafeEqual } from 'crypto';

/** Паузы перед повторами доставки. Дальше событие выбрасывается: пуш через час бессмыслен. */
export const WEBHOOK_RETRY_DELAYS_MS: readonly number[] = [10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000];
export const WEBHOOK_MAX_ATTEMPTS = 1 + WEBHOOK_RETRY_DELAYS_MS.length;
const PREVIEW_MAX = 200;
// Intl.Segmenter режет по графемам корректно, но честно проходит по всей
// строке. Сообщение может быть многомегабайтным, а нужны только первые 200
// графем — поэтому вход сначала обрезаем по code units (запас x4 с лихвой
// покрывает и суррогатные пары, и составные эмодзи/комбинируемые символы).
const PREVIEW_SLICE_UNITS = PREVIEW_MAX * 4;
const previewSegmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });

/**
 * Вид сообщения для вебхука партнёра: по нему партнёр подбирает иконку пуша.
 * Определение самой функции (messageKind) — в messenger/push-text.util.ts;
 * тип живёт здесь, а не там, потому что мессенджер зависит от partner-core,
 * а не наоборот.
 */
export type MessageKind = 'text' | 'image' | 'video' | 'audio' | 'file' | 'system';

export interface WebhookEvent {
  id: string;
  type: 'message.created' | 'ping';
  createdAt: string;
  [key: string]: unknown;
}

export interface MessageCreatedInput {
  message: { id: string; senderId: string; sentAt?: Date | string | null };
  senderName: string;
  preview: string;
  kind: MessageKind;
  mentionsRecipient: boolean;
}

export interface WebhookConversation {
  id: string;
  type: string;
  title: string | null;
}

/**
 * Первые PREVIEW_MAX графем текста. Режет по графемам (Intl.Segmenter), а не
 * по code points — составной эмодзи или символ с комбинируемыми знаками на
 * границе не разрезается пополам.
 */
function truncatePreview(text: string): string {
  const wasSliced = text.length > PREVIEW_SLICE_UNITS;
  const bounded = text.slice(0, PREVIEW_SLICE_UNITS);
  const graphemes: string[] = [];
  for (const { segment } of previewSegmenter.segment(bounded)) {
    graphemes.push(segment);
    if (graphemes.length >= PREVIEW_MAX) break;
  }
  // Предварительный срез режет по code units, а не по границам графем. Если
  // он действительно что-то обрезал и графем всё равно набралось меньше
  // лимита — значит, цикл дошёл до самого конца обрезанного хвоста, и
  // последняя графема могла оказаться разрезанной посередине (составной
  // эмодзи ZWJ/тон кожи даёт висячий суррогат). Отбрасываем её, а не
  // показываем мусор партнёру.
  if (wasSliced && graphemes.length < PREVIEW_MAX) graphemes.pop();
  return graphemes.join('');
}

/**
 * Проверка заголовка X-TalerID-Signature над телом, которое реально пришло
 * (см. тестовый приёмник): разбирает `t=…,v1=…`, пересчитывает HMAC и
 * сравнивает его constant-time, а не строкой — чтобы не утекало через тайминг.
 */
export function verifyWebhookSignature(
  secret: string,
  header: string | null | undefined,
  body: string,
): boolean {
  if (!header) return false;
  const match = /^t=(\d+),v1=([0-9a-f]+)$/.exec(header);
  if (!match) return false;
  const [, ts, mac] = match;
  const expectedMac = /v1=([0-9a-f]+)$/.exec(signWebhook(secret, Number(ts), body))?.[1];
  if (!expectedMac) return false;
  const a = Buffer.from(mac, 'hex');
  const b = Buffer.from(expectedMac, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function buildMessageCreatedEvent(args: {
  recipient: { userId: string; externalId: string };
  senderExternalId: string | null;
  conversation: WebhookConversation;
  input: MessageCreatedInput;
}): WebhookEvent {
  const { recipient, senderExternalId, conversation, input } = args;
  const sentAt = input.message.sentAt ? new Date(input.message.sentAt) : new Date();
  return {
    // Одно сообщение одному получателю — одно событие: по id партнёр
    // отбрасывает повторные доставки.
    id: `evt_${input.message.id}_${recipient.userId}`,
    type: 'message.created',
    createdAt: new Date().toISOString(),
    recipient: { externalId: recipient.externalId, talerUserId: recipient.userId },
    conversation,
    message: {
      id: input.message.id,
      senderTalerUserId: input.message.senderId,
      senderExternalId,
      senderName: input.senderName,
      preview: truncatePreview(input.preview ?? ''),
      kind: input.kind,
      mentionsRecipient: input.mentionsRecipient,
      createdAt: sentAt.toISOString(),
    },
  };
}

export function pingEvent(): WebhookEvent {
  return { id: `evt_ping_${randomUUID()}`, type: 'ping', createdAt: new Date().toISOString() };
}

/** Заголовок X-TalerID-Signature: t=<unix-время>,v1=<hex HMAC-SHA256(секрет, "t.тело")>. */
export function signWebhook(secret: string, timestamp: number, body: string): string {
  const mac = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  return `t=${timestamp},v1=${mac}`;
}

/** Пауза перед повтором № attemptsMade (BullMQ считает с 1). */
export function partnerWebhookBackoff(attemptsMade: number): number {
  const index = Math.min(Math.max(attemptsMade, 1), WEBHOOK_RETRY_DELAYS_MS.length) - 1;
  return WEBHOOK_RETRY_DELAYS_MS[index];
}
