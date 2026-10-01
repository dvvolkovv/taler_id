import { createHmac, randomUUID } from 'crypto';

/** Паузы перед повторами доставки. Дальше событие выбрасывается: пуш через час бессмыслен. */
export const WEBHOOK_RETRY_DELAYS_MS = [10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000];
export const WEBHOOK_MAX_ATTEMPTS = 1 + WEBHOOK_RETRY_DELAYS_MS.length;
const PREVIEW_MAX = 200;

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
  kind: string;
  mentionsRecipient: boolean;
}

export interface WebhookConversation {
  id: string;
  type: string;
  title: string | null;
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
      // По символам, а не по UTF-16: эмодзи на границе не разрезается пополам.
      preview: Array.from(input.preview ?? '').slice(0, PREVIEW_MAX).join(''),
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
