/** Сколько живёт ожидание подтверждения. */
export const APPROVAL_TTL_SECONDS = 10 * 60;

/**
 * Сколько ещё помнится факт «токены уже забрали». Без этого второй опрос,
 * прилетевший вплотную к первому, получил бы «истекло» — и клиент показал бы
 * ошибку человеку, который на самом деле только что вошёл.
 */
export const APPROVAL_CLAIMED_TTL_SECONDS = 60;

/** Ожиданий на пользователя в час. Выше — 429. */
export const MAX_PENDING_PER_HOUR = 10;

/** Отправок кода на почту в рамках одного ожидания. */
export const MAX_EMAIL_SENDS = 3;

/** Пауза между отправками кода, секунды. */
export const EMAIL_RESEND_COOLDOWN_SECONDS = 60;

/** Неверных кодов, после которых ожидание сжигается. */
export const MAX_CODE_ATTEMPTS = 5;

/**
 * Требовать ли подтверждение по умолчанию для аккаунтов, которые тумблер не
 * трогали. В первом релизе false: фича обкатывается на тех, кто включил сам.
 * Перевод в true — правка этой строки плюс миграция
 * `UPDATE "Profile" SET "newDeviceApproval" = true`.
 */
export const NEW_DEVICE_APPROVAL_DEFAULT = false;

export const approvalKey = (token: string) => `device_approval:${token}`;
export const approvalIdKey = (id: string) => `device_approval_id:${id}`;
export const claimedKey = (token: string) => `device_approval_claimed:${token}`;
export const codeKey = (token: string) => `device_approval_code:${token}`;
export const codeAttemptsKey = (token: string) =>
  `device_approval_attempts:${token}`;
export const emailSendsKey = (token: string) =>
  `device_approval_sends:${token}`;
export const emailCooldownKey = (token: string) =>
  `device_approval_cooldown:${token}`;
export const rateKey = (userId: string) => `device_approval_rate:${userId}`;

/**
 * Индекс «ожидания этого пользователя». Redis-множество approvalId — без него
 * найти ожидания по userId можно было бы только сканированием ключей.
 */
export const userPendingKey = (userId: string) =>
  `device_approval_pending:${userId}`;

export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

export interface ApprovalRecord {
  /**
   * Несекретный идентификатор — он и только он едет в пуш. Секрет
   * (`approvalToken`) уходит исключительно в тело ответа новому устройству:
   * превью уведомления на заблокированном экране не должно давать доступ
   * к аккаунту.
   */
  approvalId: string;
  userId: string;
  deviceId: string;
  deviceInfo: string;
  ip: string;
  location: string | null;
  status: ApprovalStatus;
  createdAt: string;
}
