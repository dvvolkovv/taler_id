/**
 * Человекочитаемый текст служебного сообщения для пуша.
 *
 * У служебных сообщений в `content` лежит JSON вида
 * `{"action":"member_added","actor":"Аня","target":"Боря"}` — его расшифровывает
 * клиент, когда рисует строку в чате. В пуш-уведомлении расшифровывать некому,
 * и до этой функции туда улетал сырой JSON: пользователь видел уведомление,
 * начинающееся с фигурной скобки.
 *
 * Формулировки намеренно повторяют те, что приложение показывает в ленте
 * (`app_ru.arb`: memberJoined, memberLeftGroup, memberWasRemoved, roleChangedTo,
 * messagePinnedBy), чтобы пуш и чат не расходились.
 *
 * Не-JSON содержимое (например, текстовые алёрты informer-бота) возвращается
 * как есть — оно и так человекочитаемое.
 */
export function systemMessagePushText(content: string | null | undefined): string {
  const raw = content ?? '';
  if (!raw.startsWith('{')) return raw;

  let data: Record<string, any>;
  try {
    data = JSON.parse(raw);
  } catch {
    return raw;
  }
  if (!data || typeof data.action !== 'string') return raw;

  const actor = typeof data.actor === 'string' ? data.actor : '';
  const target = typeof data.target === 'string' ? data.target : '';
  const role = typeof data.role === 'string' ? data.role : '';
  const preview = typeof data.preview === 'string' ? data.preview.trim() : '';

  switch (data.action) {
    case 'group_created':
      return 'Группа создана';
    case 'member_added':
      return target ? `${target} присоединился` : 'Новый участник';
    case 'member_left':
      return actor ? `${actor} покинул группу` : 'Участник покинул группу';
    case 'member_removed':
      return target ? `${target} удалён` : 'Участник удалён';
    case 'role_changed':
      return target && role ? `${target} теперь ${role}` : 'Роль изменена';
    case 'message_pinned': {
      // Превью добавляем только в пуш: в чате пользователь и так видит само
      // закреплённое сообщение, а из уведомления его иначе не разобрать.
      const who = actor ? `${actor} закрепил сообщение` : 'Сообщение закреплено';
      return preview ? `${who}: ${preview}` : who;
    }
    default:
      // Незнакомое действие: лучше нейтральная фраза, чем скобки в шторке.
      return actor ? `${actor}: обновление в чате` : 'Обновление в чате';
  }
}
