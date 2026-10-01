import { systemMessagePushText } from './system-message-text.util';

/** Текст уведомления о сообщении: общий для пуша TalerID и вебхука партнёра. */
export function buildPushText(msg: any): string {
  const c = (msg?.content as string | null) ?? '';
  // У служебных сообщений в content лежит JSON, который расшифровывает клиент
  // при отрисовке ленты. В пуше расшифровывать некому — без этой ветки в
  // шторку прилетало «{"action":"member_added",…}».
  if (msg?.isSystem) return systemMessagePushText(c);
  if (c.startsWith('[CONTACT]')) return '📇 Контакт';
  if (c.startsWith('[POLL]')) return '📊 Опрос';
  if (msg?.fileUrl) {
    const ft = (msg?.fileType as string | null) ?? '';
    if (ft === 'image') return '🖼 Фото';
    if (ft === 'video') return '🎥 Видео';
    if (ft === 'audio') return '🎵 Аудио';
    return '📎 Файл';
  }
  return c;
}

export type MessageKind = 'text' | 'image' | 'video' | 'audio' | 'file' | 'system';

/** Вид сообщения для вебхука партнёра: по нему партнёр подбирает иконку пуша. */
export function messageKind(msg: any): MessageKind {
  if (msg?.isSystem) return 'system';
  if (msg?.fileUrl) {
    const ft = (msg?.fileType as string | null) ?? '';
    return ft === 'image' || ft === 'video' || ft === 'audio' ? ft : 'file';
  }
  return 'text';
}
