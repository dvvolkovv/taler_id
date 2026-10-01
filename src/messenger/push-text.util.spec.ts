import { buildPushText, messageKind } from './push-text.util';

describe('push text', () => {
  it.each([
    [{ content: 'hello' }, 'hello', 'text'],
    [{ content: '[CONTACT]{"id":"x"}' }, '📇 Контакт', 'text'],
    [{ content: '[POLL]{"q":"?"}' }, '📊 Опрос', 'text'],
    [{ content: '', fileUrl: 'u', fileType: 'image' }, '🖼 Фото', 'image'],
    [{ content: '', fileUrl: 'u', fileType: 'video' }, '🎥 Видео', 'video'],
    [{ content: '', fileUrl: 'u', fileType: 'audio' }, '🎵 Аудио', 'audio'],
    [{ content: '', fileUrl: 'u', fileType: 'pdf' }, '📎 Файл', 'file'],
  ])('%j → %p / %p', (msg: any, text: string, kind: string) => {
    expect(buildPushText(msg)).toBe(text);
    expect(messageKind(msg)).toBe(kind);
  });

  it('decodes system messages instead of showing JSON', () => {
    const msg = {
      isSystem: true,
      content: JSON.stringify({ action: 'message_pinned', actor: 'Alice', preview: 'Встреча' }),
    };
    expect(buildPushText(msg)).not.toContain('{');
    expect(messageKind(msg)).toBe('system');
  });
});
