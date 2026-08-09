import { systemMessagePushText } from './system-message-text.util';

describe('systemMessagePushText', () => {
  it('never returns raw JSON for any action the service can emit', () => {
    // Every case _createSystemMessage can produce, plus an unknown one.
    const contents = [
      JSON.stringify({ action: 'group_created', actor: 'Аня' }),
      JSON.stringify({ action: 'member_added', actor: 'Аня', target: 'Боря' }),
      JSON.stringify({ action: 'member_removed', actor: 'Аня', target: 'Боря' }),
      JSON.stringify({ action: 'member_left', actor: 'Боря' }),
      JSON.stringify({ action: 'role_changed', actor: 'Аня', target: 'Боря', role: 'ADMIN' }),
      JSON.stringify({ action: 'message_pinned', actor: 'Аня', preview: 'Встреча в 14:00' }),
      JSON.stringify({ action: 'something_new_we_add_later', actor: 'Аня' }),
    ];

    for (const c of contents) {
      const out = systemMessagePushText(c);
      expect(out.startsWith('{')).toBe(false);
      expect(out).not.toContain('"action"');
      expect(out.length).toBeGreaterThan(0);
    }
  });

  it('renders a pin with its preview', () => {
    const out = systemMessagePushText(
      JSON.stringify({ action: 'message_pinned', actor: 'Аня', preview: 'Встреча в 14:00' }),
    );
    expect(out).toBe('Аня закрепил сообщение: Встреча в 14:00');
  });

  it('renders a pin without a preview', () => {
    const out = systemMessagePushText(JSON.stringify({ action: 'message_pinned', actor: 'Аня' }));
    expect(out).toBe('Аня закрепил сообщение');
  });

  it('matches the wording the app shows in the chat feed', () => {
    expect(systemMessagePushText(JSON.stringify({ action: 'member_added', actor: 'Аня', target: 'Боря' })))
      .toBe('Боря присоединился');
    expect(systemMessagePushText(JSON.stringify({ action: 'member_left', actor: 'Боря' })))
      .toBe('Боря покинул группу');
    expect(systemMessagePushText(JSON.stringify({ action: 'member_removed', actor: 'Аня', target: 'Боря' })))
      .toBe('Боря удалён');
    expect(systemMessagePushText(JSON.stringify({ action: 'role_changed', actor: 'Аня', target: 'Боря', role: 'ADMIN' })))
      .toBe('Боря теперь ADMIN');
    expect(systemMessagePushText(JSON.stringify({ action: 'group_created', actor: 'Аня' })))
      .toBe('Группа создана');
  });

  it('passes plain-text system messages through untouched', () => {
    // informer-bot alerts are already human-readable and must not be mangled
    const alert = '⚠️ **Informer API недоступен 15+ минут**';
    expect(systemMessagePushText(alert)).toBe(alert);
  });

  it('survives malformed input instead of throwing', () => {
    expect(systemMessagePushText('{not json at all')).toBe('{not json at all');
    expect(systemMessagePushText('')).toBe('');
    expect(systemMessagePushText(null)).toBe('');
    expect(systemMessagePushText(undefined)).toBe('');
    expect(systemMessagePushText(JSON.stringify({ no: 'action' }))).toBe('{"no":"action"}');
  });

  it('does not crash when the payload omits the names', () => {
    expect(systemMessagePushText(JSON.stringify({ action: 'member_added' }))).toBe('Новый участник');
    expect(systemMessagePushText(JSON.stringify({ action: 'role_changed' }))).toBe('Роль изменена');
  });
});
