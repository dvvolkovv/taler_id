export const MCP_SCOPES = [
  'mcp:calendar',
  'mcp:notes',
  'mcp:messages.read',
  'mcp:messages.send',
] as const;

export const MCP_SCOPE_DESCRIPTIONS: Record<string, { ru: string; en: string }> = {
  'mcp:calendar': {
    ru: 'Просмотр и управление календарём и напоминаниями',
    en: 'View and manage your calendar and reminders',
  },
  'mcp:notes': {
    ru: 'Просмотр и управление заметками',
    en: 'View and manage your notes',
  },
  'mcp:messages.read': {
    ru: 'Чтение ваших сообщений и списка контактов',
    en: 'Read your messages and contact list',
  },
  'mcp:messages.send': {
    ru: 'Отправка сообщений вашим контактам от вашего имени',
    en: 'Send messages to your contacts on your behalf',
  },
};
