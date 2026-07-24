// Prevent Jest from walking into ESM-only transitive deps (sanitize-html → htmlparser2)
jest.mock('../mail/mail-bridge.service', () => ({
  MailBridgeService: jest.fn(),
}));

import { McpServerFactory } from './mcp-server.factory';

describe('McpServerFactory scope filtering', () => {
  const factory = new McpServerFactory(
    { findByRange: jest.fn(), findOne: jest.fn(), create: jest.fn(), update: jest.fn(), remove: jest.fn() } as any,
    { findAll: jest.fn(), create: jest.fn(), update: jest.fn(), remove: jest.fn() } as any,
    { listContacts: jest.fn(), getConversations: jest.fn(), getMessages: jest.fn(), searchMessages: jest.fn(), hasContactWith: jest.fn(), isBlockedBy: jest.fn(), getOrCreateDirectConversation: jest.fn(), createMessage: jest.fn(), getMessageById: jest.fn(), getUserDisplayName: jest.fn() } as any,
    { deliverNewMessage: jest.fn() } as any,
    { listMessages: jest.fn(), getMessage: jest.fn(), sendMessage: jest.fn() } as any,
  );

  function toolNames(scopes: string[]) {
    const server = factory.buildServer('user-1', scopes);
    return Object.keys((server as any)._registeredTools).sort();
  }

  it('calendar scope → only calendar tools', () => {
    expect(toolNames(['mcp:calendar'])).toEqual([
      'create_calendar_event', 'delete_calendar_event', 'get_calendar_event',
      'list_calendar_events', 'update_calendar_event',
    ]);
  });

  it('messages.read without send → no send_message', () => {
    const names = toolNames(['mcp:messages.read']);
    expect(names).not.toContain('send_message');
    expect(names).toContain('get_messages');
    expect(names).toHaveLength(4);
  });

  it('no mcp scopes → zero tools', () => {
    expect(toolNames(['openid', 'profile'])).toHaveLength(0);
  });

  it('all scopes → 14 tools', () => {
    expect(toolNames(['mcp:calendar','mcp:notes','mcp:messages.read','mcp:messages.send'])).toHaveLength(14);
  });

  it('mail scopes → mail tools', () => {
    expect(toolNames(['mcp:mail.read', 'mcp:mail.send'])).toEqual([
      'check_mail', 'read_mail', 'send_mail',
    ]);
  });

  it('all scopes including mail → 17 tools', () => {
    expect(toolNames(['mcp:calendar','mcp:notes','mcp:messages.read','mcp:messages.send','mcp:mail.read','mcp:mail.send'])).toHaveLength(17);
  });
});
