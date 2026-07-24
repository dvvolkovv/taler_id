import { HttpException, NotFoundException } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  registerMessengerReadTools,
  registerMessengerSendTool,
} from './messenger.tools';

// ─── Shared mock factory ───

function makeSvc(overrides: Record<string, jest.Mock> = {}) {
  return {
    listContacts: jest.fn().mockResolvedValue([{ id: 'c1', username: 'alice' }]),
    getConversations: jest.fn().mockResolvedValue([{ id: 'conv1' }]),
    getMessages: jest.fn().mockResolvedValue({ messages: [], nextCursor: undefined }),
    searchMessages: jest.fn().mockResolvedValue([]),
    hasContactWith: jest.fn().mockResolvedValue(true),
    getOrCreateDirectConversation: jest.fn().mockResolvedValue({ id: 'conv2' }),
    createMessage: jest.fn().mockResolvedValue({ id: 'msg1', deduped: false }),
    getMessageById: jest.fn().mockResolvedValue({ id: 'msg1', content: 'hello', sentAt: new Date() }),
    getUserDisplayName: jest.fn().mockResolvedValue('Alice'),
    ...overrides,
  };
}

function makeGateway() {
  return {
    server: {
      to: jest.fn().mockReturnThis(),
      emit: jest.fn(),
    },
  };
}

// ─── registerMessengerReadTools ───

describe('registerMessengerReadTools', () => {
  function build(svc = makeSvc()) {
    const server = new McpServer({ name: 't', version: '1' });
    registerMessengerReadTools(server, svc, 'user-1');
    return { server, svc };
  }

  it('registers exactly four tools', () => {
    const { server } = build();
    const names = Object.keys((server as any)._registeredTools);
    expect(names.sort()).toEqual([
      'get_messages',
      'list_contacts',
      'list_conversations',
      'search_messages',
    ]);
  });

  // ─── list_contacts ───

  it('list_contacts calls listContacts with userId and returns JSON', async () => {
    const { server, svc } = build();
    const tool = (server as any)._registeredTools['list_contacts'];
    const result = await tool.handler({}, {} as any);
    expect(svc.listContacts).toHaveBeenCalledWith('user-1');
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveLength(1);
    expect(data[0].id).toBe('c1');
  });

  // ─── list_conversations ───

  it('list_conversations calls getConversations with userId and returns JSON', async () => {
    const { server, svc } = build();
    const tool = (server as any)._registeredTools['list_conversations'];
    const result = await tool.handler({}, {} as any);
    expect(svc.getConversations).toHaveBeenCalledWith('user-1');
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveLength(1);
    expect(data[0].id).toBe('conv1');
  });

  // ─── get_messages ───

  it('get_messages passes correct args (conversationId, userId, cursor, limit)', async () => {
    const { server, svc } = build();
    const tool = (server as any)._registeredTools['get_messages'];
    await tool.handler({ conversation_id: 'conv1', cursor: 'abc', limit: 10 }, {} as any);
    expect(svc.getMessages).toHaveBeenCalledWith('conv1', 'user-1', 'abc', 10);
  });

  it('get_messages uses default limit 30 when not provided', async () => {
    const { server, svc } = build();
    const tool = (server as any)._registeredTools['get_messages'];
    await tool.handler({ conversation_id: 'conv1' }, {} as any);
    expect(svc.getMessages).toHaveBeenCalledWith('conv1', 'user-1', undefined, 30);
  });

  it('get_messages returns isError for HttpException (e.g. not a participant)', async () => {
    const svc = makeSvc({
      getMessages: jest.fn().mockRejectedValue(new NotFoundException('Not participant')),
    });
    const { server } = build(svc);
    const tool = (server as any)._registeredTools['get_messages'];
    const result = await tool.handler({ conversation_id: 'bad-conv' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/bad-conv/);
  });

  it('get_messages re-throws plain Error', async () => {
    const svc = makeSvc({
      getMessages: jest.fn().mockRejectedValue(new Error('db down')),
    });
    const { server } = build(svc);
    const tool = (server as any)._registeredTools['get_messages'];
    await expect(
      tool.handler({ conversation_id: 'conv1' }, {} as any),
    ).rejects.toThrow('db down');
  });

  it('get_messages schema rejects limit > 100', () => {
    const { server } = build();
    const schema = (server as any)._registeredTools['get_messages'].inputSchema;
    expect(schema.safeParse({ conversation_id: 'x', limit: 200 }).success).toBe(false);
  });

  // ─── search_messages ───

  it('search_messages calls searchMessages(query, userId) in that arg order', async () => {
    const { server, svc } = build();
    const tool = (server as any)._registeredTools['search_messages'];
    await tool.handler({ query: 'hello' }, {} as any);
    expect(svc.searchMessages).toHaveBeenCalledWith('hello', 'user-1');
  });

  it('search_messages schema rejects query shorter than 2 chars', () => {
    const { server } = build();
    const schema = (server as any)._registeredTools['search_messages'].inputSchema;
    expect(schema.safeParse({ query: 'x' }).success).toBe(false);
  });
});

// ─── registerMessengerSendTool ───

describe('registerMessengerSendTool', () => {
  function build(svc = makeSvc(), gw = makeGateway()) {
    const server = new McpServer({ name: 't', version: '1' });
    registerMessengerSendTool(server, svc, gw as any, 'user-1');
    return { server, svc, gw };
  }

  it('registers exactly one tool: send_message', () => {
    const { server } = build();
    const names = Object.keys((server as any)._registeredTools);
    expect(names).toEqual(['send_message']);
  });

  // ─── contact gate ───

  it('refuses to send when hasContactWith returns false (no createMessage called)', async () => {
    const svc = makeSvc({ hasContactWith: jest.fn().mockResolvedValue(false) });
    const { server } = build(svc);
    const tool = (server as any)._registeredTools['send_message'];
    const result = await tool.handler({ contact_id: 'stranger', text: 'hello' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/контакт/i);
    expect(svc.createMessage).not.toHaveBeenCalled();
    expect(svc.getOrCreateDirectConversation).not.toHaveBeenCalled();
  });

  // ─── happy path ───

  it('happy path: creates conversation, sends message, broadcasts, returns ids', async () => {
    const gw = makeGateway();
    const svc = makeSvc({
      createMessage: jest.fn().mockResolvedValue({ id: 'msg42', deduped: false }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'msg42', content: 'hi', sentAt: new Date() }),
      getUserDisplayName: jest.fn().mockResolvedValue('Bob'),
    });
    const { server } = build(svc, gw);
    const tool = (server as any)._registeredTools['send_message'];
    const result = await tool.handler({ contact_id: 'c1', text: 'hi' }, {} as any);

    // contact gate checked
    expect(svc.hasContactWith).toHaveBeenCalledWith('user-1', 'c1');

    // conversation obtained
    expect(svc.getOrCreateDirectConversation).toHaveBeenCalledWith('user-1', 'c1');

    // message created with (convId, senderId, text)
    expect(svc.createMessage).toHaveBeenCalledWith('conv2', 'user-1', 'hi');

    // full message fetched for broadcast
    expect(svc.getMessageById).toHaveBeenCalledWith('msg42');

    // broadcast emitted to conv room
    expect(gw.server.to).toHaveBeenCalledWith('conv2');
    expect(gw.server.emit).toHaveBeenCalledWith(
      'new_message',
      expect.objectContaining({ id: 'msg42', senderName: 'Bob', reactions: [] }),
    );

    // result shape
    const data = JSON.parse(result.content[0].text);
    expect(data).toEqual({ message_id: 'msg42', conversation_id: 'conv2' });
  });

  // ─── deduped path ───

  it('deduped path: no broadcast, still returns ids', async () => {
    const gw = makeGateway();
    const svc = makeSvc({
      createMessage: jest.fn().mockResolvedValue({ id: 'msg99', deduped: true }),
    });
    const { server } = build(svc, gw);
    const tool = (server as any)._registeredTools['send_message'];
    const result = await tool.handler({ contact_id: 'c1', text: 'hi' }, {} as any);

    expect(svc.getMessageById).not.toHaveBeenCalled();
    expect(gw.server.emit).not.toHaveBeenCalled();

    const data = JSON.parse(result.content[0].text);
    expect(data).toEqual({ message_id: 'msg99', conversation_id: 'conv2' });
  });

  // ─── getMessageById returns null ───

  it('no broadcast and no crash when getMessageById returns null', async () => {
    const gw = makeGateway();
    const svc = makeSvc({
      createMessage: jest.fn().mockResolvedValue({ id: 'msg55', deduped: false }),
      getMessageById: jest.fn().mockResolvedValue(null),
    });
    const { server } = build(svc, gw);
    const tool = (server as any)._registeredTools['send_message'];
    const result = await tool.handler({ contact_id: 'c1', text: 'hi' }, {} as any);

    expect(gw.server.emit).not.toHaveBeenCalled();
    const data = JSON.parse(result.content[0].text);
    expect(data.message_id).toBe('msg55');
  });

  // ─── text min 1 char ───

  it('send_message schema rejects empty text', () => {
    const { server } = build();
    const schema = (server as any)._registeredTools['send_message'].inputSchema;
    expect(schema.safeParse({ contact_id: 'c1', text: '' }).success).toBe(false);
  });
});
