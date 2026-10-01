import { installSocketGate } from './socket-gate';

function fakeSocket(data: any = {}) {
  let middleware: (packet: any[], next: (err?: Error) => void) => void = () => undefined;
  const socket: any = {
    data,
    emit: jest.fn(),
    use: jest.fn((fn: any) => {
      middleware = fn;
    }),
  };
  const send = async (packet: any[]) => {
    const next = jest.fn();
    middleware(packet, next);
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    return next;
  };
  return { socket, send };
}

describe('installSocketGate', () => {
  let scope: any;
  beforeEach(() => {
    scope = {
      isPartnerConversation: jest.fn().mockResolvedValue(true),
      isPartnerMessage: jest.fn().mockResolvedValue(true),
    };
  });

  it('lets every event of a TalerID socket through', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1' });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['call_invite', {}])).toHaveBeenCalled();
    expect(scope.isPartnerConversation).not.toHaveBeenCalled();
  });

  it('drops packets of a socket that failed authentication', async () => {
    const { socket, send } = fakeSocket();
    installSocketGate(socket, Promise.resolve(false), scope);
    expect(await send(['message', { conversationId: 'c1' }])).not.toHaveBeenCalled();
    expect(socket.emit).not.toHaveBeenCalled();
  });

  it('holds packets until authentication finishes instead of losing them', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1' });
    let finish: (ok: boolean) => void = () => undefined;
    installSocketGate(socket, new Promise<boolean>((r) => (finish = r)), scope);
    const pending = send(['join', { conversationId: 'c1' }]);
    finish(true);
    expect(await pending).toHaveBeenCalled();
  });

  it('holds packets for a PARTNER socket too, until auth AND the scope check finish', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    let finish: (ok: boolean) => void = () => undefined;
    let resolveScope: (ok: boolean) => void = () => undefined;
    scope.isPartnerConversation.mockReturnValue(new Promise<boolean>((r) => (resolveScope = r)));
    installSocketGate(socket, new Promise<boolean>((r) => (finish = r)), scope);
    const pending = send(['message', { conversationId: 'c1', content: 'hi' }]);
    finish(true);
    // Auth finished, but the scope's DB lookup for c1 is still pending — the
    // packet must not be let through (or dropped) yet.
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    expect(await pending).not.toHaveBeenCalled();
  });

  it('refuses call events on a partner socket', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['call_invite', { conversationId: 'c1' }])).not.toHaveBeenCalled();
    expect(socket.emit).toHaveBeenCalledWith('error', { message: 'not_available_for_partner', event: 'call_invite' });
  });

  it('lets a partner message into a chat and checks each chat only once', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 'c1', content: 'hi' }])).toHaveBeenCalled();
    expect(await send(['typing', { conversationId: 'c1', isTyping: true }])).toHaveBeenCalled();
    expect(scope.isPartnerConversation).toHaveBeenCalledTimes(1);
  });

  it('refuses a partner packet aimed at a conversation the scope does not confirm (e.g. a channel)', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.isPartnerConversation.mockResolvedValue(false);
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 'channel-1' }])).not.toHaveBeenCalled();
    expect(socket.emit).toHaveBeenCalledWith('error', { message: 'not_available_for_partner', event: 'message' });
  });

  it('refuses an unknown conversationId outright (fails closed, unlike the REST 404 path)', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.isPartnerConversation.mockResolvedValue(false); // не нашли id вовсе
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['join', { conversationId: 'ghost' }])).not.toHaveBeenCalled();
  });

  it('refuses a non-string conversationId without even asking the scope', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 12345, content: 'hi' }])).not.toHaveBeenCalled();
    expect(socket.emit).toHaveBeenCalledWith('error', { message: 'not_available_for_partner', event: 'message' });
    expect(scope.isPartnerConversation).not.toHaveBeenCalled();
  });

  it('refuses a null conversationId (present but not a string)', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: null, content: 'hi' }])).not.toHaveBeenCalled();
    expect(scope.isPartnerConversation).not.toHaveBeenCalled();
  });

  it('never caches a conversation the scope refused — rechecks it every time', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.isPartnerConversation.mockResolvedValue(false);
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 'channel-1', content: 'a' }])).not.toHaveBeenCalled();
    expect(await send(['message', { conversationId: 'channel-1', content: 'b' }])).not.toHaveBeenCalled();
    expect(scope.isPartnerConversation).toHaveBeenCalledTimes(2);
  });

  it('checks the message of edit, delete, react and thread replies', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.isPartnerMessage.mockResolvedValue(false);
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['react_message', { conversationId: 'c1', messageId: 'saved-msg', emoji: '👍' }])).not.toHaveBeenCalled();
    expect(await send(['thread_reply', { conversationId: 'c1', threadParentId: 'saved-msg', content: 'x' }])).not.toHaveBeenCalled();
  });

  it('refuses a non-string messageId without even asking the scope', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(
      await send(['react_message', { conversationId: 'c1', messageId: ['not', 'a', 'string'], emoji: '👍' }]),
    ).not.toHaveBeenCalled();
    expect(scope.isPartnerMessage).not.toHaveBeenCalled();
  });

  it('does not keep a per-socket cache on client.data (must not travel through the Redis adapter)', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    await send(['message', { conversationId: 'c1', content: 'hi' }]);
    expect(() => JSON.stringify(socket.data)).not.toThrow();
    expect(socket.data.partnerConversations).toBeUndefined();
  });
});
