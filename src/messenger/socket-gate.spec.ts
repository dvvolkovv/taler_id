import { ForbiddenException } from '@nestjs/common';
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
      assertConversation: jest.fn().mockResolvedValue(undefined),
      assertMessage: jest.fn().mockResolvedValue(undefined),
    };
  });

  it('lets every event of a TalerID socket through', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1' });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['call_invite', {}])).toHaveBeenCalled();
    expect(scope.assertConversation).not.toHaveBeenCalled();
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
    expect(scope.assertConversation).toHaveBeenCalledTimes(1);
  });

  it('refuses a partner packet aimed at a channel', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.assertConversation.mockRejectedValue(new ForbiddenException('not_available_for_partner'));
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 'channel-1' }])).not.toHaveBeenCalled();
    expect(socket.emit).toHaveBeenCalledWith('error', { message: 'not_available_for_partner', event: 'message' });
  });

  it('checks the message of edit, delete, react and thread replies', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.assertMessage.mockRejectedValue(new ForbiddenException('not_available_for_partner'));
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['react_message', { conversationId: 'c1', messageId: 'saved-msg', emoji: '👍' }])).not.toHaveBeenCalled();
    expect(await send(['thread_reply', { conversationId: 'c1', threadParentId: 'saved-msg', content: 'x' }])).not.toHaveBeenCalled();
  });
});
