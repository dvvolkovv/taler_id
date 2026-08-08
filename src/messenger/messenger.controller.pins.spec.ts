import { MessengerController } from './messenger.controller';

describe('MessengerController pinned-messages branching', () => {
  let service: any;
  let gateway: any;
  let emit: jest.Mock;
  let controller: MessengerController;

  beforeEach(() => {
    // to() всегда возвращает один и тот же объект с emit — так можно
    // проверять и то, что комнату выбрали правильно, и что реально ушло.
    emit = jest.fn();
    service = {
      pinMessage: jest.fn(),
      unpinMessage: jest.fn(),
      unpinAll: jest.fn(),
      dismissPins: jest.fn(),
      getMessageById: jest.fn(),
      getUserDisplayName: jest.fn(),
    };
    gateway = {
      server: { to: jest.fn().mockReturnValue({ emit }) },
      deliverNewMessage: jest.fn().mockResolvedValue(undefined),
    };
    controller = new MessengerController(
      service as any,
      gateway as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
  });

  const user = { sub: 'user-1' };

  it('pin emits message_pinned with the documented payload and delivers the service message when systemMessageId is set', async () => {
    const pinnedAt = new Date('2026-08-06T12:00:00.000Z');
    service.pinMessage.mockResolvedValue({
      pinnedAt,
      pinnedCount: 3,
      alreadyPinned: false,
      systemMessageId: 'sys-1',
    });
    const full = { id: 'sys-1', conversationId: 'conv-1', content: 'X закрепил сообщение' };
    service.getMessageById.mockResolvedValue(full);
    service.getUserDisplayName.mockResolvedValue('Dmitry');

    const res = await controller.pinMessage('conv-1', 'msg-1', user);

    expect(gateway.server.to).toHaveBeenCalledWith('conv-1');
    expect(emit).toHaveBeenCalledWith('message_pinned', {
      conversationId: 'conv-1',
      messageId: 'msg-1',
      pinnedById: 'user-1',
      pinnedAt,
      pinnedCount: 3,
    });
    expect(service.getMessageById).toHaveBeenCalledWith('sys-1');
    expect(gateway.deliverNewMessage).toHaveBeenCalledWith(
      { ...full, senderName: 'Dmitry', reactions: [] },
      'user-1',
      'conv-1',
    );
    expect(res).toEqual({
      pinnedAt,
      pinnedCount: 3,
      alreadyPinned: false,
      systemMessageId: 'sys-1',
    });
  });

  it('pin with alreadyPinned: true emits nothing and delivers nothing', async () => {
    service.pinMessage.mockResolvedValue({
      pinnedAt: new Date(),
      pinnedCount: 3,
      alreadyPinned: true,
      systemMessageId: null,
    });

    await controller.pinMessage('conv-1', 'msg-1', user);

    expect(emit).not.toHaveBeenCalled();
    expect(service.getMessageById).not.toHaveBeenCalled();
    expect(gateway.deliverNewMessage).not.toHaveBeenCalled();
  });

  it('delivery failure does not fail the request', async () => {
    const pinnedAt = new Date('2026-08-06T12:00:00.000Z');
    service.pinMessage.mockResolvedValue({
      pinnedAt,
      pinnedCount: 4,
      alreadyPinned: false,
      systemMessageId: 'sys-2',
    });
    service.getMessageById.mockResolvedValue({ id: 'sys-2', conversationId: 'conv-1' });
    service.getUserDisplayName.mockResolvedValue('Dmitry');
    // Регрессия для fetchSockets-инцидента 2026-07-24: доставка падает, но
    // пин уже зафиксирован и разослан — запрос обязан резолвиться, а не 500.
    gateway.deliverNewMessage.mockRejectedValue(new Error('fetchSockets timeout'));

    const res = await controller.pinMessage('conv-1', 'msg-1', user);

    expect(res).toEqual({
      pinnedAt,
      pinnedCount: 4,
      alreadyPinned: false,
      systemMessageId: 'sys-2',
    });
    expect(emit).toHaveBeenCalledWith('message_pinned', expect.objectContaining({
      conversationId: 'conv-1',
      messageId: 'msg-1',
    }));
  });

  it('unpin emits message_unpinned only when wasPinned is true', async () => {
    service.unpinMessage.mockResolvedValue({ pinnedCount: 2, wasPinned: false });
    await controller.unpinMessage('conv-1', 'msg-1', user);
    expect(emit).not.toHaveBeenCalled();

    service.unpinMessage.mockResolvedValue({ pinnedCount: 1, wasPinned: true });
    await controller.unpinMessage('conv-1', 'msg-1', user);
    expect(emit).toHaveBeenCalledWith('message_unpinned', {
      conversationId: 'conv-1',
      messageId: 'msg-1',
      pinnedCount: 1,
    });
  });

  it('unpinAll with unpinned: 0 emits nothing', async () => {
    service.unpinAll.mockResolvedValue({ unpinned: 0 });

    await controller.unpinAll('conv-1', user);

    expect(emit).not.toHaveBeenCalled();
  });

  it('dismiss passes a real Date to service.dismissPins for a valid ISO body, and undefined for garbage', async () => {
    service.dismissPins.mockResolvedValue({ pinsDismissedAt: new Date() });

    await controller.dismissPins('conv-1', { upTo: '2026-08-06T12:00:00.000Z' }, user);
    expect(service.dismissPins).toHaveBeenLastCalledWith(
      'conv-1',
      'user-1',
      expect.any(Date),
    );

    await controller.dismissPins('conv-1', { upTo: 'not-a-date' }, user);
    expect(service.dismissPins).toHaveBeenLastCalledWith(
      'conv-1',
      'user-1',
      undefined,
    );
  });
});
