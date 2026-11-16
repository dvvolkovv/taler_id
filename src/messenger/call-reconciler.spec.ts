import { Logger } from '@nestjs/common';
import { CallReconciler } from './call-reconciler';

// A call stays open on the server — and in the remaining person's app, as
// the "return to call" banner — when the other side vanishes without sending
// call_ended: their app died, they lost network. LiveKit webhooks are off on
// every environment, so nothing tells the server. The reconciler asks LiveKit
// who is still in each open call and ends the ones somebody has left.

const T0 = new Date('2026-11-16T12:00:00Z');
const at = (s: number) => new Date(T0.getTime() + s * 1000);

const call = (over: Record<string, unknown> = {}) => ({
  roomName: 'call-1',
  initiatorId: 'alice',
  participantIds: ['alice', 'bob'],
  conversationId: 'conv-1',
  ...over,
});

function setup(calls: unknown[] = [call()]) {
  const store = new Map<string, string>();
  const redis = {
    setNxEx: jest.fn(async (key: string, _ttl: number, value: string) => {
      if (store.has(key)) return false;
      store.set(key, value);
      return true;
    }),
    get: jest.fn(async (key: string) => store.get(key) ?? null),
    del: jest.fn(async (key: string) => {
      store.delete(key);
    }),
  };
  const prisma = { callLog: { findMany: jest.fn(async () => calls) } };
  const probe = { identities: jest.fn(async (_room: string) => ['alice#d1']) };
  const gateway = { endCallFromHttp: jest.fn(async () => {}) };
  const reconciler = new CallReconciler(
    prisma as any,
    redis as any,
    probe as any,
    gateway as any,
  );
  // Each pass takes a short lock so two app nodes don't both end a call;
  // between passes in a test it is released, as its TTL would.
  const pass = async (now: Date) => {
    await reconciler.runOnce(now);
    store.delete('call:reconcile:lock');
  };
  return { reconciler, prisma, redis, probe, gateway, store, pass };
}

beforeAll(() => {
  jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
  jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
});

describe('CallReconciler', () => {
  it('ends a call a minute after the peer vanished, on behalf of the one gone', async () => {
    const { gateway, pass } = setup();

    await pass(at(0));
    await pass(at(30));
    expect(gateway.endCallFromHttp).not.toHaveBeenCalled();

    await pass(at(60));
    expect(gateway.endCallFromHttp).toHaveBeenCalledTimes(1);
    expect(gateway.endCallFromHttp).toHaveBeenCalledWith('bob', 'conv-1', 'call-1');
  });

  it('a peer back in the room restarts the clock', async () => {
    const { gateway, probe, pass } = setup();

    await pass(at(0));
    probe.identities.mockResolvedValueOnce(['alice#d1', 'bob#d2']);
    await pass(at(30));
    await pass(at(50));
    await pass(at(100));
    expect(gateway.endCallFromHttp).not.toHaveBeenCalled();

    await pass(at(110));
    expect(gateway.endCallFromHttp).toHaveBeenCalledTimes(1);
  });

  it('leaves a call with both people in it alone', async () => {
    const { gateway, probe, pass } = setup();
    probe.identities.mockResolvedValue(['alice#d1', 'bob#d2']);

    await pass(at(0));
    await pass(at(120));

    expect(gateway.endCallFromHttp).not.toHaveBeenCalled();
  });

  it('bots in the room are not the peer', async () => {
    const { gateway, probe, pass } = setup();
    probe.identities.mockResolvedValue(['alice#d1', 'meeting-recorder', 'voice-translator']);

    await pass(at(0));
    await pass(at(60));

    expect(gateway.endCallFromHttp).toHaveBeenCalledWith('bob', 'conv-1', 'call-1');
  });

  it('an empty room is nobody stuck in a call — not guessed at', async () => {
    const { gateway, probe, pass } = setup();
    probe.identities.mockResolvedValue([]);

    await pass(at(0));
    await pass(at(120));

    expect(gateway.endCallFromHttp).not.toHaveBeenCalled();
  });

  it('a caller talking to the AI twin is not cut off', async () => {
    const { gateway, probe, pass } = setup();
    probe.identities.mockResolvedValue(['alice#d1', 'agent-AJ_x1']);

    await pass(at(0));
    await pass(at(120));

    expect(gateway.endCallFromHttp).not.toHaveBeenCalled();
  });

  it('LiveKit not answering means "don\'t know" — the call is left alone, the rest still checked', async () => {
    const { gateway, probe, pass } = setup([
      call({ roomName: 'call-down' }),
      call({ roomName: 'call-2', conversationId: 'conv-2' }),
    ]);
    probe.identities.mockImplementation(async (room: string) => {
      if (room === 'call-down') throw new Error('twirp error: unavailable');
      return ['alice#d1'];
    });

    await pass(at(0));
    await pass(at(60));

    expect(gateway.endCallFromHttp).toHaveBeenCalledTimes(1);
    expect(gateway.endCallFromHttp).toHaveBeenCalledWith('bob', 'conv-2', 'call-2');
  });

  it('a failing end of one call does not stop the pass', async () => {
    const { gateway, pass } = setup([
      call({ roomName: 'call-1' }),
      call({ roomName: 'call-2', conversationId: 'conv-2' }),
    ]);
    gateway.endCallFromHttp.mockRejectedValueOnce(new Error('db down'));

    await pass(at(0));
    await pass(at(60));

    expect(gateway.endCallFromHttp).toHaveBeenCalledTimes(2);
  });

  it('in a group call, ends once the last other person has gone', async () => {
    const { gateway, probe, pass } = setup([
      call({ participantIds: ['alice', 'bob', 'carol'] }),
    ]);
    probe.identities.mockResolvedValue(['alice#d1', 'carol#d3']);
    await pass(at(0));
    await pass(at(120));
    expect(gateway.endCallFromHttp).not.toHaveBeenCalled();

    probe.identities.mockResolvedValue(['carol#d3']);
    await pass(at(130));
    await pass(at(190));
    expect(gateway.endCallFromHttp).toHaveBeenCalledTimes(1);
    expect(gateway.endCallFromHttp).toHaveBeenCalledWith('alice', 'conv-1', 'call-1');
  });

  it('only one app node runs a pass at a time', async () => {
    const { reconciler, probe, store } = setup();
    store.set('call:reconcile:lock', 'other-node');

    await reconciler.runOnce(at(0));

    expect(probe.identities).not.toHaveBeenCalled();
  });

  it('looks only at recent answered calls that are still open', async () => {
    const { reconciler, prisma } = setup([]);

    await reconciler.runOnce(at(0));

    const where = (prisma.callLog.findMany.mock.calls[0] as any)[0].where;
    expect(where.answeredAt).toEqual({ not: null });
    expect(where.endedAt).toBeNull();
    expect(where.conversationId).toEqual({ not: null });
    expect(where.startedAt.gt.getTime()).toBe(at(0).getTime() - 12 * 3600 * 1000);
  });

  it('a pass that outlasts the interval does not overlap the next', async () => {
    const { reconciler, probe } = setup();
    let release!: () => void;
    probe.identities.mockImplementation(
      () => new Promise((r) => (release = () => r(['alice#d1']))),
    );

    const first = reconciler.tick();
    await new Promise((r) => setImmediate(r));
    await reconciler.tick();
    release();
    await first;

    expect(probe.identities).toHaveBeenCalledTimes(1);
  });
});
