import { Logger } from '@nestjs/common';
import { InterpreterReconciler } from './interpreter.reconciler';

const NOW = new Date('2026-11-01T12:00:00Z');
const secondsAgo = (s: number) => new Date(NOW.getTime() - s * 1000);

const active = (over: Record<string, unknown> = {}) => ({
  id: 'sess-1',
  roomName: 'interp-room-1',
  billingSessionId: 'bill-1' as string | null,
  startedAt: secondsAgo(600) as Date | null,
  agentSeenAt: secondsAgo(10) as Date | null,
  ...over,
});

function setup(rows: { active?: unknown[]; waiting?: unknown[] } = {}) {
  const prisma = {
    interpreterSession: {
      findMany: jest.fn(async ({ where }: any) =>
        where.status === 'ACTIVE' ? (rows.active ?? []) : (rows.waiting ?? []),
      ),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    aiSession: {
      findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
    },
  };
  const livekit = { agentPresent: jest.fn().mockResolvedValue(true) };
  const interpreter = { close: jest.fn().mockResolvedValue(undefined) };
  const reconciler = new InterpreterReconciler(
    prisma as any,
    livekit as any,
    interpreter as any,
  );
  return { reconciler, prisma, livekit, interpreter };
}

beforeEach(() => {
  jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
});

afterEach(() => jest.restoreAllMocks());

describe('InterpreterReconciler: active sessions', () => {
  it.each([
    ['terminated_no_funds', 'NO_FUNDS'],
    ['terminated_stale', 'MAX_DURATION'],
    ['failed', 'TRANSLATION_FAILED'],
  ])(
    'ends a session whose billing metering closed as %s',
    async (billing, reason) => {
      const row = active();
      const { reconciler, prisma, livekit, interpreter } = setup({
        active: [row],
      });
      prisma.aiSession.findUnique.mockResolvedValue({ status: billing });

      await reconciler.runOnce(NOW);

      expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
        where: { id: 'bill-1' },
        select: { status: true },
      });
      expect(interpreter.close).toHaveBeenCalledWith(row, reason, {
        stopAgent: true,
      });
      expect(livekit.agentPresent).not.toHaveBeenCalled();
    },
  );

  it('notes when it last saw the agent in the room', async () => {
    const { reconciler, prisma, livekit, interpreter } = setup({
      active: [active()],
    });

    await reconciler.runOnce(NOW);

    expect(livekit.agentPresent).toHaveBeenCalledWith('interp-room-1');
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: { id: 'sess-1', status: 'ACTIVE' },
      data: { agentSeenAt: NOW },
    });
    expect(interpreter.close).not.toHaveBeenCalled();
  });

  it('ends a session the agent has been missing from for over 60 s', async () => {
    const lost = active({ agentSeenAt: secondsAgo(61) });
    const { reconciler, livekit, interpreter } = setup({ active: [lost] });
    livekit.agentPresent.mockResolvedValue(false);

    await reconciler.runOnce(NOW);

    expect(interpreter.close).toHaveBeenCalledWith(lost, 'AGENT_LOST', {
      stopAgent: true,
    });
  });

  it('gives the agent 60 s, counted from the join when it was never seen', async () => {
    const { reconciler, livekit, interpreter, prisma } = setup({
      active: [
        active({ agentSeenAt: secondsAgo(60) }),
        active({ id: 'sess-2', agentSeenAt: null, startedAt: secondsAgo(30) }),
      ],
    });
    livekit.agentPresent.mockResolvedValue(false);

    await reconciler.runOnce(NOW);

    expect(interpreter.close).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.updateMany).not.toHaveBeenCalled();
  });

  it('decides nothing when LiveKit does not answer', async () => {
    const { reconciler, livekit, interpreter, prisma } = setup({
      active: [active({ agentSeenAt: secondsAgo(3600) })],
    });
    livekit.agentPresent.mockResolvedValue(null);

    await reconciler.runOnce(NOW);

    expect(interpreter.close).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.updateMany).not.toHaveBeenCalled();
  });
});

describe('InterpreterReconciler: waiting sessions', () => {
  it('ends a waiting session whose code expired over 5 minutes ago', async () => {
    const stale = { id: 'sess-w', roomName: 'interp-w' };
    const { reconciler, prisma, interpreter } = setup({ waiting: [stale] });

    await reconciler.runOnce(NOW);

    expect(prisma.interpreterSession.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          status: 'WAITING',
          codeExpiresAt: { lt: new Date(NOW.getTime() - 5 * 60_000) },
        },
      }),
    );
    expect(interpreter.close).toHaveBeenCalledWith(stale, 'EXPIRED', {
      stopAgent: false,
    });
  });
});

describe('InterpreterReconciler: robustness', () => {
  it('goes on with the other sessions when one fails', async () => {
    const { reconciler, livekit, interpreter } = setup({
      active: [active(), active({ id: 'sess-2', roomName: 'interp-room-2' })],
      waiting: [{ id: 'sess-w', roomName: 'interp-w' }],
    });
    livekit.agentPresent
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(false);
    interpreter.close.mockRejectedValue(new Error('db down'));

    await expect(reconciler.runOnce(NOW)).resolves.toBeUndefined();
    expect(livekit.agentPresent).toHaveBeenCalledTimes(2);
    expect(interpreter.close).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'sess-w' }),
      'EXPIRED',
      { stopAgent: false },
    );
  });

  it('never throws, even when the sessions cannot be loaded', async () => {
    const { reconciler, prisma } = setup();
    prisma.interpreterSession.findMany.mockRejectedValue(new Error('db down'));

    await expect(reconciler.tick()).resolves.toBeUndefined();
  });

  it('skips a tick while the previous one is still running', async () => {
    const { reconciler, prisma } = setup();
    let release!: () => void;
    prisma.interpreterSession.findMany.mockReturnValueOnce(
      new Promise((resolve) => (release = () => resolve([]))),
    );

    const first = reconciler.tick();
    await reconciler.tick();
    expect(prisma.interpreterSession.findMany).toHaveBeenCalledTimes(1);

    release();
    await first;
    await reconciler.tick();
    expect(prisma.interpreterSession.findMany).toHaveBeenCalledTimes(4);
  });
});
