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

/** Whether a row satisfies the reconciler's status filter: one alternative or an OR. */
function matches(row: any, where: any): boolean {
  return (where.OR ?? [where]).some(
    (alt: any) =>
      alt.status === row.status &&
      (!alt.endedAt || row.endedAt.getTime() > alt.endedAt.gt.getTime()),
  );
}

function setup(
  rows: {
    active?: unknown[];
    waiting?: unknown[];
    ended?: unknown[];
    openBilling?: { id: string }[];
  } = {},
) {
  const prisma = {
    interpreterSession: {
      findMany: jest.fn(async ({ where }: any) => {
        if (where.billingSessionId) {
          const rowsWithStatus = [
            ...((rows.active ?? []) as any[]).map((s) => ({
              status: 'ACTIVE',
              ...s,
            })),
            ...((rows.ended ?? []) as any[]),
          ];
          return rowsWithStatus.filter(
            (s) =>
              where.billingSessionId.in.includes(s.billingSessionId) &&
              matches(s, where),
          );
        }
        return where.status === 'ACTIVE'
          ? (rows.active ?? [])
          : (rows.waiting ?? []);
      }),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    aiSession: {
      findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
      findMany: jest.fn(async () => rows.openBilling ?? []),
    },
  };
  const livekit = { agentPresent: jest.fn().mockResolvedValue(true) };
  const interpreter = {
    close: jest.fn().mockResolvedValue(undefined),
    closeUnheldBilling: jest.fn().mockResolvedValue(undefined),
  };
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
    // Only forward: another node may have written a later sighting already.
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: {
        id: 'sess-1',
        status: 'ACTIVE',
        OR: [{ agentSeenAt: null }, { agentSeenAt: { lt: NOW } }],
      },
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

describe('InterpreterReconciler: billing no session holds', () => {
  it('closes open interpreter billing that no session holds', async () => {
    // bill-1 belongs to a live conversation; bill-2 was opened by a join that
    // died before claiming the code, or left open by a failed cleanup.
    const { reconciler, prisma, interpreter } = setup({
      active: [active()],
      openBilling: [{ id: 'bill-1' }, { id: 'bill-2' }],
    });

    await reconciler.runOnce(NOW);

    expect(prisma.aiSession.findMany).toHaveBeenCalledWith({
      where: {
        featureKey: 'interpreter',
        status: 'active',
        // A join that is still running gets a minute to link it.
        startedAt: { lt: new Date(NOW.getTime() - 60_000) },
      },
      select: { id: true },
    });
    expect(prisma.interpreterSession.findMany).toHaveBeenCalledWith({
      where: {
        billingSessionId: { in: ['bill-1', 'bill-2'] },
        OR: [
          { status: 'ACTIVE' },
          {
            status: 'ENDED',
            endedAt: { gt: new Date(NOW.getTime() - 60_000) },
          },
        ],
      },
      select: { billingSessionId: true },
    });
    expect(interpreter.closeUnheldBilling).toHaveBeenCalledTimes(1);
    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-2');
  });

  it('leaves billing of a session that ended moments ago to close()', async () => {
    // close() marks the row ENDED first and closes billing after stopping the
    // agent; closing it here would record a hang-up as 'failed'.
    const { reconciler, interpreter } = setup({
      ended: [
        { billingSessionId: 'bill-2', status: 'ENDED', endedAt: secondsAgo(5) },
      ],
      openBilling: [{ id: 'bill-2' }],
    });

    await reconciler.runOnce(NOW);

    expect(interpreter.closeUnheldBilling).not.toHaveBeenCalled();
  });

  it('closes billing a session left open after ending over a minute ago', async () => {
    // close() died, or its billing step failed, before the billing was closed.
    const { reconciler, interpreter } = setup({
      ended: [
        {
          billingSessionId: 'bill-2',
          status: 'ENDED',
          endedAt: secondsAgo(61),
        },
      ],
      openBilling: [{ id: 'bill-2' }],
    });

    await reconciler.runOnce(NOW);

    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-2');
  });

  it('does not look for sessions when no interpreter billing is open', async () => {
    const { reconciler, prisma, interpreter } = setup();

    await reconciler.runOnce(NOW);

    // The active and the waiting pass; no third lookup.
    expect(prisma.interpreterSession.findMany).toHaveBeenCalledTimes(2);
    expect(interpreter.closeUnheldBilling).not.toHaveBeenCalled();
  });

  it('goes on with the other billing sessions when one fails to close', async () => {
    const { reconciler, interpreter } = setup({
      openBilling: [{ id: 'bill-2' }, { id: 'bill-3' }],
    });
    interpreter.closeUnheldBilling.mockRejectedValueOnce(new Error('db down'));

    await expect(reconciler.runOnce(NOW)).resolves.toBeUndefined();
    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-3');
  });

  it('runs even when the session passes could not load', async () => {
    const { reconciler, prisma, interpreter } = setup({
      openBilling: [{ id: 'bill-2' }],
    });
    prisma.interpreterSession.findMany
      .mockRejectedValueOnce(new Error('db down'))
      .mockRejectedValueOnce(new Error('db down'));

    await reconciler.runOnce(NOW);

    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-2');
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
