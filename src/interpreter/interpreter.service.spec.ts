import { HttpException, Logger } from '@nestjs/common';
import { FeatureDisabledException } from '../billing/exceptions/feature-disabled.exception';
import { InsufficientFundsException } from '../billing/exceptions/insufficient-funds.exception';
import { AgentCallError } from './interpreter-agent.client';
import { hashCode } from './interpreter-code';
import { InterpreterService } from './interpreter.service';

const NOW = new Date('2026-11-01T12:00:00Z');
const HOST = 'host-1';
const GUEST = 'guest-1';
const STRANGER = 'stranger-1';
const hostUser = { sub: HOST, session_id: 'login-host' };
const guestUser = { sub: GUEST, session_id: 'login-guest' };
const CODE = 'ABCDEFGH';
const PRINT_A = Array<number>(192).fill(0.1);
const PRINT_B = Array.from({ length: 192 }, (_, i) => (i % 2 ? 0.1 : -0.1));

const waitingRow = (over: Record<string, unknown> = {}) => ({
  id: 'sess-1',
  roomName: 'interp-room-1',
  hostId: HOST,
  guestId: null as string | null,
  hostLang: 'ru',
  guestLang: null as string | null,
  codeHash: hashCode(CODE) as string | null,
  codeExpiresAt: new Date(NOW.getTime() + 60_000) as Date | null,
  status: 'WAITING',
  billingSessionId: null as string | null,
  agentSeenAt: null as Date | null,
  startedAt: null as Date | null,
  endedAt: null as Date | null,
  endReason: null as string | null,
  ...over,
});

const activeRow = (over: Record<string, unknown> = {}) =>
  waitingRow({
    guestId: GUEST,
    guestLang: 'de',
    codeHash: null,
    codeExpiresAt: null,
    status: 'ACTIVE',
    billingSessionId: 'bill-1',
    startedAt: NOW,
    agentSeenAt: NOW,
    ...over,
  });

type Row = ReturnType<typeof waitingRow>;

/** Matches the where clauses the service uses: equality, { not }, OR. */
const matches = (
  row: Record<string, unknown>,
  where: Record<string, any>,
): boolean =>
  Object.entries(where).every(([key, want]) =>
    key === 'OR'
      ? (want as Record<string, any>[]).some((w) => matches(row, w))
      : want !== null && typeof want === 'object' && 'not' in want
        ? row[key] !== want.not
        : row[key] === want,
  );

function setup() {
  const rows: Row[] = [];
  const profiles: Record<string, any> = {
    [HOST]: {
      firstName: 'Anna',
      avatarUrl: 'https://cdn.test/anna.png',
      ownerEmbedding: PRINT_A,
    },
    [GUEST]: { firstName: 'Boris', avatarUrl: null, ownerEmbedding: PRINT_B },
  };
  // jest.fn over a tiny in-memory table: conditional updates behave as in the DB.
  const prisma = {
    interpreterSession: {
      findUnique: jest.fn(
        async ({ where }: any) => rows.find((r) => matches(r, where)) ?? null,
      ),
      findFirst: jest.fn(
        async ({ where }: any) => rows.find((r) => matches(r, where)) ?? null,
      ),
      findMany: jest.fn(async ({ where }: any) =>
        rows.filter((r) => matches(r, where)),
      ),
      create: jest.fn(async ({ data }: any) => {
        const row = waitingRow({ id: 'sess-new', ...data });
        rows.push(row);
        return { id: row.id };
      }),
      updateMany: jest.fn(async ({ where, data }: any) => {
        const hit = rows.filter((r) => matches(r, where));
        for (const r of hit) Object.assign(r, data);
        return { count: hit.length };
      }),
    },
    profile: {
      findUnique: jest.fn(async ({ where }: any) => profiles[where.userId]),
    },
    aiSession: {
      findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
    },
  };
  const gating = {
    assertCanStart: jest.fn().mockResolvedValue(undefined),
    startSession: jest.fn().mockResolvedValue({ id: 'bill-1' }),
    endSession: jest.fn().mockResolvedValue(undefined),
  };
  const redis = {
    incr: jest.fn().mockResolvedValue(1),
    expire: jest.fn().mockResolvedValue(undefined),
  };
  const agent = {
    start: jest.fn().mockResolvedValue(undefined),
    stop: jest.fn().mockResolvedValue(undefined),
    selftest: jest.fn(),
  };
  const livekit = {
    wsUrl: 'wss://lk.test',
    createRoom: jest.fn().mockResolvedValue(undefined),
    issueToken: jest.fn(async ({ userId }: any) => `lk-token:${userId}`),
    deleteRoom: jest.fn().mockResolvedValue(undefined),
  };
  const service = new InterpreterService(
    prisma as any,
    gating as any,
    redis as any,
    agent as any,
    livekit as any,
  );
  return { service, rows, profiles, prisma, gating, redis, agent, livekit };
}

/** [status, code] of the HttpException a call rejects with. */
async function failure(call: Promise<unknown>): Promise<[number, string]> {
  const e = await call.then(
    () => {
      throw new Error('expected the call to fail');
    },
    (err: unknown) => err,
  );
  if (!(e instanceof HttpException)) throw e;
  return [e.getStatus(), (e.getResponse() as { message: string }).message];
}

const savedFlag = process.env.INTERPRETER_ENABLED;

beforeEach(() => {
  jest.useFakeTimers({ now: NOW });
  process.env.INTERPRETER_ENABLED = 'true';
  for (const level of ['log', 'warn', 'error'] as const) {
    jest.spyOn(Logger.prototype, level).mockImplementation(() => undefined);
  }
});

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

afterAll(() => {
  if (savedFlag === undefined) delete process.env.INTERPRETER_ENABLED;
  else process.env.INTERPRETER_ENABLED = savedFlag;
});

describe('languages', () => {
  it('lists the languages and tells whether the feature is on', () => {
    const { service } = setup();
    expect(service.languages().enabled).toBe(true);
    expect(service.languages().languages).toHaveLength(81);
    expect(service.languages().languages[0]).toEqual({
      code: 'af',
      name: 'Afrikaans',
    });

    for (const value of ['false', 'TRUE', '1', '']) {
      process.env.INTERPRETER_ENABLED = value;
      expect(service.languages().enabled).toBe(false);
    }
  });
});

describe('create', () => {
  it('checks in order: switch, language, voice print, conversation, funds', async () => {
    const { service, rows, profiles, gating, livekit, prisma } = setup();
    profiles[HOST].ownerEmbedding = [];
    rows.push(activeRow({ id: 'other', hostId: 'someone', guestId: HOST }));
    gating.assertCanStart.mockRejectedValue(
      new InsufficientFundsException('interpreter', 24_000_000n, 0n),
    );

    process.env.INTERPRETER_ENABLED = 'false';
    expect(await failure(service.create(hostUser, 'xx'))).toEqual([
      403,
      'interpreter_disabled',
    ]);
    process.env.INTERPRETER_ENABLED = 'true';
    expect(await failure(service.create(hostUser, 'xx'))).toEqual([
      400,
      'unsupported_language',
    ]);
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      409,
      'voice_print_required',
    ]);
    profiles[HOST].ownerEmbedding = PRINT_A;
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      409,
      'already_in_session',
    ]);
    rows.length = 0;
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      402,
      'insufficient_funds',
    ]);
    gating.assertCanStart.mockRejectedValue(
      new FeatureDisabledException('interpreter'),
    );
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      403,
      'feature_disabled',
    ]);

    expect(gating.assertCanStart).toHaveBeenCalledWith(HOST, 'interpreter');
    expect(livekit.createRoom).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.create).not.toHaveBeenCalled();
  });

  it('opens a waiting session with a hashed code, without billing yet', async () => {
    const { service, prisma, gating, livekit } = setup();

    const created = await service.create(hostUser, 'ru');

    expect(created.code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(created.roomName).toMatch(/^interp-[0-9a-f-]{36}$/);
    expect(livekit.createRoom).toHaveBeenCalledWith(created.roomName);
    expect(prisma.interpreterSession.create).toHaveBeenCalledWith({
      data: {
        roomName: created.roomName,
        hostId: HOST,
        hostLang: 'ru',
        codeHash: hashCode(created.code),
        codeExpiresAt: new Date(NOW.getTime() + 5 * 60_000),
      },
      select: { id: true },
    });
    expect(livekit.issueToken).toHaveBeenCalledWith({
      roomName: created.roomName,
      userId: HOST,
      loginSessionId: 'login-host',
      lang: 'ru',
      name: 'Anna',
    });
    expect(created).toEqual({
      sessionId: 'sess-new',
      code: created.code,
      expiresAt: new Date(NOW.getTime() + 5 * 60_000),
      roomName: created.roomName,
      token: 'lk-token:host-1',
      livekitWsUrl: 'wss://lk.test',
    });
    expect(gating.startSession).not.toHaveBeenCalled();
  });

  it("replaces the host's own waiting session: its QR stops working", async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(waitingRow({ id: 'old', roomName: 'interp-old' }));

    await service.create(hostUser, 'ru');

    expect(rows[0]).toMatchObject({
      status: 'ENDED',
      endReason: 'HANGUP',
      codeHash: null,
      endedAt: NOW,
    });
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-old');
    expect(agent.stop).not.toHaveBeenCalled();
    expect(gating.endSession).not.toHaveBeenCalled();
  });

  it('answers 503 when LiveKit cannot create the room', async () => {
    const { service, livekit, prisma } = setup();
    livekit.createRoom.mockRejectedValue(new Error('twirp error'));

    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      503,
      'interpreter_unavailable',
    ]);
    expect(prisma.interpreterSession.create).not.toHaveBeenCalled();
  });
});

describe('newCode', () => {
  it('gives the host a new code and retires the old one', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    const fresh = await service.newCode(HOST, 'sess-1');

    expect(fresh.code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(fresh.expiresAt).toEqual(new Date(NOW.getTime() + 5 * 60_000));
    expect(rows[0].codeHash).toBe(hashCode(fresh.code));
    expect(rows[0].codeHash).not.toBe(hashCode(CODE));
  });

  it('is for the host of a session that is still waiting', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());
    expect(await failure(service.newCode(GUEST, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
    expect(await failure(service.newCode(HOST, 'sess-x'))).toEqual([
      404,
      'session_not_found',
    ]);

    rows[0] = activeRow();
    expect(await failure(service.newCode(HOST, 'sess-1'))).toEqual([
      409,
      'not_waiting',
    ]);
  });

  it('does not re-arm a session a guest joined meanwhile', async () => {
    const { service, rows, prisma } = setup();
    rows.push(waitingRow());
    prisma.interpreterSession.updateMany.mockResolvedValueOnce({ count: 0 });

    expect(await failure(service.newCode(HOST, 'sess-1'))).toEqual([
      409,
      'not_waiting',
    ]);
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: { id: 'sess-1', status: 'WAITING' },
      data: { codeHash: expect.any(String), codeExpiresAt: expect.any(Date) },
    });
  });

  it('is off with the switch', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());
    process.env.INTERPRETER_ENABLED = 'false';
    expect(await failure(service.newCode(HOST, 'sess-1'))).toEqual([
      403,
      'interpreter_disabled',
    ]);
  });
});

describe('join', () => {
  it('checks in order before anything is opened', async () => {
    const { service, rows, profiles, redis, prisma, gating } = setup();
    rows.push(waitingRow({ codeExpiresAt: new Date(NOW.getTime() - 1) }));
    rows.push(activeRow({ id: 'other', hostId: GUEST, guestId: 'someone' }));
    profiles[GUEST].ownerEmbedding = [];
    profiles[HOST].ownerEmbedding = [];
    redis.incr.mockResolvedValue(11);

    process.env.INTERPRETER_ENABLED = 'false';
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      403,
      'interpreter_disabled',
    ]);
    expect(redis.incr).not.toHaveBeenCalled();
    process.env.INTERPRETER_ENABLED = 'true';
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      429,
      'too_many_attempts',
    ]);
    redis.incr.mockResolvedValue(2);
    expect(await failure(service.join(guestUser, 'nope', 'xx'))).toEqual([
      404,
      'code_not_found',
    ]);
    expect(await failure(service.join(guestUser, 'ZZZZZZZZ', 'xx'))).toEqual([
      404,
      'code_not_found',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      410,
      'code_expired',
    ]);
    rows[0].codeExpiresAt = new Date(NOW.getTime() + 60_000);
    expect(await failure(service.join(hostUser, CODE, 'xx'))).toEqual([
      409,
      'own_code',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      400,
      'unsupported_language',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'ru'))).toEqual([
      400,
      'same_language',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'voice_print_required',
    ]);
    profiles[GUEST].ownerEmbedding = PRINT_B;
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'already_in_session',
    ]);
    rows.pop();
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'host_voice_print_required',
    ]);
    profiles[HOST].ownerEmbedding = PRINT_B;
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'same_voice_print',
    ]);

    expect(gating.startSession).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.updateMany).not.toHaveBeenCalled();
  });

  describe('two prints the voice gate could not tell apart', () => {
    /** A unit print at cosine c from tilted(1). */
    const tilted = (c: number) => {
      const print = Array<number>(192).fill(0);
      print[0] = c;
      print[1] = Math.sqrt(1 - c * c);
      return print;
    };

    it.each([
      ['the same print', PRINT_A, PRINT_A],
      ['a rescaled copy', PRINT_A, PRINT_A.map((v) => v * 3)],
      ['prints at cosine 0.995', tilted(1), tilted(0.995)],
    ])('refuses %s before billing opens', async (_, hostPrint, guestPrint) => {
      const { service, rows, profiles, gating, agent } = setup();
      rows.push(waitingRow());
      profiles[HOST].ownerEmbedding = hostPrint;
      profiles[GUEST].ownerEmbedding = guestPrint;

      expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
        409,
        'same_voice_print',
      ]);
      expect(gating.startSession).not.toHaveBeenCalled();
      expect(agent.start).not.toHaveBeenCalled();
      expect(rows[0]).toMatchObject({
        status: 'WAITING',
        codeHash: hashCode(CODE),
      });
    });

    it.each([
      ['two different people', PRINT_A, PRINT_B],
      ['prints at cosine 0.985', tilted(1), tilted(0.985)],
    ])('lets %s through', async (_, hostPrint, guestPrint) => {
      const { service, rows, profiles, gating } = setup();
      rows.push(waitingRow());
      profiles[HOST].ownerEmbedding = hostPrint;
      profiles[GUEST].ownerEmbedding = guestPrint;

      await expect(service.join(guestUser, CODE, 'de')).resolves.toEqual(
        expect.objectContaining({ sessionId: 'sess-1' }),
      );
      expect(gating.startSession).toHaveBeenCalled();
    });
  });

  it('does not find a code whose session is no longer waiting', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ codeHash: hashCode(CODE) }));

    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      404,
      'code_not_found',
    ]);
  });

  it('counts attempts per person in a one-minute window', async () => {
    const { service, redis } = setup();

    await failure(service.join(guestUser, 'nope', 'de'));
    expect(redis.incr).toHaveBeenCalledWith('interp:join:guest-1');
    expect(redis.expire).toHaveBeenCalledWith('interp:join:guest-1', 60);

    redis.incr.mockResolvedValue(2);
    await failure(service.join(guestUser, 'nope', 'de'));
    expect(redis.expire).toHaveBeenCalledTimes(1);
  });

  it('accepts the code as a person types it', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    await expect(service.join(guestUser, 'abcd-efgh', 'de')).resolves.toEqual(
      expect.objectContaining({ sessionId: 'sess-1' }),
    );
  });

  it('opens billing, claims the code, then starts the agent', async () => {
    const { service, rows, gating, prisma, agent, livekit } = setup();
    rows.push(waitingRow());

    const joined = await service.join(guestUser, CODE, 'de');

    expect(gating.startSession).toHaveBeenCalledWith(
      HOST,
      'interpreter',
      'sess-1',
    );
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: { id: 'sess-1', status: 'WAITING', codeHash: hashCode(CODE) },
      data: {
        guestId: GUEST,
        guestLang: 'de',
        billingSessionId: 'bill-1',
        status: 'ACTIVE',
        startedAt: NOW,
        agentSeenAt: NOW,
        codeHash: null,
        codeExpiresAt: null,
      },
    });
    expect(agent.start).toHaveBeenCalledWith({
      sessionId: 'sess-1',
      roomName: 'interp-room-1',
      participants: [
        { userId: HOST, lang: 'ru', embedding: PRINT_A },
        { userId: GUEST, lang: 'de', embedding: PRINT_B },
      ],
    });
    const order = [
      gating.startSession,
      prisma.interpreterSession.updateMany,
      agent.start,
    ].map((fn) => fn.mock.invocationCallOrder[0]);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(livekit.issueToken).toHaveBeenCalledWith({
      roomName: 'interp-room-1',
      userId: GUEST,
      loginSessionId: 'login-guest',
      lang: 'de',
      name: 'Boris',
    });
    expect(joined).toEqual({
      sessionId: 'sess-1',
      roomName: 'interp-room-1',
      token: 'lk-token:guest-1',
      livekitWsUrl: 'wss://lk.test',
      partner: {
        firstName: 'Anna',
        avatarUrl: 'https://cdn.test/anna.png',
        lang: 'ru',
      },
      directions: { toMe: 'simultaneous', fromMe: 'simultaneous' },
    });
  });

  it('reports each direction from the guest side', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    // Slovak is not a language the translate model speaks, but one it hears.
    const joined = await service.join(guestUser, CODE, 'sk');

    expect(joined.directions).toEqual({
      toMe: 'phrase',
      fromMe: 'simultaneous',
    });
  });

  it("ends the guest's own waiting session", async () => {
    const { service, rows, livekit } = setup();
    rows.push(waitingRow());
    rows.push(
      waitingRow({
        id: 'guest-own',
        roomName: 'interp-guest-own',
        hostId: GUEST,
        codeHash: hashCode('ZZZZZZZZ'),
      }),
    );

    await service.join(guestUser, CODE, 'de');

    expect(rows[1]).toMatchObject({ status: 'ENDED', endReason: 'HANGUP' });
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-guest-own');
  });

  it("maps the host's billing refusal and leaves the code valid", async () => {
    const { service, rows, gating, agent } = setup();
    rows.push(waitingRow());

    gating.startSession.mockRejectedValueOnce(
      new InsufficientFundsException('interpreter', 24_000_000n, 0n),
    );
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      402,
      'host_insufficient_funds',
    ]);
    gating.startSession.mockRejectedValueOnce(
      new FeatureDisabledException('interpreter'),
    );
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      403,
      'host_feature_disabled',
    ]);

    expect(rows[0]).toMatchObject({
      status: 'WAITING',
      codeHash: hashCode(CODE),
    });
    expect(agent.start).not.toHaveBeenCalled();
  });

  it('closes the billing again when another guest claimed the code first', async () => {
    const { service, rows, prisma, gating, agent } = setup();
    rows.push(waitingRow());
    prisma.interpreterSession.updateMany.mockResolvedValueOnce({ count: 0 });

    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'code_used',
    ]);
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'failed');
    expect(agent.start).not.toHaveBeenCalled();
  });

  it('closes the billing again when the claim itself fails', async () => {
    const { service, rows, prisma, gating } = setup();
    rows.push(waitingRow());
    prisma.interpreterSession.updateMany.mockRejectedValueOnce(
      new Error('db down'),
    );

    await expect(service.join(guestUser, CODE, 'de')).rejects.toThrow(
      'db down',
    );
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'failed');
  });

  it('ends the session as translation_failed when the agent does not start', async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(waitingRow());
    agent.start.mockRejectedValue(new AgentCallError(503, 'agent refused'));

    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      503,
      'interpreter_unavailable',
    ]);
    expect(rows[0]).toMatchObject({
      status: 'ENDED',
      endReason: 'TRANSLATION_FAILED',
    });
    expect(agent.stop).toHaveBeenCalledWith('interp-room-1');
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'failed');
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');
  });
});

describe('get', () => {
  it('shows a waiting session without partner or directions', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    await expect(service.get(HOST, 'sess-1')).resolves.toEqual({
      status: 'waiting',
      endReason: null,
      partner: null,
      directions: null,
      startedAt: null,
    });
  });

  it('shows each side the other one', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ guestLang: 'sk' }));

    await expect(service.get(HOST, 'sess-1')).resolves.toEqual({
      status: 'active',
      endReason: null,
      partner: { firstName: 'Boris', avatarUrl: null, lang: 'sk' },
      directions: { toMe: 'simultaneous', fromMe: 'phrase' },
      startedAt: NOW,
    });
    await expect(service.get(GUEST, 'sess-1')).resolves.toEqual(
      expect.objectContaining({
        partner: {
          firstName: 'Anna',
          avatarUrl: 'https://cdn.test/anna.png',
          lang: 'ru',
        },
        directions: { toMe: 'phrase', fromMe: 'simultaneous' },
      }),
    );
  });

  it('tells why a session ended', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ status: 'ENDED', endReason: 'TRANSLATION_FAILED' }));

    await expect(service.get(GUEST, 'sess-1')).resolves.toEqual(
      expect.objectContaining({
        status: 'ended',
        endReason: 'translation_failed',
      }),
    );
  });

  it('is only for the two participants', async () => {
    const { service, rows } = setup();
    rows.push(activeRow());

    expect(await failure(service.get(STRANGER, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
    expect(await failure(service.get(HOST, 'sess-x'))).toEqual([
      404,
      'session_not_found',
    ]);
  });

  it('still answers a participant with the switch off, so the app learns why it ended', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ status: 'ENDED', endReason: 'AGENT_LOST' }));
    process.env.INTERPRETER_ENABLED = 'false';

    await expect(service.get(HOST, 'sess-1')).resolves.toEqual(
      expect.objectContaining({ status: 'ended', endReason: 'agent_lost' }),
    );
    expect(await failure(service.get(STRANGER, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
  });
});

describe('end', () => {
  it('lets either participant hang up, once', async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(activeRow());

    await expect(service.end(GUEST, 'sess-1')).resolves.toEqual({
      status: 'ended',
    });
    expect(rows[0]).toMatchObject({ status: 'ENDED', endReason: 'HANGUP' });
    expect(agent.stop).toHaveBeenCalledWith('interp-room-1');
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');

    await expect(service.end(HOST, 'sess-1')).resolves.toEqual({
      status: 'ended',
    });
    expect(agent.stop).toHaveBeenCalledTimes(1);
    expect(gating.endSession).toHaveBeenCalledTimes(1);
  });

  it('is only for the two participants', async () => {
    const { service, rows } = setup();
    rows.push(activeRow());

    expect(await failure(service.end(STRANGER, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
    expect(rows[0].status).toBe('ACTIVE');
  });

  it('still works with the switch off, so billing stops at once', async () => {
    const { service, rows, gating } = setup();
    rows.push(activeRow());
    process.env.INTERPRETER_ENABLED = 'false';

    await service.end(HOST, 'sess-1');

    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
  });
});

describe('agentEnded', () => {
  it.each([
    ['partner_left', 'PARTNER_LEFT', 'completed'],
    ['agent_lost', 'AGENT_LOST', 'failed'],
    ['translation_failed', 'TRANSLATION_FAILED', 'failed'],
  ] as const)(
    'ends the session as %s without stopping the agent that reported it',
    async (reason, endReason, billing) => {
      const { service, rows, agent, gating, livekit } = setup();
      rows.push(activeRow());

      await expect(service.agentEnded('sess-1', reason)).resolves.toEqual({
        ok: true,
      });
      expect(rows[0]).toMatchObject({ status: 'ENDED', endReason });
      expect(agent.stop).not.toHaveBeenCalled();
      expect(gating.endSession).toHaveBeenCalledWith('bill-1', billing);
      expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');
    },
  );

  it('answers ok for an unknown or already ended session, changing nothing', async () => {
    const { service, rows, gating, livekit } = setup();
    rows.push(activeRow({ status: 'ENDED', endReason: 'HANGUP' }));

    await expect(service.agentEnded('sess-x', 'agent_lost')).resolves.toEqual({
      ok: true,
    });
    await expect(service.agentEnded('sess-1', 'agent_lost')).resolves.toEqual({
      ok: true,
    });
    expect(rows[0].endReason).toBe('HANGUP');
    expect(gating.endSession).not.toHaveBeenCalled();
    expect(livekit.deleteRoom).not.toHaveBeenCalled();
  });
});

describe('close', () => {
  it('leaves billing alone when metering already ended it', async () => {
    const { service, rows, gating, prisma } = setup();
    rows.push(activeRow(), activeRow({ id: 'sess-2', roomName: 'r-2' }));

    await service.close(rows[0], 'NO_FUNDS', { stopAgent: true });
    await service.close(rows[1], 'MAX_DURATION', { stopAgent: true });

    expect(prisma.aiSession.findUnique).not.toHaveBeenCalled();
    expect(gating.endSession).not.toHaveBeenCalled();
  });

  it('does not overwrite a billing session that is no longer active', async () => {
    const { service, rows, gating, prisma } = setup();
    rows.push(activeRow());
    prisma.aiSession.findUnique.mockResolvedValue({
      status: 'terminated_no_funds',
    });

    await service.close(rows[0], 'HANGUP', { stopAgent: true });

    expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
      where: { id: 'bill-1' },
      select: { status: true },
    });
    expect(gating.endSession).not.toHaveBeenCalled();
  });

  it('runs every cleanup step even when the ones before it fail', async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(activeRow());
    agent.stop.mockRejectedValue(new Error('agent down'));
    gating.endSession.mockRejectedValue(new Error('db hiccup'));
    livekit.deleteRoom.mockRejectedValue(new Error('sfu down'));

    await expect(
      service.close(rows[0], 'HANGUP', { stopAgent: true }),
    ).resolves.toBeUndefined();
    expect(gating.endSession).toHaveBeenCalled();
    expect(livekit.deleteRoom).toHaveBeenCalled();
  });

  it('cleans up after the row as it ended, not the caller copy', async () => {
    // The caller read the session while it was waiting; a guest joined
    // before the close landed, and that join opened billing.
    const { service, rows, agent, gating } = setup();
    rows.push(activeRow());
    const staleCopy = waitingRow();

    await service.close(staleCopy, 'HANGUP', { stopAgent: true });

    expect(agent.stop).toHaveBeenCalledWith('interp-room-1');
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
  });

  it("falls back to the caller's copy when the row cannot be re-read", async () => {
    const { service, rows, prisma, gating } = setup();
    rows.push(activeRow());
    prisma.interpreterSession.findUnique.mockRejectedValueOnce(
      new Error('db hiccup'),
    );

    await service.close(activeRow(), 'HANGUP', { stopAgent: true });

    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
  });

  it('never stops an agent for a session that was never active', async () => {
    const { service, rows, agent, livekit } = setup();
    rows.push(waitingRow());

    await service.close(rows[0], 'EXPIRED', { stopAgent: true });

    expect(agent.stop).not.toHaveBeenCalled();
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');
  });
});

describe('closeUnheldBilling', () => {
  it('ends billing the reconciler found with no session holding it', async () => {
    const { service, gating, prisma } = setup();

    await service.closeUnheldBilling('bill-9');

    expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
      where: { id: 'bill-9' },
      select: { status: true },
    });
    expect(gating.endSession).toHaveBeenCalledWith('bill-9', 'failed');
  });

  it('leaves it alone when metering or another node ended it first', async () => {
    const { service, gating, prisma } = setup();
    prisma.aiSession.findUnique.mockResolvedValue({ status: 'failed' });

    await service.closeUnheldBilling('bill-9');

    expect(gating.endSession).not.toHaveBeenCalled();
  });
});

describe('selftest', () => {
  it("passes the agent's answer through", async () => {
    const { service, agent } = setup();
    agent.selftest.mockResolvedValue({ status: 200, body: { ok: true } });

    await expect(service.selftest()).resolves.toEqual({
      status: 200,
      body: { ok: true },
    });
  });

  it('still reaches the agent with the switch off, for the post-deploy smoke', async () => {
    const { service, agent } = setup();
    agent.selftest.mockResolvedValue({ status: 200, body: { ok: true } });
    process.env.INTERPRETER_ENABLED = 'false';

    await expect(service.selftest()).resolves.toEqual({
      status: 200,
      body: { ok: true },
    });
    expect(agent.selftest).toHaveBeenCalledTimes(1);
  });
});
