import { ForbiddenException } from '@nestjs/common';
import { VoiceService } from './voice.service';

/**
 * True if `p` has not settled within `ms` of real (not fake/mocked) time.
 *
 * Used to prove a join method genuinely `await`s the chat-clear helper
 * rather than firing it and moving on (`void` instead of `await` would be a
 * silent regression — see the tests below). Counting microtask ticks
 * (`await Promise.resolve()` in a loop) does NOT work for this: token
 * minting goes through `AccessToken.toJwt()` (`livekit-server-sdk` →
 * `jose`'s HS256 signing), which resolves via real async crypto rather than
 * a plain microtask chain, so a fixed number of `Promise.resolve()` ticks
 * elapses before minting finishes *regardless* of whether the clear was
 * awaited — a fire-and-forget clear and a properly-awaited one both leave
 * `joinRoom`'s overall promise unsettled after a handful of ticks, which
 * would make the mutation this test exists to catch pass silently. A real
 * timer sidesteps that: it gives any pending crypto callback ample room to
 * fire, so "still pending after `ms`" means genuinely blocked, not merely
 * "hasn't gotten there yet".
 */
function stillPending(p: Promise<unknown>, ms = 100): Promise<boolean> {
  return Promise.race([
    p.then(() => false),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(true), ms)),
  ]);
}

// Regression cover for the 2026-07-27 audit finding: POST /voice/rooms/:name/join
// issued a LiveKit token to any authenticated caller who knew a room name, and
// added them to participantIds on the way in.
describe('VoiceService.joinRoom entitlement', () => {
  let service: VoiceService;
  let prisma: any;

  const OWNER = 'abcdef12-3456-7890-abcd-ef1234567890';

  beforeEach(() => {
    prisma = {
      callLog: { findUnique: jest.fn(), update: jest.fn() },
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'user-1',
          username: 'user1',
          profile: { firstName: 'A', lastName: 'B' },
        }),
      },
    };

    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      // Task 4b: joinRoom now calls clearChatIfNewMeeting before minting a
      // token, which calls this. A bare `{}` made every admitting test in
      // this block route through a real (refused) HTTP call to
      // localhost:7880 and then a swallowed TypeError — harmless (the
      // helper is best-effort) but noisy, and a latent hang if :7880 ever
      // blackholes instead of refusing. Stubbed for real below, same as
      // the describe block after this one.
      { clearFeed: jest.fn().mockResolvedValue(undefined) } as any,
    );
    // I2: the meeting-boundary check calls a dedicated short-timeout client
    // (`participantsCheckRooms`), not the shared `rooms` used by
    // sendData/recording uploads — see clearChatIfNewMeeting's docstring.
    (service as any).participantsCheckRooms = {
      listParticipants: jest.fn().mockResolvedValue([]),
    };
  });

  it('refuses a caller who was never invited', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      initiatorId: 'user-1',
      participantIds: ['user-1', 'user-2'],
    });

    await expect(service.joinRoom('call-1', 'intruder')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('does not write an uninvited caller into the call log', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      initiatorId: 'user-1',
      participantIds: ['user-1'],
    });

    await expect(service.joinRoom('call-1', 'intruder')).rejects.toThrow();
    // Self-legitimising was half the problem: an intruder must not end up
    // looking like a participant in call history.
    expect(prisma.callLog.update).not.toHaveBeenCalled();
  });

  it('refuses when no call log exists for the room', async () => {
    prisma.callLog.findUnique.mockResolvedValue(null);

    await expect(service.joinRoom('call-unknown', 'user-1')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('admits a user the invite flow already recorded', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      initiatorId: 'user-1',
      participantIds: ['user-1', 'invited-user'],
    });

    const res = await service.joinRoom('call-1', 'invited-user');
    expect(typeof res.token).toBe('string');
    expect(res.token.length).toBeGreaterThan(0);
  });

  it('admits the owner of a personal room without a call log', async () => {
    prisma.callLog.findUnique.mockResolvedValue(null);

    const res = await service.joinRoom(
      `personal-${OWNER.substring(0, 8)}-deadbeef`,
      OWNER,
    );
    expect(typeof res.token).toBe('string');
  });

  it("refuses a stranger at someone else's personal room", async () => {
    prisma.callLog.findUnique.mockResolvedValue(null);

    await expect(
      service.joinRoom('personal-abcdef12-deadbeef', 'stranger-uuid-here'),
    ).rejects.toThrow(ForbiddenException);
  });
});

// Task 4b: LiveKit webhooks (room_finished) aren't configured on any
// environment — DEV, TEST and DO-media configs all lack a `webhook`
// section — so there's no clean "this meeting just ended" signal to clear
// the room chat feed on exit. The boundary is caught on entry instead: all
// three join paths ask LiveKit who's already in the room before handing
// out a token. A room that doesn't exist yet resolves an empty participant
// list rather than rejecting — confirmed against a live LiveKit instance,
// not assumed — so an empty result (vacant room or not-yet-created room
// alike) means "this join starts a new meeting" and clears any chat left
// over from a previous one. A *rejected* call means the LiveKit API itself
// is unreachable, which says nothing about who's in the room — that does
// NOT clear, only logs a warning, so a transient LiveKit outage can't wipe
// a live meeting's chat. The reject-doesn't-clear and clearFeed-can-fail
// branches are only exercised via `joinRoom` below, not repeated for
// `joinPublicRoom`/`joinPublicRoomAuth` too: all three call the exact same
// private `clearChatIfNewMeeting`, so re-running its internal branches
// through every call site would just re-test the same lines: the
// per-path tests below stick to what actually differs by path — whether
// clearing happens at all, and with which room name.
describe('VoiceService — очистка ленты чата на входе в комнату', () => {
  let service: VoiceService;
  let prisma: any;
  let chatBuffer: { clearFeed: jest.Mock };
  let rooms: { createRoom: jest.Mock };
  let participantsCheckRooms: { listParticipants: jest.Mock };

  const OWNER = 'abcdef12-3456-7890-abcd-ef1234567890';
  const PERSONAL_ROOM = `personal-${OWNER.substring(0, 8)}-deadbeef`;

  beforeEach(() => {
    prisma = {
      callLog: { findUnique: jest.fn().mockResolvedValue(null) },
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: OWNER,
          username: 'owner',
          profile: { firstName: 'A', lastName: 'B' },
        }),
      },
      publicRoom: {
        findUnique: jest.fn().mockResolvedValue({
          code: 'code-1',
          roomName: 'pub-1',
          isActive: true,
          type: 'permanent',
          expiresAt: null,
          passwordHash: null,
        }),
        update: jest.fn(),
      },
    };
    chatBuffer = { clearFeed: jest.fn().mockResolvedValue(undefined) };
    rooms = { createRoom: jest.fn().mockResolvedValue(undefined) };
    participantsCheckRooms = {
      listParticipants: jest.fn().mockResolvedValue([]),
    };

    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      chatBuffer as any,
    );
    // Same override pattern as voice.service.chat.spec.ts: rooms/ruRooms are
    // constructed inline in the class, not injected, so tests replace them
    // post-construction. None of these room names carry the `call-ru-`
    // prefix, so sfuFor and participantsCheckClient both always resolve to
    // the non-RU instance. I2: clearChatIfNewMeeting's LiveKit call goes
    // through the dedicated short-timeout `participantsCheckRooms`, not the
    // shared `rooms` used by sendData/recording uploads — see its docstring.
    (service as any).rooms = rooms;
    (service as any).participantsCheckRooms = participantsCheckRooms;
  });

  it('joinRoom чистит ленту, когда LiveKit сообщает о пустой комнате', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);

    await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(chatBuffer.clearFeed).toHaveBeenCalledTimes(1);
    expect(chatBuffer.clearFeed).toHaveBeenCalledWith(PERSONAL_ROOM);
  });

  it('joinRoom не чистит ленту, когда в комнате уже есть участники', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([
      { identity: 'someone-else' },
    ]);

    await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('joinRoom всё равно выдаёт токен, если listParticipants упал, — но ленту НЕ чистит: авария API не значит пустую комнату', async () => {
    participantsCheckRooms.listParticipants.mockRejectedValue(
      new Error('livekit unavailable'),
    );

    const res = await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(typeof res.token).toBe('string');
    expect(res.token.length).toBeGreaterThan(0);
    // Живая проверка на LiveKit (2026-09-07) показала: несуществующая
    // комната отдаёт [] через listParticipants, а не бросает — то есть
    // единственный сценарий, ради которого раньше держали "отказ → чистим",
    // и без этого правила покрыт успешным пустым списком. Отказ теперь
    // значит только "сам API недоступен", и на этом трогать чужую ленту
    // работающей встречи нельзя.
    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('joinRoom входит и без чистки, даже если сам clearFeed падает', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);
    chatBuffer.clearFeed.mockRejectedValue(new Error('redis down'));

    const res = await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(typeof res.token).toBe('string');
    expect(res.token.length).toBeGreaterThan(0);
  });

  // Порядок операций — весь смысл этой задачи, не только сам факт вызова
  // clearFeed: если бы его не дожидались (await → случайно превратился в
  // fire-and-forget), joinRoom мог бы вернуть токен раньше, чем лента
  // реально очистится, — и участник, успевший подключиться и написать
  // первым, увидел бы своё же сообщение стёртым чуть позже, когда
  // отложенная очистка наконец доедет. Обычные `toHaveBeenCalledWith` тесты
  // выше этого не ловят вовсе: им всё равно, дождались клира или нет, лишь
  // бы он был вызван хоть когда-нибудь.
  it('joinRoom дожидается очистки ленты, прежде чем вернуть токен', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);
    let releaseClear!: () => void;
    chatBuffer.clearFeed.mockImplementation(
      () => new Promise<void>((resolve) => (releaseClear = resolve)),
    );

    const pending = service.joinRoom(PERSONAL_ROOM, OWNER);
    expect(await stillPending(pending)).toBe(true);

    releaseClear();
    await expect(pending).resolves.toMatchObject({
      token: expect.any(String),
    });
  });

  it('joinPublicRoom чистит ленту, когда комната пуста', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);

    await service.joinPublicRoom('code-1', 'Гость');

    expect(chatBuffer.clearFeed).toHaveBeenCalledWith('pub-1');
  });

  it('joinPublicRoom не чистит ленту, когда в комнате уже есть гости', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([
      { identity: 'guest-abc' },
    ]);

    await service.joinPublicRoom('code-1', 'Гость');

    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('joinPublicRoom дожидается очистки ленты, прежде чем вернуть токен', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);
    let releaseClear!: () => void;
    chatBuffer.clearFeed.mockImplementation(
      () => new Promise<void>((resolve) => (releaseClear = resolve)),
    );

    const pending = service.joinPublicRoom('code-1', 'Гость');
    expect(await stillPending(pending)).toBe(true);

    releaseClear();
    await expect(pending).resolves.toMatchObject({
      token: expect.any(String),
    });
  });

  it('joinPublicRoomAuth чистит ленту, когда комната пуста', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);

    await service.joinPublicRoomAuth('code-1', OWNER);

    expect(chatBuffer.clearFeed).toHaveBeenCalledWith('pub-1');
  });

  it('joinPublicRoomAuth не чистит ленту, когда в комнате уже есть участники', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([
      { identity: 'someone-else' },
    ]);

    await service.joinPublicRoomAuth('code-1', OWNER);

    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('joinPublicRoomAuth дожидается очистки ленты, прежде чем вернуть токен', async () => {
    participantsCheckRooms.listParticipants.mockResolvedValue([]);
    let releaseClear!: () => void;
    chatBuffer.clearFeed.mockImplementation(
      () => new Promise<void>((resolve) => (releaseClear = resolve)),
    );

    const pending = service.joinPublicRoomAuth('code-1', OWNER);
    expect(await stillPending(pending)).toBe(true);

    releaseClear();
    await expect(pending).resolves.toMatchObject({
      token: expect.any(String),
    });
  });

  it('createRoom не спрашивает LiveKit о старой ленте — имя всегда свежий uuid', async () => {
    await service.createRoom(OWNER);

    expect(participantsCheckRooms.listParticipants).not.toHaveBeenCalled();
    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });
});
