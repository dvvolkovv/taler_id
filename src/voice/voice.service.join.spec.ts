import { ForbiddenException } from '@nestjs/common';
import { VoiceService } from './voice.service';

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
      {} as any,
    );
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
// out a token, and treat "nobody" (including "room doesn't exist yet",
// which listParticipants reports by throwing) as "this join starts a new
// meeting" and clears any chat left over from a previous one.
describe('VoiceService — очистка ленты чата на входе в комнату', () => {
  let service: VoiceService;
  let prisma: any;
  let chatBuffer: { clearFeed: jest.Mock };
  let rooms: { listParticipants: jest.Mock; createRoom: jest.Mock };

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
    rooms = {
      listParticipants: jest.fn().mockResolvedValue([]),
      createRoom: jest.fn().mockResolvedValue(undefined),
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
    // prefix, so sfuFor always resolves to `rooms`.
    (service as any).rooms = rooms;
  });

  it('joinRoom чистит ленту, когда LiveKit сообщает о пустой комнате', async () => {
    rooms.listParticipants.mockResolvedValue([]);

    await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(chatBuffer.clearFeed).toHaveBeenCalledTimes(1);
    expect(chatBuffer.clearFeed).toHaveBeenCalledWith(PERSONAL_ROOM);
  });

  it('joinRoom не чистит ленту, когда в комнате уже есть участники', async () => {
    rooms.listParticipants.mockResolvedValue([{ identity: 'someone-else' }]);

    await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('joinRoom всё равно выдаёт токен, если listParticipants упал — и чистит ленту, трактуя это как новую встречу', async () => {
    rooms.listParticipants.mockRejectedValue(new Error('livekit unavailable'));

    const res = await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(typeof res.token).toBe('string');
    expect(res.token.length).toBeGreaterThan(0);
    expect(chatBuffer.clearFeed).toHaveBeenCalledWith(PERSONAL_ROOM);
  });

  it('joinRoom входит и без чистки, даже если сам clearFeed падает', async () => {
    rooms.listParticipants.mockResolvedValue([]);
    chatBuffer.clearFeed.mockRejectedValue(new Error('redis down'));

    const res = await service.joinRoom(PERSONAL_ROOM, OWNER);

    expect(typeof res.token).toBe('string');
  });

  it('joinPublicRoom чистит ленту, когда комната пуста', async () => {
    rooms.listParticipants.mockResolvedValue([]);

    await service.joinPublicRoom('code-1', 'Гость');

    expect(chatBuffer.clearFeed).toHaveBeenCalledWith('pub-1');
  });

  it('joinPublicRoom не чистит ленту, когда в комнате уже есть гости', async () => {
    rooms.listParticipants.mockResolvedValue([{ identity: 'guest-abc' }]);

    await service.joinPublicRoom('code-1', 'Гость');

    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('joinPublicRoomAuth чистит ленту, когда комната пуста', async () => {
    rooms.listParticipants.mockResolvedValue([]);

    await service.joinPublicRoomAuth('code-1', OWNER);

    expect(chatBuffer.clearFeed).toHaveBeenCalledWith('pub-1');
  });

  it('joinPublicRoomAuth не чистит ленту, когда в комнате уже есть участники', async () => {
    rooms.listParticipants.mockResolvedValue([{ identity: 'someone-else' }]);

    await service.joinPublicRoomAuth('code-1', OWNER);

    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });

  it('createRoom не спрашивает LiveKit о старой ленте — имя всегда свежий uuid', async () => {
    await service.createRoom(OWNER);

    expect(rooms.listParticipants).not.toHaveBeenCalled();
    expect(chatBuffer.clearFeed).not.toHaveBeenCalled();
  });
});
