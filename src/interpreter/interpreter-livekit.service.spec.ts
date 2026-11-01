import { Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { RoomServiceClient } from 'livekit-server-sdk';
import { LK_API_SECRET } from '../common/livekit-credentials';
import { makeParticipantIdentity } from '../common/participant-identity';
import { InterpreterLivekitService } from './interpreter-livekit.service';

jest.mock('livekit-server-sdk', () => ({
  ...jest.requireActual('livekit-server-sdk'),
  RoomServiceClient: jest.fn(),
}));

describe('InterpreterLivekitService', () => {
  const savedWsUrl = process.env.LIVEKIT_WS_URL;
  let svc: InterpreterLivekitService;
  let rooms: { createRoom: jest.Mock; deleteRoom: jest.Mock };
  let presence: { listParticipants: jest.Mock };

  beforeEach(() => {
    jest.mocked(RoomServiceClient).mockClear();
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    svc = new InterpreterLivekitService();
    rooms = {
      createRoom: jest.fn().mockResolvedValue({}),
      deleteRoom: jest.fn().mockResolvedValue(undefined),
    };
    presence = { listParticipants: jest.fn() };
    svc.rooms = rooms as unknown as RoomServiceClient;
    svc.presence = presence as unknown as RoomServiceClient;
  });

  afterEach(() => {
    jest.restoreAllMocks();
    if (savedWsUrl === undefined) delete process.env.LIVEKIT_WS_URL;
    else process.env.LIVEKIT_WS_URL = savedWsUrl;
  });

  it('polls presence on its own client with a 2-second timeout', () => {
    const calls = jest.mocked(RoomServiceClient).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls.filter((args) => args[3]?.requestTimeout === 2)).toHaveLength(
      1,
    );
  });

  it('creates a room for two people, the agent and a reconnect', async () => {
    await svc.createRoom('interp-1');

    expect(rooms.createRoom).toHaveBeenCalledWith({
      name: 'interp-1',
      emptyTimeout: 300,
      departureTimeout: 60,
      maxParticipants: 4,
    });
  });

  it('issues a token that publishes only a microphone and carries the language', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await svc.issueToken({
      roomName: 'interp-1',
      userId: 'user-1',
      loginSessionId: 'login-1',
      lang: 'de',
      name: 'Anna',
    });
    const after = Math.floor(Date.now() / 1000);

    const claims = jwt.verify(token, LK_API_SECRET, {
      algorithms: ['HS256'],
    }) as jwt.JwtPayload;
    // A person plus a device, as in calls: two phones of one account do not kick each other.
    expect(claims.sub).toBe(makeParticipantIdentity('user-1', 'login-1'));
    expect(claims.sub).toMatch(/^user-1#[0-9a-f]{8}$/);
    expect(claims.name).toBe('Anna');
    expect(JSON.parse(claims.metadata as string)).toEqual({ lang: 'de' });
    expect(claims.video).toEqual({
      roomJoin: true,
      room: 'interp-1',
      canPublish: true,
      canPublishSources: ['microphone'],
      canSubscribe: true,
      canPublishData: false,
    });
    expect(claims.exp).toBeGreaterThanOrEqual(before + 4 * 3600);
    expect(claims.exp).toBeLessThanOrEqual(after + 4 * 3600);
  });

  it('sees the agent among the participants', async () => {
    presence.listParticipants.mockResolvedValue([
      { identity: 'user-1#abcd1234' },
      { identity: 'voice-interpreter' },
    ]);

    await expect(svc.agentPresent('interp-1')).resolves.toBe(true);
    expect(presence.listParticipants).toHaveBeenCalledWith('interp-1');
  });

  it('reports the agent absent from a room without it, or without anyone', async () => {
    presence.listParticipants.mockResolvedValueOnce([
      { identity: 'user-1#abcd1234' },
    ]);
    await expect(svc.agentPresent('interp-1')).resolves.toBe(false);

    presence.listParticipants.mockResolvedValueOnce([]);
    await expect(svc.agentPresent('interp-1')).resolves.toBe(false);
  });

  it('does not know when LiveKit cannot answer', async () => {
    presence.listParticipants.mockRejectedValue(new Error('timeout'));

    await expect(svc.agentPresent('interp-1')).resolves.toBeNull();
  });

  it('deletes a room best-effort', async () => {
    rooms.deleteRoom.mockRejectedValue(new Error('unavailable'));

    await expect(svc.deleteRoom('interp-1')).resolves.toBeUndefined();
    expect(rooms.deleteRoom).toHaveBeenCalledWith('interp-1');
  });

  it('reads the connect URL at call time', () => {
    delete process.env.LIVEKIT_WS_URL;
    expect(svc.wsUrl).toBe('ws://localhost:7880');

    process.env.LIVEKIT_WS_URL = 'wss://livekit.example';
    expect(svc.wsUrl).toBe('wss://livekit.example');
  });
});
