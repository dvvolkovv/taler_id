import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { RoomAccessGuard } from './room-access.guard';
import { ACCESS_TOKEN_TYPE } from '../../common/utils/access-token.util';

const LK_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const ctxFor = (roomName: string, authHeader?: string) =>
  ({
    switchToHttp: () => ({
      getRequest: () => ({
        params: { roomName },
        headers: authHeader ? { authorization: authHeader } : {},
      }),
    }),
  }) as any;

const livekitToken = (room: string) =>
  jwt.sign({ sub: 'guest-1', video: { roomJoin: true, room } }, LK_SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h',
  });

const userToken = (sub: string) =>
  jwt.sign({ sub, typ: ACCESS_TOKEN_TYPE }, privateKey, {
    algorithm: 'RS256',
    expiresIn: '1h',
  });

describe('RoomAccessGuard', () => {
  let guard: RoomAccessGuard;
  let prisma: any;
  let publicKeyPath: string;

  beforeAll(() => {
    publicKeyPath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'room-access-')),
      'public.pem',
    );
    fs.writeFileSync(publicKeyPath, publicKey);
  });

  afterAll(() => {
    fs.rmSync(path.dirname(publicKeyPath), { recursive: true, force: true });
  });

  beforeEach(() => {
    prisma = {
      callLog: { findUnique: jest.fn().mockResolvedValue(null) },
      publicRoom: { findFirst: jest.fn().mockResolvedValue(null) },
    };
    guard = new RoomAccessGuard(prisma, {
      get: () => publicKeyPath,
    } as any);
  });

  it('rejects a request with no token', async () => {
    await expect(guard.canActivate(ctxFor('call-1'))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('accepts a LiveKit grant naming this room', async () => {
    const ctx = ctxFor('call-1', `Bearer ${livekitToken('call-1')}`);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('rejects a LiveKit grant for a different room', async () => {
    // The core of the finding: knowing a room name must not be enough.
    const ctx = ctxFor('call-victim', `Bearer ${livekitToken('call-mine')}`);
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('rejects a forged LiveKit token', async () => {
    const forged = jwt.sign(
      { sub: 'attacker', video: { room: 'call-1' } },
      'wrong-secret',
      { algorithm: 'HS256' },
    );
    await expect(
      guard.canActivate(ctxFor('call-1', `Bearer ${forged}`)),
    ).rejects.toThrow(ForbiddenException);
  });

  it('accepts a participant of the call', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      participantIds: ['user-1', 'user-2'],
    });
    const ctx = ctxFor('call-1', `Bearer ${userToken('user-1')}`);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('rejects an authenticated user who is not a participant', async () => {
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      participantIds: ['user-1'],
    });
    const ctx = ctxFor('call-1', `Bearer ${userToken('intruder')}`);
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('accepts the owner of a personal room', async () => {
    const owner = 'abcdef12-3456-7890-abcd-ef1234567890';
    const ctx = ctxFor(
      `personal-${owner.substring(0, 8)}-deadbeef`,
      `Bearer ${userToken(owner)}`,
    );
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it("rejects a past guest of someone else's personal room", async () => {
    // Guests learn the room code from the share link and keep it forever;
    // that must not let them start a recording later.
    const ctx = ctxFor(
      'personal-abcdef12-deadbeef',
      `Bearer ${userToken('99999999-3456-7890-abcd-ef1234567890')}`,
    );
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('accepts the creator of a temporary room', async () => {
    // tmp-/pub- rooms have no CallLog; ownership lives in PublicRoom.
    prisma.publicRoom.findFirst.mockResolvedValue({ id: 'pr-1' });

    const ctx = ctxFor('tmp-abcdef', `Bearer ${userToken('owner-1')}`);
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('rejects a stranger at a temporary room they did not create', async () => {
    prisma.publicRoom.findFirst.mockResolvedValue(null);

    const ctx = ctxFor('tmp-abcdef', `Bearer ${userToken('stranger')}`);
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });

  it('rejects an OIDC id_token even though it is signed with the API key', async () => {
    const idToken = jwt.sign(
      { sub: 'user-1', aud: 'client-abc', iss: 'https://id.taler.tirol/oauth' },
      privateKey,
      { algorithm: 'RS256', expiresIn: '1h' },
    );
    prisma.callLog.findUnique.mockResolvedValue({
      roomName: 'call-1',
      participantIds: ['user-1'],
    });
    await expect(
      guard.canActivate(ctxFor('call-1', `Bearer ${idToken}`)),
    ).rejects.toThrow(ForbiddenException);
  });
});
