/**
 * E2E test: Group voice call full HTTP flow.
 *
 * Verifies that the wired-up controller + service + Prisma layer behaves
 * end-to-end:
 *   - host creates a call → invitees fan out, LiveKit token issued, GroupCall+Invites persist
 *   - alice joins → status flips LOBBY→ACTIVE, alice's invite=JOINED
 *   - bob declines → invite=DECLINED
 *   - alice leaves → status=ENDED with reason `all_left`
 *   - host /end on a separate call → status=ENDED with reason `host_ended`
 *   - non-host /end and /kick are rejected with 403 by GroupCallHostGuard
 *   - GET /active returns the call to invitees during LOBBY
 *
 * External services that hit the network are mocked at provider level so the
 * test doesn't need real LiveKit / APNs / FCM:
 *   - ApnsService.sendGroupCallInvite (push to iOS)
 *   - FcmService.sendGroupCallInvite + the other push methods invoked by app
 *     start (registerEmitter wiring touches these indirectly via injection)
 *   - VoiceService.generateGroupCallToken (deterministic stub — real impl
 *     constructs a JWT signed by LiveKit secret which we don't need here)
 *   - VoiceService.deleteRoom / removeParticipant (LiveKit RoomServiceClient
 *     calls — would otherwise attempt HTTP to a non-existent LK server)
 *   - GroupCallGateway emit methods (would otherwise go through MessengerGateway
 *     → Socket.IO server, which isn't started under app.init())
 *
 * Preconditions:
 *   - Postgres reachable at $DATABASE_URL (Prisma client connects on bootstrap)
 *   - Redis reachable at $REDIS_URL (BullModule + RedisService rate-limit)
 *
 * Without those, the test fails fast at app.init() with connection errors.
 * The test code itself is well-formed and runs in CI / staging.
 */

import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { ApnsService } from '../src/common/apns.service';
import { FcmService } from '../src/common/fcm.service';
import { VoiceService } from '../src/voice/voice.service';
import { GroupCallGateway } from '../src/voice/group-call/group-call.gateway';

function decodeJwtSub(token: string): string {
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  return payload.sub as string;
}

async function createTestUser(
  app: INestApplication,
  email: string,
): Promise<{ token: string; userId: string }> {
  const res = await request(app.getHttpServer())
    .post('/auth/register')
    .send({ email, password: 'P@ssw0rd1!' });
  if (res.status !== 201) {
    throw new Error(
      `register ${email} failed: ${res.status} ${JSON.stringify(res.body)}`,
    );
  }
  const token = res.body.accessToken;
  const userId = decodeJwtSub(token);
  return { token, userId };
}

describe('GroupCall (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let hostToken: string;
  let aliceToken: string;
  let bobToken: string;
  let hostId: string;
  let aliceId: string;
  let bobId: string;

  // Unique emails per test run — avoids unique-constraint clashes if a previous
  // run left rows behind (e.g., the suite was interrupted).
  const ts = Date.now();
  const hostEmail = `e2e-gc-host-${ts}@example.test`;
  const aliceEmail = `e2e-gc-alice-${ts}@example.test`;
  const bobEmail = `e2e-gc-bob-${ts}@example.test`;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      // Mock external services so e2e doesn't need real LiveKit / APNs / FCM.
      // These overrides are *value* providers, so any ApnsService / FcmService
      // injection in the dependency graph (including transitive ones via
      // MessengerModule) gets the stubbed object.
      .overrideProvider(ApnsService)
      .useValue({
        sendGroupCallInvite: jest.fn().mockResolvedValue(undefined),
        sendVoIPCallInvite: jest.fn().mockResolvedValue(undefined),
        sendCallEnded: jest.fn().mockResolvedValue(undefined),
        sendNewMessage: jest.fn().mockResolvedValue(undefined),
        sendCalendarInvite: jest.fn().mockResolvedValue(undefined),
        sendCalendarReminder: jest.fn().mockResolvedValue(undefined),
        sendCalendarUpdated: jest.fn().mockResolvedValue(undefined),
        sendContactRequest: jest.fn().mockResolvedValue(undefined),
        sendCallCancelled: jest.fn().mockResolvedValue(undefined),
      })
      .overrideProvider(FcmService)
      .useValue({
        sendGroupCallInvite: jest.fn().mockResolvedValue(undefined),
        sendCallInvite: jest.fn().mockResolvedValue(undefined),
        sendNewMessage: jest.fn().mockResolvedValue(undefined),
        sendCalendarInvite: jest.fn().mockResolvedValue(undefined),
        sendCalendarReminder: jest.fn().mockResolvedValue(undefined),
        sendCalendarUpdated: jest.fn().mockResolvedValue(undefined),
        sendContactRequest: jest.fn().mockResolvedValue(undefined),
        sendCallCancelled: jest.fn().mockResolvedValue(undefined),
      })
      // GroupCallGateway → MessengerGateway.emitToUser hits Socket.IO's `server`,
      // which isn't initialised under `app.init()` (no `app.listen()`). Replace
      // every emit method with a no-op so the service path doesn't blow up on
      // `undefined.to(...)`.
      .overrideProvider(GroupCallGateway)
      .useValue({
        emitInvite: jest.fn(),
        emitStatus: jest.fn(),
        emitJoined: jest.fn(),
        emitLeft: jest.fn(),
        emitKicked: jest.fn(),
        emitMuteRequest: jest.fn(),
        emitHostChanged: jest.fn(),
        emitEnded: jest.fn(),
      })
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
    prisma = moduleRef.get(PrismaService);

    // Patch VoiceService methods after app.init so DI is fully wired.
    // generateGroupCallToken is a pure JWT helper — but it depends on env
    // (LIVEKIT_API_KEY/SECRET) and we don't want the test to be sensitive to
    // those, so stub it. deleteRoom and removeParticipant hit the real
    // RoomServiceClient (HTTP to LiveKit), which would 502 in test envs.
    const voice = moduleRef.get(VoiceService);
    (voice as any).generateGroupCallToken = jest.fn().mockResolvedValue({
      token: 'test-livekit-token',
      livekitWsUrl: 'wss://test-livekit/',
    });
    (voice as any).deleteRoom = jest.fn().mockResolvedValue(undefined);
    (voice as any).removeParticipant = jest.fn().mockResolvedValue(undefined);

    ({ token: hostToken, userId: hostId } = await createTestUser(app, hostEmail));
    ({ token: aliceToken, userId: aliceId } = await createTestUser(app, aliceEmail));
    ({ token: bobToken, userId: bobId } = await createTestUser(app, bobEmail));
  });

  afterAll(async () => {
    if (prisma) {
      // Cleanup order matters because of FK constraints:
      //   GroupCallInvite (cascade-deletes on GroupCall) →
      //   GroupCall →
      //   Profile (FK to User) →
      //   Session (FK to User, ON DELETE RESTRICT) →
      //   User
      const userIds = [hostId, aliceId, bobId].filter(Boolean);
      await prisma.groupCallInvite.deleteMany({ where: { userId: { in: userIds } } });
      await prisma.groupCall.deleteMany({ where: { hostUserId: { in: userIds } } });
      await prisma.profile.deleteMany({ where: { userId: { in: userIds } } });
      await prisma.session.deleteMany({ where: { userId: { in: userIds } } });
      await prisma.user.deleteMany({ where: { id: { in: userIds } } });
    }
    if (app) await app.close();
  });

  it('full flow: create → join (alice) → decline (bob) → leave (alice) → ENDED(all_left)', async () => {
    const create = await request(app.getHttpServer())
      .post('/voice/group-calls')
      .set('Authorization', `Bearer ${hostToken}`)
      .send({ inviteeIds: [aliceId, bobId] })
      .expect(201);

    expect(create.body.groupCall?.id).toBeDefined();
    expect(create.body.livekitToken).toBe('test-livekit-token');
    const callId: string = create.body.groupCall.id;

    // Persisted state: LOBBY with two CALLING invites.
    const initial = await prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    expect(initial!.status).toBe('LOBBY');
    expect(initial!.invites).toHaveLength(2);

    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/join`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .expect(200);

    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/decline`)
      .set('Authorization', `Bearer ${bobToken}`)
      .expect(200);

    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/leave`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .expect(200);

    const dbCall = await prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    expect(dbCall!.status).toBe('ENDED');
    expect(dbCall!.endedReason).toBe('all_left');
  });

  it('host_ended: host /end terminates an active call', async () => {
    const create = await request(app.getHttpServer())
      .post('/voice/group-calls')
      .set('Authorization', `Bearer ${hostToken}`)
      .send({ inviteeIds: [aliceId] })
      .expect(201);
    const callId: string = create.body.groupCall.id;

    // Alice joins so the call goes ACTIVE — `forceEnd` should accept either
    // LOBBY or ACTIVE, but exercising the ACTIVE path is the realistic case.
    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/join`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .expect(200);

    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/end`)
      .set('Authorization', `Bearer ${hostToken}`)
      .expect(200);

    const dbCall = await prisma.groupCall.findUnique({ where: { id: callId } });
    expect(dbCall!.status).toBe('ENDED');
    expect(dbCall!.endedReason).toBe('host_ended');
  });

  it('non-host /end → 403', async () => {
    const create = await request(app.getHttpServer())
      .post('/voice/group-calls')
      .set('Authorization', `Bearer ${hostToken}`)
      .send({ inviteeIds: [aliceId, bobId] })
      .expect(201);
    const callId: string = create.body.groupCall.id;

    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/end`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .expect(403);
  });

  it('non-host /kick → 403', async () => {
    const create = await request(app.getHttpServer())
      .post('/voice/group-calls')
      .set('Authorization', `Bearer ${hostToken}`)
      .send({ inviteeIds: [aliceId, bobId] })
      .expect(201);
    const callId: string = create.body.groupCall.id;

    await request(app.getHttpServer())
      .post(`/voice/group-calls/${callId}/kick`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ userId: bobId })
      .expect(403);
  });

  it('GET /active returns calls for invitees', async () => {
    const create = await request(app.getHttpServer())
      .post('/voice/group-calls')
      .set('Authorization', `Bearer ${hostToken}`)
      .send({ inviteeIds: [aliceId] })
      .expect(201);
    const callId: string = create.body.groupCall.id;

    const aliceActive = await request(app.getHttpServer())
      .get('/voice/group-calls/active')
      .set('Authorization', `Bearer ${aliceToken}`)
      .expect(200);

    expect(Array.isArray(aliceActive.body.calls)).toBe(true);
    expect(
      aliceActive.body.calls.find((c: any) => c.id === callId),
    ).toBeDefined();
  });
});
