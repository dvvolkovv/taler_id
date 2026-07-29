import * as admin from 'firebase-admin';
import { FcmService } from './fcm.service';

// Regression cover for the stale-ringing report (2026-07-29): a call push sent
// while the callee was offline sat in FCM (default retention: four weeks) and
// was delivered the moment they came back online — their phone rang for a call
// that had ended long before.
describe('FcmService call pushes expire', () => {
  let service: FcmService;
  let send: jest.Mock;

  const messageFor = (call: number) => send.mock.calls[call][0];

  beforeEach(() => {
    send = jest.fn().mockResolvedValue('ok');
    jest.spyOn(admin, 'messaging').mockReturnValue({ send } as any);

    service = new FcmService({
      user: { findUnique: jest.fn().mockResolvedValue({ fcmToken: 'tok' }) },
    } as any);
    // Bypass credential loading — only the payload shape is under test.
    (service as any).initialized = true;
  });

  afterEach(() => jest.restoreAllMocks());

  describe('sendCallInvite', () => {
    it('gives Android a ringing-length TTL instead of FCM default retention', async () => {
      await service.sendCallInvite('tok', 'Алиса', 'call-1', 'conv-1');

      const msg = messageFor(0);
      expect(msg.android.ttl).toBe(30_000);
    });

    it('expires the iOS fallback push too', async () => {
      const before = Math.floor(Date.now() / 1000);
      await service.sendCallInvite('tok', 'Алиса', 'call-1', 'conv-1');

      const exp = Number(messageFor(0).apns.headers['apns-expiration']);
      expect(exp).toBeGreaterThanOrEqual(before + 29);
      expect(exp).toBeLessThanOrEqual(before + 31);
    });

    it('still carries the data the client needs to ring', async () => {
      await service.sendCallInvite('tok', 'Алиса', 'call-1', 'conv-1', 'k', 'a');

      const msg = messageFor(0);
      expect(msg.data).toMatchObject({
        type: 'call_invite',
        roomName: 'call-1',
        conversationId: 'conv-1',
        fromName: 'Алиса',
        e2eeKey: 'k',
      });
    });
  });

  describe('sendCallCancelled', () => {
    it('outlives the invite by a margin, but not indefinitely', async () => {
      await service.sendCallCancelled('tok', 'call-1', 'Алиса');

      const msg = messageFor(0);
      // Long enough to catch an invite already on screen, short enough not to
      // surface days later.
      expect(msg.android.ttl).toBe(60_000);
      expect(msg.android.ttl).toBeGreaterThan(30_000);
      expect(Number(msg.apns.headers['apns-expiration'])).toBeGreaterThan(
        Math.floor(Date.now() / 1000),
      );
    });
  });

  it('group invites keep the TTL they already had', async () => {
    // Takes a userId and resolves the token itself.
    await service.sendGroupCallInvite('user-1', {
      groupCallId: 'g-1',
      host: { id: 'u-1', displayName: 'Алиса', avatarUrl: null },
      inviteeCount: 3,
    } as any);

    expect(messageFor(0).android.ttl).toBe(30_000);
  });
});
