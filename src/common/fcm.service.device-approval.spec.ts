import * as admin from 'firebase-admin';
import { FcmService } from './fcm.service';

// Regression cover for 2026-11-17: an approval request lives ten minutes, but
// its push went out with FCM's default retention (four weeks) and sat in the
// notification shade with no end. Tapped the next morning, both "it's me" and
// "not me" answered 404 — the request had long expired.
describe('FcmService device-approval push expires with the request', () => {
  let service: FcmService;
  let send: jest.Mock;

  const message = () => send.mock.calls[0][0];
  const inMs = (ms: number) => new Date(Date.now() + ms).toISOString();

  beforeEach(() => {
    send = jest.fn().mockResolvedValue('ok');
    jest.spyOn(admin, 'messaging').mockReturnValue({ send } as any);

    service = new FcmService({} as any);
    // Bypass credential loading — only the payload shape is under test.
    (service as any).initialized = true;
  });

  afterEach(() => jest.restoreAllMocks());

  const push = (expiresAt: string) =>
    service.sendDeviceApprovalRequest('tok', {
      approvalId: 'appr-1',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      expiresAt,
    });

  it('gives Android only the time the request has left', async () => {
    await push(inMs(10 * 60 * 1000));

    const ttl = message().android.ttl;
    expect(ttl).toBeLessThanOrEqual(10 * 60 * 1000);
    expect(ttl).toBeGreaterThan(10 * 60 * 1000 - 5_000);
  });

  it('expires the iOS push at the same moment', async () => {
    const expiresAt = inMs(10 * 60 * 1000);
    await push(expiresAt);

    const exp = Number(message().apns.headers['apns-expiration']);
    const deadline = Math.floor(Date.parse(expiresAt) / 1000);
    expect(exp).toBeGreaterThanOrEqual(deadline - 1);
    expect(exp).toBeLessThanOrEqual(deadline);
  });

  it('tells the client when the request expires', async () => {
    const expiresAt = inMs(10 * 60 * 1000);
    await push(expiresAt);

    expect(message().data).toMatchObject({
      type: 'device_approval',
      approvalId: 'appr-1',
      expiresAt,
    });
  });

  it('never hands FCM a negative TTL for a request already past its deadline', async () => {
    await push(inMs(-60_000));

    expect(message().android.ttl).toBe(0);
  });
});
