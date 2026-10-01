import { createHmac } from 'crypto';
import {
  buildMessageCreatedEvent,
  partnerWebhookBackoff,
  pingEvent,
  signWebhook,
  verifyWebhookSignature,
  WEBHOOK_RETRY_DELAYS_MS,
} from './partner-webhook-events';

describe('partner webhook events', () => {
  const input = {
    message: { id: 'm1', senderId: 'u-a', sentAt: new Date('2026-10-01T10:00:00Z') },
    senderName: 'Іван',
    preview: 'x'.repeat(250),
    kind: 'text',
    mentionsRecipient: true,
  };

  it('builds message.created with a deterministic id and a 200-char preview', () => {
    const event = buildMessageCreatedEvent({
      recipient: { userId: 'u-b', externalId: 'm-b' },
      senderExternalId: 'm-a',
      conversation: { id: 'c1', type: 'GROUP', title: 'Громада' },
      input,
    });
    expect(event).toEqual({
      id: 'evt_m1_u-b',
      type: 'message.created',
      createdAt: expect.any(String),
      recipient: { externalId: 'm-b', talerUserId: 'u-b' },
      conversation: { id: 'c1', type: 'GROUP', title: 'Громада' },
      message: {
        id: 'm1',
        senderTalerUserId: 'u-a',
        senderExternalId: 'm-a',
        senderName: 'Іван',
        preview: 'x'.repeat(200),
        kind: 'text',
        mentionsRecipient: true,
        createdAt: '2026-10-01T10:00:00.000Z',
      },
    });
  });

  it('does not split an emoji when cutting the preview', () => {
    const event = buildMessageCreatedEvent({
      recipient: { userId: 'u-b', externalId: 'm-b' },
      senderExternalId: null,
      conversation: { id: 'c1', type: 'DIRECT', title: null },
      input: { ...input, preview: '😀'.repeat(201) },
    });
    expect((event.message as any).preview).toBe('😀'.repeat(200));
  });

  const EMOJI = '👩🏽‍💻'; // woman + medium skin tone + ZWJ + laptop = 7 UTF-16 code units, one grapheme

  // The one invariant actually promised: whatever grapheme the preview ends
  // on, it is never a dangling lone surrogate (invalid UTF-16 that breaks
  // JSON/UTF-8 re-encoding downstream). Ending on a "degraded" but still
  // complete and valid grapheme — e.g. the bare base emoji when only its
  // trailing skin-tone/ZWJ/laptop got cut — is a cosmetic truncation, not a
  // bug: the base emoji alone decodes and renders just fine.
  function assertNoLoneSurrogate(preview: string) {
    const lastCharCode = preview.charCodeAt(preview.length - 1);
    expect(lastCharCode >= 0xd800 && lastCharCode <= 0xdbff).toBe(false);
  }

  function previewFor(preview: string): string {
    const event = buildMessageCreatedEvent({
      recipient: { userId: 'u-b', externalId: 'm-b' },
      senderExternalId: null,
      conversation: { id: 'c1', type: 'DIRECT', title: null },
      input: { ...input, preview },
    });
    return (event.message as any).preview as string;
  }

  // 4× code-unit pre-slice (800 units) cuts 'a' + 200×EMOJI (7 units each,
  // 1401 total) mid-grapheme, at the very first code unit of copy 115. If the
  // segmenter's last segment off that cut tail is kept as-is, the preview
  // ends on a lone leading surrogate — invalid UTF-16, breaks re-encoding.
  it('drops a possibly-cut grapheme at the end instead of ending on a lone surrogate', () => {
    const preview = previewFor('a' + EMOJI.repeat(200));
    assertNoLoneSurrogate(preview);
    expect(Array.from(new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(preview)).length)
      .toBeGreaterThan(1);
  });

  // Boundary case: when the 200th (cap-hitting) grapheme is ITSELF the one
  // the pre-slice cut short, "graphemes.length < PREVIEW_MAX" never catches
  // it — we hit the cap and the slice ran out in the very same grapheme.
  // 'a'.repeat(99) + EMOJI.repeat(101): 99 units of 'a' + 100 full emoji
  // (700 units) + 1 leftover unit (EMOJI's lone leading surrogate) = exactly
  // 800 units = PREVIEW_SLICE_UNITS, and exactly 99+100+1 = 200 graphemes.
  it('drops the cut grapheme even when it is exactly the 200th (cap and slice-end coincide)', () => {
    const preview = previewFor('a'.repeat(99) + EMOJI.repeat(101));
    assertNoLoneSurrogate(preview);
  });

  it('never ends the preview on a lone surrogate, across a range of boundary-straddling lengths', () => {
    for (let prefixLen = 95; prefixLen <= 106; prefixLen++) {
      for (let repeats = 96; repeats <= 112; repeats++) {
        assertNoLoneSurrogate(previewFor('a'.repeat(prefixLen) + EMOJI.repeat(repeats)));
      }
    }
  });

  it('signs "t.body" with HMAC-SHA256', () => {
    const expected = createHmac('sha256', 'whsec_test').update('1700000000.{"a":1}').digest('hex');
    expect(signWebhook('whsec_test', 1_700_000_000, '{"a":1}')).toBe(`t=1700000000,v1=${expected}`);
  });

  describe('verifyWebhookSignature', () => {
    const secret = 'whsec_test';
    const body = '{"id":"evt_1"}';
    // 1_700_000_000 s → ms, fixed "now" so the fixtures don't age out as real
    // time passes (the function defaults `now` to Date.now() in production).
    const now = 1_700_000_000_000;

    it('accepts a header produced by signWebhook for the same secret and body', () => {
      const header = signWebhook(secret, 1_700_000_000, body);
      expect(verifyWebhookSignature(secret, header, body, now)).toBe(true);
    });

    it('rejects a wrong secret, a tampered body, a malformed header, and a missing header', () => {
      const header = signWebhook(secret, 1_700_000_000, body);
      expect(verifyWebhookSignature('whsec_other', header, body, now)).toBe(false);
      expect(verifyWebhookSignature(secret, header, body + 'x', now)).toBe(false);
      expect(verifyWebhookSignature(secret, 'not-a-signature-header', body, now)).toBe(false);
      expect(verifyWebhookSignature(secret, undefined, body, now)).toBe(false);
      expect(verifyWebhookSignature(secret, null, body, now)).toBe(false);
    });

    // Without this, a captured header (or just one from a month-old log) would
    // verify forever — the signature alone never expires.
    it('accepts a timestamp within the 5-minute tolerance window on both sides, rejects just outside it', () => {
      const nowSec = now / 1000;
      const justPast = signWebhook(secret, nowSec - 299, body);
      const justFuture = signWebhook(secret, nowSec + 299, body);
      const tooOld = signWebhook(secret, nowSec - 301, body);
      const tooFuture = signWebhook(secret, nowSec + 301, body);
      expect(verifyWebhookSignature(secret, justPast, body, now)).toBe(true);
      expect(verifyWebhookSignature(secret, justFuture, body, now)).toBe(true);
      expect(verifyWebhookSignature(secret, tooOld, body, now)).toBe(false);
      expect(verifyWebhookSignature(secret, tooFuture, body, now)).toBe(false);
    });
  });

  it('gives every ping its own id without a colon', () => {
    const a = pingEvent();
    const b = pingEvent();
    expect(a.type).toBe('ping');
    expect(a.id).not.toBe(b.id);
    expect(a.id).not.toContain(':');
  });

  it('backs off 10 s → 30 s → 1 min → 5 min → 15 min → 1 h', () => {
    expect(WEBHOOK_RETRY_DELAYS_MS).toEqual([10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000]);
    expect([1, 2, 3, 4, 5, 6].map(partnerWebhookBackoff)).toEqual(WEBHOOK_RETRY_DELAYS_MS);
    expect(partnerWebhookBackoff(9)).toBe(3_600_000);
  });
});
