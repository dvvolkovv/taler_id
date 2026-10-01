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

  // 4× code-unit pre-slice (800 units) cuts 'a' + 200×EMOJI (7 units each,
  // 1401 total) mid-grapheme, at the very first code unit of copy 115. If the
  // segmenter's last segment off that cut tail is kept as-is, the preview
  // ends on a lone leading surrogate — invalid UTF-16, breaks re-encoding.
  it('drops a possibly-cut grapheme at the end instead of ending on a lone surrogate', () => {
    const EMOJI = '👩🏽‍💻'; // woman + medium skin tone + ZWJ + laptop = 7 UTF-16 code units, one grapheme
    const event = buildMessageCreatedEvent({
      recipient: { userId: 'u-b', externalId: 'm-b' },
      senderExternalId: null,
      conversation: { id: 'c1', type: 'DIRECT', title: null },
      input: { ...input, preview: 'a' + EMOJI.repeat(200) },
    });
    const preview = (event.message as any).preview as string;
    const lastCharCode = preview.charCodeAt(preview.length - 1);
    expect(lastCharCode >= 0xd800 && lastCharCode <= 0xdbff).toBe(false);
    const segments = Array.from(
      new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(preview),
      (s) => s.segment,
    );
    expect(segments.every((s) => s === 'a' || s === EMOJI)).toBe(true);
    expect(segments.length).toBeGreaterThan(1);
  });

  it('signs "t.body" with HMAC-SHA256', () => {
    const expected = createHmac('sha256', 'whsec_test').update('1700000000.{"a":1}').digest('hex');
    expect(signWebhook('whsec_test', 1_700_000_000, '{"a":1}')).toBe(`t=1700000000,v1=${expected}`);
  });

  describe('verifyWebhookSignature', () => {
    const secret = 'whsec_test';
    const body = '{"id":"evt_1"}';

    it('accepts a header produced by signWebhook for the same secret and body', () => {
      const header = signWebhook(secret, 1_700_000_000, body);
      expect(verifyWebhookSignature(secret, header, body)).toBe(true);
    });

    it('rejects a wrong secret, a tampered body, a malformed header, and a missing header', () => {
      const header = signWebhook(secret, 1_700_000_000, body);
      expect(verifyWebhookSignature('whsec_other', header, body)).toBe(false);
      expect(verifyWebhookSignature(secret, header, body + 'x')).toBe(false);
      expect(verifyWebhookSignature(secret, 'not-a-signature-header', body)).toBe(false);
      expect(verifyWebhookSignature(secret, undefined, body)).toBe(false);
      expect(verifyWebhookSignature(secret, null, body)).toBe(false);
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
