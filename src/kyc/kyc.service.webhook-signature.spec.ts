import { BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';
import { KycService } from './kyc.service';

// Regression cover for the 2026-07-27 audit finding: the mismatch branch logged
// `expected` — a valid HMAC for a body the sender controls — turning a public
// endpoint into a signing oracle for anyone who can read backend logs.
describe('KycService.handleWebhook signature handling', () => {
  const SECRET = 'webhook-secret';
  const BODY = Buffer.from(JSON.stringify({ applicantId: 'a-1' }));

  const validSignature = (body: Buffer, secret = SECRET) =>
    crypto.createHmac('sha256', secret).update(body).digest('hex');

  let service: KycService;
  let prisma: any;
  let warnings: string[];
  const ORIGINAL_SECRET = process.env.SUMSUB_WEBHOOK_SECRET;

  beforeEach(() => {
    process.env.SUMSUB_WEBHOOK_SECRET = SECRET;
    warnings = [];
    prisma = { kycRecord: { findFirst: jest.fn().mockResolvedValue(null) } };
    service = new KycService(prisma, {} as any, {} as any, {} as any);
    jest
      .spyOn((service as any).logger, 'warn')
      .mockImplementation((m: string) => warnings.push(String(m)));
    jest.spyOn((service as any).logger, 'error').mockImplementation(() => {});
  });

  afterAll(() => {
    process.env.SUMSUB_WEBHOOK_SECRET = ORIGINAL_SECRET;
  });

  it('accepts a correctly signed callback', async () => {
    await expect(
      service.handleWebhook(BODY, validSignature(BODY)),
    ).resolves.toEqual({ received: true });
  });

  it('rejects a wrong signature', async () => {
    await expect(service.handleWebhook(BODY, 'f'.repeat(64))).rejects.toThrow(
      BadRequestException,
    );
  });

  it('never writes a usable signature to the log', async () => {
    await expect(
      service.handleWebhook(BODY, 'f'.repeat(64)),
    ).rejects.toThrow();

    const expected = validSignature(BODY);
    expect(warnings.join('\n')).not.toContain(expected);
    expect(warnings.join('\n')).not.toContain(SECRET);
    // Nor the secret's length, which narrows a brute-force search.
    expect(warnings.join('\n')).not.toContain(`secret_len=${SECRET.length}`);
  });

  it('rejects a signature of the right shape but wrong content', async () => {
    const otherBody = Buffer.from(JSON.stringify({ applicantId: 'a-2' }));
    await expect(
      service.handleWebhook(BODY, validSignature(otherBody)),
    ).rejects.toThrow(BadRequestException);
  });

  it('refuses callbacks entirely when no secret is configured', async () => {
    delete process.env.SUMSUB_WEBHOOK_SECRET;

    // Previously an unset secret skipped verification and accepted anything.
    await expect(service.handleWebhook(BODY, '')).rejects.toThrow(
      BadRequestException,
    );
  });

  it('does not crash on a malformed signature value', async () => {
    await expect(service.handleWebhook(BODY, '')).rejects.toThrow(
      BadRequestException,
    );
    await expect(
      service.handleWebhook(BODY, undefined as any),
    ).rejects.toThrow(BadRequestException);
  });
});
