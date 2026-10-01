import { PartnerWebhooksProcessor } from './partner-webhooks.processor';

describe('PartnerWebhooksProcessor', () => {
  // attemptsMade: 2 → this call is attempt 3 of 7 — mid-retry, not final.
  const job: any = {
    name: 'deliver',
    attemptsMade: 2,
    opts: { attempts: 7 },
    data: {
      partnerId: 'p1',
      event: { id: 'evt_1', type: 'ping', createdAt: 'x' },
    },
  };

  it('passes the attempt number and throws on failure so BullMQ retries', async () => {
    const webhooks: any = {
      deliver: jest
        .fn()
        .mockResolvedValue({ delivered: false, error: 'http_500' }),
    };
    await expect(
      new PartnerWebhooksProcessor(webhooks).process(job),
    ).rejects.toThrow('http_500');
    expect(webhooks.deliver).toHaveBeenCalledWith('p1', job.data.event, 3);
  });

  it('finishes quietly on success and when the event was dropped without retry', async () => {
    const ok: any = {
      deliver: jest.fn().mockResolvedValue({ delivered: true }),
    };
    await expect(
      new PartnerWebhooksProcessor(ok).process(job),
    ).resolves.toBeUndefined();
    const off: any = {
      deliver: jest.fn().mockResolvedValue({
        delivered: false,
        error: 'webhook_not_configured',
      }),
    };
    await expect(
      new PartnerWebhooksProcessor(off).process(job),
    ).resolves.toBeUndefined();
    const revoked: any = {
      deliver: jest
        .fn()
        .mockResolvedValue({ delivered: false, error: 'link_not_active' }),
    };
    await expect(
      new PartnerWebhooksProcessor(revoked).process(job),
    ).resolves.toBeUndefined();
  });

  it('ignores unknown job names', async () => {
    const webhooks: any = { deliver: jest.fn() };
    await new PartnerWebhooksProcessor(webhooks).process({
      ...job,
      name: 'other',
    });
    expect(webhooks.deliver).not.toHaveBeenCalled();
  });

  it('logs one warn line with partner slug, event id and error code on the final failed attempt', async () => {
    const webhooks: any = {
      deliver: jest.fn().mockResolvedValue({
        delivered: false,
        error: 'http_500',
        partnerSlug: 'nadi',
      }),
    };
    const processor = new PartnerWebhooksProcessor(webhooks);
    const warnSpy = jest
      .spyOn((processor as any).logger, 'warn')
      .mockImplementation(() => undefined as any);
    // attemptsMade: 6 → this call is attempt 7 of 7 — the last one.
    const finalJob = { ...job, attemptsMade: 6 };
    await expect(processor.process(finalJob)).rejects.toThrow('http_500');
    expect(warnSpy).toHaveBeenCalledTimes(1);
    const line = warnSpy.mock.calls[0][0] as string;
    expect(line).toContain('nadi');
    expect(line).toContain('evt_1');
    expect(line).toContain('http_500');
    // Monitoring line only — never the signing secret or the message body.
    expect(line).not.toContain('whsec_');
  });

  it('does not warn-log before the final attempt', async () => {
    const webhooks: any = {
      deliver: jest.fn().mockResolvedValue({
        delivered: false,
        error: 'http_500',
        partnerSlug: 'nadi',
      }),
    };
    const processor = new PartnerWebhooksProcessor(webhooks);
    const warnSpy = jest
      .spyOn((processor as any).logger, 'warn')
      .mockImplementation(() => undefined as any);
    await expect(processor.process(job)).rejects.toThrow('http_500'); // attempt 3 of 7
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
