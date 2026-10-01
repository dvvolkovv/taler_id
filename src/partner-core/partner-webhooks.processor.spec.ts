import { PartnerWebhooksProcessor } from './partner-webhooks.processor';

describe('PartnerWebhooksProcessor', () => {
  const job: any = {
    name: 'deliver',
    attemptsMade: 2,
    data: { partnerId: 'p1', event: { id: 'evt_1', type: 'ping', createdAt: 'x' } },
  };

  it('passes the attempt number and throws on failure so BullMQ retries', async () => {
    const webhooks: any = { deliver: jest.fn().mockResolvedValue({ delivered: false, error: 'http_500' }) };
    await expect(new PartnerWebhooksProcessor(webhooks).process(job)).rejects.toThrow('http_500');
    expect(webhooks.deliver).toHaveBeenCalledWith('p1', job.data.event, 3);
  });

  it('finishes quietly on success and when the webhook is not configured', async () => {
    const ok: any = { deliver: jest.fn().mockResolvedValue({ delivered: true }) };
    await expect(new PartnerWebhooksProcessor(ok).process(job)).resolves.toBeUndefined();
    const off: any = { deliver: jest.fn().mockResolvedValue({ delivered: false, error: 'webhook_not_configured' }) };
    await expect(new PartnerWebhooksProcessor(off).process(job)).resolves.toBeUndefined();
  });

  it('ignores unknown job names', async () => {
    const webhooks: any = { deliver: jest.fn() };
    await new PartnerWebhooksProcessor(webhooks).process({ ...job, name: 'other' });
    expect(webhooks.deliver).not.toHaveBeenCalled();
  });
});
