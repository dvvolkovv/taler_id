jest.mock('axios');
import axios from 'axios';
import { encryptWebhookSecret } from './partner-secrets.util';
import { signWebhook } from './partner-webhook-events';
import { PartnerWebhooksService } from './partner-webhooks.service';

const savedSecretsKey = process.env.PARTNER_SECRETS_KEY;
process.env.PARTNER_SECRETS_KEY = 'c'.repeat(64);
afterAll(() => {
  if (savedSecretsKey === undefined) delete process.env.PARTNER_SECRETS_KEY;
  else process.env.PARTNER_SECRETS_KEY = savedSecretsKey;
});

const savedEnabled = process.env.PARTNER_API_ENABLED;
afterAll(() => {
  if (savedEnabled === undefined) delete process.env.PARTNER_API_ENABLED;
  else process.env.PARTNER_API_ENABLED = savedEnabled;
});

function make() {
  const prisma: any = {
    conversation: {
      findUnique: jest.fn().mockResolvedValue({ type: 'DIRECT', name: null }),
    },
    partnerLink: {
      findMany: jest.fn().mockResolvedValue([]),
      findUnique: jest.fn().mockResolvedValue({ status: 'ACTIVE' }),
    },
  };
  const registry: any = { findById: jest.fn() };
  const list: string[] = [];
  const client: any = {
    lpush: jest.fn(async (_key: string, value: string) => list.unshift(value)),
    ltrim: jest.fn().mockResolvedValue('OK'),
    lrange: jest.fn(async (_key: string, start: number, stop: number) =>
      list.slice(start, stop + 1),
    ),
  };
  const redis: any = { getClient: () => client };
  const queue: any = { add: jest.fn().mockResolvedValue({}) };
  const service = new PartnerWebhooksService(prisma, registry, redis, queue);
  return { service, prisma, registry, client, queue };
}

const flush = () => new Promise((r) => setImmediate(r));

describe('PartnerWebhooksService.planFanOut', () => {
  const args = {
    conversationId: 'c1',
    participantIds: ['u-a', 'u-b', 'u-c'],
    senderId: 'u-a',
    systemPost: false,
    conversationType: 'DIRECT' as string | null,
  };
  const input = {
    message: {
      id: 'm1',
      senderId: 'u-a',
      sentAt: new Date('2026-10-01T10:00:00Z'),
    },
    senderName: 'A',
    preview: 'hi',
    kind: 'text',
    mentionsRecipient: false,
  };

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
  });

  it('does nothing while the partner API is off', async () => {
    process.env.PARTNER_API_ENABLED = 'false';
    const { service, prisma } = make();
    await expect(service.planFanOut(args)).resolves.toBeNull();
    expect(prisma.partnerLink.findMany).not.toHaveBeenCalled();
  });

  it('skips system posts and conversation types other than chats and groups, without touching the database', async () => {
    const { service, prisma } = make();
    await expect(
      service.planFanOut({ ...args, systemPost: true }),
    ).resolves.toBeNull();
    await expect(
      service.planFanOut({ ...args, conversationType: 'CHANNEL' }),
    ).resolves.toBeNull();
    await expect(
      service.planFanOut({ ...args, conversationType: null }),
    ).resolves.toBeNull();
    expect(prisma.partnerLink.findMany).not.toHaveBeenCalled();
  });

  it('loads the links of all participants in one query and returns null when there are none', async () => {
    const { service, prisma } = make();
    await expect(service.planFanOut(args)).resolves.toBeNull();
    expect(prisma.partnerLink.findMany).toHaveBeenCalledTimes(1);
    expect(prisma.partnerLink.findMany).toHaveBeenCalledWith({
      where: {
        userId: { in: ['u-a', 'u-b', 'u-c'] },
        status: 'ACTIVE',
        partner: { enabled: true, webhookUrl: { not: null } },
      },
      select: { userId: true, externalId: true, partnerId: true },
    });
  });

  it('forces the title to null for a DIRECT conversation without reading the conversation row', async () => {
    const { service, prisma, queue } = make();
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const plan = await service.planFanOut(args); // conversationType: 'DIRECT'
    plan!.enqueue('u-b', input);
    await flush();
    expect(prisma.conversation.findUnique).not.toHaveBeenCalled();
    const [, data] = queue.add.mock.calls[0];
    expect(data.event.conversation).toEqual({
      id: 'c1',
      type: 'DIRECT',
      title: null,
    });
  });

  it("queues one event per linked recipient, with the sender's externalId from the same partner", async () => {
    const { service, prisma, queue } = make();
    prisma.conversation.findUnique.mockResolvedValue({ name: 'Громада' });
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const plan = await service.planFanOut({
      ...args,
      conversationType: 'GROUP',
    });
    plan!.enqueue('u-b', input);
    plan!.enqueue('u-c', input);
    plan!.enqueue('u-a', input);
    await flush();
    expect(queue.add).toHaveBeenCalledTimes(1);
    const [name, data, opts] = queue.add.mock.calls[0];
    expect(name).toBe('deliver');
    expect(data.partnerId).toBe('p1');
    expect(data.event).toMatchObject({
      id: 'evt_m1_u-b',
      recipient: { externalId: 'm-b' },
      conversation: { id: 'c1', type: 'GROUP', title: 'Громада' },
      message: { senderExternalId: 'm-a', preview: 'hi' },
    });
    expect(opts).toEqual({
      jobId: 'p1_evt_m1_u-b',
      attempts: 7,
      backoff: { type: 'custom' },
      // BullMQ 5 only age-sweeps a finished set when ANOTHER job finishes
      // into it — a lone final-failed job with its preview could stay in
      // Redis forever. The journal (recentDeliveries) is the durable record;
      // jobId dedup only needs to cover jobs still in flight.
      removeOnComplete: true,
      removeOnFail: true,
    });
  });

  it("gives the sender's externalId only from the recipient's own partner", async () => {
    const { service, prisma, queue } = make();
    prisma.partnerLink.findMany.mockResolvedValue([
      // sender is linked to a DIFFERENT partner than the recipient
      { userId: 'u-a', externalId: 'm-a-other', partnerId: 'p2' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const plan = await service.planFanOut(args);
    plan!.enqueue('u-b', input);
    await flush();
    expect(queue.add).toHaveBeenCalledTimes(1);
    const [, data] = queue.add.mock.calls[0];
    expect(data.partnerId).toBe('p1');
    expect(data.event.message.senderExternalId).toBeNull();
  });

  it('queues one job per partner when the recipient is linked to two partners', async () => {
    const { service, prisma, queue } = make();
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-b', externalId: 'm-b-1', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b-2', partnerId: 'p2' },
    ]);
    const plan = await service.planFanOut(args);
    plan!.enqueue('u-b', input);
    await flush();
    expect(queue.add).toHaveBeenCalledTimes(2);
    const jobIds = queue.add.mock.calls.map(([, , opts]: any) => opts.jobId);
    expect(new Set(jobIds).size).toBe(2);
  });

  it('never breaks message delivery when loading links fails', async () => {
    const { service, prisma } = make();
    prisma.partnerLink.findMany.mockRejectedValue(new Error('db down'));
    await expect(service.planFanOut(args)).resolves.toBeNull();
  });

  it('never breaks message delivery when the group-title lookup fails', async () => {
    const { service, prisma } = make();
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    prisma.conversation.findUnique.mockRejectedValue(new Error('db down'));
    await expect(
      service.planFanOut({ ...args, conversationType: 'GROUP' }),
    ).resolves.toBeNull();
  });

  it('swallows a rejected queue.add (logged)', async () => {
    const { service, prisma, queue } = make();
    queue.add.mockRejectedValue(new Error('redis down'));
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const warnSpy = jest
      .spyOn((service as any).logger, 'warn')
      .mockImplementation(() => undefined as any);
    const plan = await service.planFanOut(args);
    expect(() => plan!.enqueue('u-b', input)).not.toThrow();
    await flush();
    expect(warnSpy).toHaveBeenCalled();
  });
});

describe('PartnerWebhooksService.deliver', () => {
  const event: any = {
    id: 'evt_1',
    type: 'ping',
    createdAt: '2026-10-01T10:00:00.000Z',
  };
  let partner: any;

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
    (axios.post as jest.Mock).mockReset();
    partner = {
      id: 'p1',
      slug: 'nadi',
      enabled: true,
      webhookUrl: 'https://nadi.example/hook',
      webhookSecretEnc: encryptWebhookSecret('whsec_test'),
    };
  });

  it('posts the signed body and records a 2xx as delivered', async () => {
    const { service, registry, client } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValue({ status: 204 });
    const res = await service.deliver('p1', event, 2);
    expect(res).toMatchObject({
      eventId: 'evt_1',
      type: 'ping',
      attempt: 2,
      delivered: true,
      status: 204,
      error: null,
    });
    const [url, body, config] = (axios.post as jest.Mock).mock.calls[0];
    expect(url).toBe('https://nadi.example/hook');
    expect(body).toBe(JSON.stringify(event));
    const t = Number(/t=(\d+)/.exec(config.headers['X-TalerID-Signature'])![1]);
    expect(config.headers['X-TalerID-Signature']).toBe(
      signWebhook('whsec_test', t, body),
    );
    expect(config.headers).toMatchObject({
      'Content-Type': 'application/json',
      'User-Agent': 'TalerID-Webhooks/1',
      'X-TalerID-Event': 'ping',
      'X-TalerID-Delivery': 'evt_1',
    });
    // Overall deadline via AbortSignal, not axios' inactivity-only `timeout`
    // (a receiver dripping 1 byte/s never goes idle long enough to trip it).
    // Response is capped and read as text, not auto-parsed/buffered unbounded.
    expect(config.signal).toBeInstanceOf(AbortSignal);
    expect(config).toMatchObject({
      maxRedirects: 0,
      maxContentLength: 64 * 1024,
      responseType: 'text',
    });
    expect(client.lpush).toHaveBeenCalledWith(
      'partner:webhook:log:p1',
      expect.any(String),
    );
    expect(client.ltrim).toHaveBeenCalledWith('partner:webhook:log:p1', 0, 999);
  });

  // Timeout/abort and the reset-mid-body-is-NOT-response_too_large distinction
  // are exercised against a REAL local HTTP server in
  // partner-webhooks.service.network.spec.ts — axios actually wraps an
  // AbortSignal abort as a CanceledError (not a 'TimeoutError'-named error, as
  // a first guess here assumed), so a hand-built mock error risks asserting
  // our own wrong assumption instead of what axios really throws.

  it('journals an oversize response as a short retryable error code, by the message prefix axios uses for it', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue(partner);
    const tooBig = new Error('maxContentLength size of 65536 exceeded');
    (axios.post as jest.Mock).mockRejectedValueOnce(tooBig);
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      status: null,
      error: 'response_too_large',
    });
  });

  it('journals secret_unreadable (and stays retryable) when the webhook secret cannot be decrypted, without a bare throw', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue({
      ...partner,
      webhookSecretEnc: 'not-valid-ciphertext',
    });
    const warnSpy = jest
      .spyOn((service as any).logger, 'warn')
      .mockImplementation(() => undefined as any);
    const res = await service.deliver('p1', event);
    expect(res).toMatchObject({
      delivered: false,
      status: null,
      error: 'secret_unreadable',
    });
    expect(axios.post).not.toHaveBeenCalled();
    // Only the partner id/slug — never the secret or the event body.
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('nadi'));
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('p1'));
    expect(warnSpy.mock.calls[0][0]).not.toContain('not-valid-ciphertext');
  });

  it('drops a message.created event without retrying when the recipient link is no longer active', async () => {
    const { service, registry, prisma } = make();
    registry.findById.mockResolvedValue(partner);
    prisma.partnerLink.findUnique.mockResolvedValue({ status: 'REVOKED' });
    const msgEvent: any = {
      id: 'evt_m1_u-b',
      type: 'message.created',
      createdAt: 'x',
      recipient: { externalId: 'm-b', talerUserId: 'u-b' },
    };
    await expect(service.deliver('p1', msgEvent)).resolves.toMatchObject({
      delivered: false,
      error: 'link_not_active',
    });
    expect(axios.post).not.toHaveBeenCalled();
    expect(prisma.partnerLink.findUnique).toHaveBeenCalledWith({
      where: { partnerId_userId: { partnerId: 'p1', userId: 'u-b' } },
      select: { status: true },
    });
  });

  it('drops a message.created event without retrying when the recipient link is gone entirely', async () => {
    const { service, registry, prisma } = make();
    registry.findById.mockResolvedValue(partner);
    prisma.partnerLink.findUnique.mockResolvedValue(null);
    const msgEvent: any = {
      id: 'evt_m1_u-b',
      type: 'message.created',
      createdAt: 'x',
      recipient: { externalId: 'm-b', talerUserId: 'u-b' },
    };
    await expect(service.deliver('p1', msgEvent)).resolves.toMatchObject({
      delivered: false,
      error: 'link_not_active',
    });
    expect(axios.post).not.toHaveBeenCalled();
  });

  it('still delivers a message.created event when the recipient link is active', async () => {
    const { service, registry, prisma } = make();
    registry.findById.mockResolvedValue(partner);
    prisma.partnerLink.findUnique.mockResolvedValue({ status: 'ACTIVE' });
    (axios.post as jest.Mock).mockResolvedValue({ status: 200 });
    const msgEvent: any = {
      id: 'evt_m1_u-b',
      type: 'message.created',
      createdAt: 'x',
      recipient: { externalId: 'm-b', talerUserId: 'u-b' },
    };
    await expect(service.deliver('p1', msgEvent)).resolves.toMatchObject({
      delivered: true,
    });
    expect(axios.post).toHaveBeenCalled();
  });

  it('records non-2xx answers and network errors as failures', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValueOnce({ status: 500 });
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      status: 500,
      error: 'http_500',
    });
    (axios.post as jest.Mock).mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      status: null,
      error: 'ECONNREFUSED',
    });
  });

  it('calls nobody when the webhook is not configured', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue({ ...partner, webhookUrl: null });
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      error: 'webhook_not_configured',
    });
    expect(axios.post).not.toHaveBeenCalled();
  });

  it('returns the newest deliveries first, clamped to 200', async () => {
    const { service, registry, client } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValue({ status: 200 });
    await service.deliver('p1', { ...event, id: 'evt_a' });
    await service.deliver('p1', { ...event, id: 'evt_b' });
    const rows = await service.recentDeliveries('p1', 500);
    expect(rows.map((r) => r.eventId)).toEqual(['evt_b', 'evt_a']);
    expect(client.lrange).toHaveBeenLastCalledWith(
      'partner:webhook:log:p1',
      0,
      199,
    );
  });

  // Adjustment 6: kill switches must stop queued events and their retries
  // immediately, instead of failing normally and waiting out all 6 backoff
  // steps (~1.5h) before the worker gives up.
  it('drops the job without retrying when the partner API is off globally', async () => {
    process.env.PARTNER_API_ENABLED = 'false';
    const { service, registry } = make();
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      error: 'webhook_not_configured',
    });
    expect(registry.findById).not.toHaveBeenCalled();
    expect(axios.post).not.toHaveBeenCalled();
  });

  it('drops the job without retrying when the partner has been disabled', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue({ ...partner, enabled: false });
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      error: 'webhook_not_configured',
    });
    expect(axios.post).not.toHaveBeenCalled();
  });

  it('drops the job without retrying when the webhook secret was cleared', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue({ ...partner, webhookSecretEnc: null });
    await expect(service.deliver('p1', event)).resolves.toMatchObject({
      delivered: false,
      error: 'webhook_not_configured',
    });
    expect(axios.post).not.toHaveBeenCalled();
  });

  it('keeps partnerSlug only in the in-memory result (for the processor warn line), never in the journal', async () => {
    const { service, registry, client } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValue({ status: 200 });
    const result = await service.deliver('p1', event);
    expect((result as any).partnerSlug).toBe('nadi');
    const stored = JSON.parse(client.lpush.mock.calls[0][1]);
    expect(stored).not.toHaveProperty('partnerSlug');
    // Ровно документированные поля GET webhooks/deliveries — ни полем больше.
    expect(Object.keys(stored).sort()).toEqual(
      [
        'at',
        'attempt',
        'delivered',
        'durationMs',
        'error',
        'eventId',
        'status',
        'type',
      ].sort(),
    );
    const rows = await service.recentDeliveries('p1', 10);
    expect(rows[0]).not.toHaveProperty('partnerSlug');
  });
});
