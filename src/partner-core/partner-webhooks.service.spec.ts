import { PartnerWebhooksService } from './partner-webhooks.service';

const savedEnabled = process.env.PARTNER_API_ENABLED;
afterAll(() => {
  if (savedEnabled === undefined) delete process.env.PARTNER_API_ENABLED;
  else process.env.PARTNER_API_ENABLED = savedEnabled;
});

function make() {
  const prisma: any = {
    conversation: { findUnique: jest.fn().mockResolvedValue({ type: 'DIRECT', name: null }) },
    partnerLink: { findMany: jest.fn().mockResolvedValue([]) },
  };
  const registry: any = { findById: jest.fn() };
  const list: string[] = [];
  const client: any = {
    lpush: jest.fn(async (_key: string, value: string) => list.unshift(value)),
    ltrim: jest.fn().mockResolvedValue('OK'),
    lrange: jest.fn(async (_key: string, start: number, stop: number) => list.slice(start, stop + 1)),
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
    message: { id: 'm1', senderId: 'u-a', sentAt: new Date('2026-10-01T10:00:00Z') },
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
    await expect(service.planFanOut({ ...args, systemPost: true })).resolves.toBeNull();
    await expect(service.planFanOut({ ...args, conversationType: 'CHANNEL' })).resolves.toBeNull();
    await expect(service.planFanOut({ ...args, conversationType: null })).resolves.toBeNull();
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
    expect(data.event.conversation).toEqual({ id: 'c1', type: 'DIRECT', title: null });
  });

  it("queues one event per linked recipient, with the sender's externalId from the same partner", async () => {
    const { service, prisma, queue } = make();
    prisma.conversation.findUnique.mockResolvedValue({ name: 'Громада' });
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const plan = await service.planFanOut({ ...args, conversationType: 'GROUP' });
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
      removeOnComplete: { age: 3600, count: 1000 },
      removeOnFail: { age: 86400, count: 1000 },
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
    await expect(service.planFanOut({ ...args, conversationType: 'GROUP' })).resolves.toBeNull();
  });

  it('swallows a rejected queue.add (logged)', async () => {
    const { service, prisma, queue } = make();
    queue.add.mockRejectedValue(new Error('redis down'));
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const warnSpy = jest.spyOn((service as any).logger, 'warn').mockImplementation(() => undefined as any);
    const plan = await service.planFanOut(args);
    expect(() => plan!.enqueue('u-b', input)).not.toThrow();
    await flush();
    expect(warnSpy).toHaveBeenCalled();
  });
});
