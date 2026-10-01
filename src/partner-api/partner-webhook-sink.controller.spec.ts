import { NotFoundException } from '@nestjs/common';
import { PartnerWebhookSinkController } from './partner-webhook-sink.controller';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

const saved = process.env.PARTNER_WEBHOOK_SINK;

function make(partner: any = { slug: 'e2e' }) {
  const client: any = {
    lpush: jest.fn().mockResolvedValue(1),
    ltrim: jest.fn().mockResolvedValue('OK'),
    expire: jest.fn().mockResolvedValue(1),
    lrange: jest.fn().mockResolvedValue([]),
  };
  const store = new PartnerWebhookSinkStore({ getClient: () => client } as any);
  const registry: any = { findBySlug: jest.fn().mockResolvedValue(partner) };
  return { controller: new PartnerWebhookSinkController(registry, store), client };
}

describe('PartnerWebhookSinkController', () => {
  afterEach(() => {
    if (saved === undefined) delete process.env.PARTNER_WEBHOOK_SINK;
    else process.env.PARTNER_WEBHOOK_SINK = saved;
  });

  it('is 404 unless PARTNER_WEBHOOK_SINK=true', async () => {
    delete process.env.PARTNER_WEBHOOK_SINK;
    const { controller, client } = make();
    await expect(controller.receive('e2e', {}, { a: 1 })).rejects.toThrow(NotFoundException);
    expect(client.lpush).not.toHaveBeenCalled();
  });

  it('stores the event with its signature headers for that partner', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller, client } = make();
    const headers = { 'x-talerid-event': 'ping', 'x-talerid-delivery': 'evt_1', 'x-talerid-signature': 't=1,v1=ab' };
    await expect(controller.receive('e2e', headers, { id: 'evt_1' })).resolves.toEqual({ ok: true });
    expect(client.lpush.mock.calls[0][0]).toBe('partner:sink:e2e');
    expect(JSON.parse(client.lpush.mock.calls[0][1])).toMatchObject({
      event: 'ping',
      delivery: 'evt_1',
      signature: 't=1,v1=ab',
      body: '{"id":"evt_1"}',
    });
    expect(client.ltrim).toHaveBeenCalledWith('partner:sink:e2e', 0, 99);
    expect(client.expire).toHaveBeenCalledWith('partner:sink:e2e', 3600);
  });

  it('404 for an unknown partner', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller } = make(null);
    await expect(controller.receive('ghost', {}, {})).rejects.toThrow(NotFoundException);
  });
});
