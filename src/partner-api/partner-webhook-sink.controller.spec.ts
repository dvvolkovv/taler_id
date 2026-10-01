import { NotFoundException, PayloadTooLargeException } from '@nestjs/common';
import { encryptWebhookSecret } from '../partner-core/partner-secrets.util';
import { signWebhook } from '../partner-core/partner-webhook-events';
import { PartnerWebhookSinkController } from './partner-webhook-sink.controller';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

const savedSink = process.env.PARTNER_WEBHOOK_SINK;
const savedSecretsKey = process.env.PARTNER_SECRETS_KEY;
process.env.PARTNER_SECRETS_KEY = 'c'.repeat(64);
afterAll(() => {
  if (savedSecretsKey === undefined) delete process.env.PARTNER_SECRETS_KEY;
  else process.env.PARTNER_SECRETS_KEY = savedSecretsKey;
});

const SECRET = 'whsec_test';

function make(
  partner: any = {
    slug: 'e2e',
    webhookSecretEnc: encryptWebhookSecret(SECRET),
  },
) {
  const client: any = {
    lpush: jest.fn().mockResolvedValue(1),
    ltrim: jest.fn().mockResolvedValue('OK'),
    expire: jest.fn().mockResolvedValue(1),
    lrange: jest.fn().mockResolvedValue([]),
  };
  const store = new PartnerWebhookSinkStore({ getClient: () => client } as any);
  // Direct, uncached Prisma read — NOT PartnerRegistryService.findBySlug,
  // which snapshots the table for 30s. Right after a secret rotation, a
  // cached lookup here would 404 genuinely-signed deliveries for up to half
  // a minute (flaky e2e).
  const prisma: any = {
    partner: { findUnique: jest.fn().mockResolvedValue(partner) },
  };
  return {
    controller: new PartnerWebhookSinkController(prisma, store),
    client,
    prisma,
  };
}

/** Headers + a fake Express request carrying the raw bytes our own sender would have signed. */
function signedReq(
  bodyText: string,
  extraHeaders: Record<string, string> = {},
) {
  const signature = signWebhook(
    SECRET,
    Math.floor(Date.now() / 1000),
    bodyText,
  );
  return {
    headers: {
      'x-talerid-event': 'ping',
      'x-talerid-delivery': 'evt_1',
      'x-talerid-signature': signature,
      ...extraHeaders,
    },
    req: { rawBody: Buffer.from(bodyText, 'utf8') } as any,
  };
}

describe('PartnerWebhookSinkController', () => {
  afterEach(() => {
    if (savedSink === undefined) delete process.env.PARTNER_WEBHOOK_SINK;
    else process.env.PARTNER_WEBHOOK_SINK = savedSink;
  });

  it('is 404 unless PARTNER_WEBHOOK_SINK=true', async () => {
    delete process.env.PARTNER_WEBHOOK_SINK;
    const { controller, client } = make();
    const { headers, req } = signedReq('{"id":"evt_1"}');
    await expect(controller.receive('e2e', headers, req)).rejects.toThrow(
      NotFoundException,
    );
    expect(client.lpush).not.toHaveBeenCalled();
  });

  it('stores the exact raw body bytes with its signature headers, once the signature checks out', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller, client } = make();
    const bodyText = '{"id":"evt_1"}';
    const { headers, req } = signedReq(bodyText);
    await expect(controller.receive('e2e', headers, req)).resolves.toEqual({
      ok: true,
    });
    expect(client.lpush.mock.calls[0][0]).toBe('partner:sink:e2e');
    expect(JSON.parse(client.lpush.mock.calls[0][1])).toMatchObject({
      event: 'ping',
      delivery: 'evt_1',
      signature: headers['x-talerid-signature'],
      body: bodyText,
    });
    expect(client.ltrim).toHaveBeenCalledWith('partner:sink:e2e', 0, 99);
    expect(client.expire).toHaveBeenCalledWith('partner:sink:e2e', 3600);
  });

  it('404 for an unknown partner', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller } = make(null);
    const { headers, req } = signedReq('{}');
    await expect(controller.receive('ghost', headers, req)).rejects.toThrow(
      NotFoundException,
    );
  });

  it('refuses a missing, malformed, or wrong signature without storing anything', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller, client } = make();
    const bodyText = '{"id":"evt_1"}';
    const { headers, req } = signedReq(bodyText);
    const wrongSignature = signWebhook(
      'whsec_someone_else',
      Math.floor(Date.now() / 1000),
      bodyText,
    );

    await expect(controller.receive('e2e', {}, req)).rejects.toThrow(
      NotFoundException,
    );
    await expect(
      controller.receive('e2e', { 'x-talerid-signature': 'garbage' }, req),
    ).rejects.toThrow(NotFoundException);
    await expect(
      controller.receive(
        'e2e',
        { ...headers, 'x-talerid-signature': wrongSignature },
        req,
      ),
    ).rejects.toThrow(NotFoundException);

    expect(client.lpush).not.toHaveBeenCalled();
  });

  it('404 when the partner has no webhook secret configured to verify against', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller } = make({ slug: 'e2e', webhookSecretEnc: null });
    const { headers, req } = signedReq('{}');
    await expect(controller.receive('e2e', headers, req)).rejects.toThrow(
      NotFoundException,
    );
  });

  it('refuses (413) a body over 64 KB even with a valid signature, without storing it', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller, client } = make();
    const bodyText = 'x'.repeat(64 * 1024 + 1);
    const { headers, req } = signedReq(bodyText);
    await expect(controller.receive('e2e', headers, req)).rejects.toThrow(
      PayloadTooLargeException,
    );
    expect(client.lpush).not.toHaveBeenCalled();
  });

  it('reads the partner by a direct Prisma query, not the 30s registry snapshot', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller, prisma } = make();
    const bodyText = '{"id":"evt_1"}';
    const { headers, req } = signedReq(bodyText);
    await controller.receive('e2e', headers, req);
    expect(prisma.partner.findUnique).toHaveBeenCalledWith({
      where: { slug: 'e2e' },
    });
  });
});
