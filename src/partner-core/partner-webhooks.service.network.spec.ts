import * as http from 'http';
import type { AddressInfo } from 'net';
import { encryptWebhookSecret } from './partner-secrets.util';
import { PartnerWebhooksService } from './partner-webhooks.service';

/**
 * deliver() against REAL local HTTP servers, not a mocked axios. Hand-built
 * mock errors risk asserting our own guess at axios' error shape rather than
 * what it really throws — this is exactly how the previous round's
 * `err.name === 'TimeoutError'` check turned out to be wrong (axios actually
 * surfaces an AbortSignal abort as a CanceledError).
 */

const savedSecretsKey = process.env.PARTNER_SECRETS_KEY;
process.env.PARTNER_SECRETS_KEY = 'c'.repeat(64);
const savedEnabled = process.env.PARTNER_API_ENABLED;
process.env.PARTNER_API_ENABLED = 'true';
afterAll(() => {
  if (savedSecretsKey === undefined) delete process.env.PARTNER_SECRETS_KEY;
  else process.env.PARTNER_SECRETS_KEY = savedSecretsKey;
  if (savedEnabled === undefined) delete process.env.PARTNER_API_ENABLED;
  else process.env.PARTNER_API_ENABLED = savedEnabled;
});

function startServer(handler: http.RequestListener): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    // Sockets of a destroyed/never-closing connection can keep server.close()
    // from ever calling back — track and force-destroy them on close.
    const sockets = new Set<import('net').Socket>();
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}/hook`,
        close: () =>
          new Promise<void>((r) => {
            for (const s of sockets) s.destroy();
            server.close(() => r());
          }),
      });
    });
  });
}

function make(webhookUrl: string) {
  const prisma: any = {};
  const partner = {
    id: 'p1',
    slug: 'nadi',
    enabled: true,
    webhookUrl,
    webhookSecretEnc: encryptWebhookSecret('whsec_test'),
  };
  const registry: any = { findById: jest.fn().mockResolvedValue(partner) };
  const client: any = { lpush: jest.fn().mockResolvedValue(1), ltrim: jest.fn().mockResolvedValue('OK') };
  const redis: any = { getClient: () => client };
  const queue: any = { add: jest.fn() };
  return new PartnerWebhooksService(prisma, registry, redis, queue);
}

const event: any = { id: 'evt_1', type: 'ping', createdAt: 'x' };
const SHORT_DEADLINE_MS = 200;

describe('PartnerWebhooksService.deliver against a real server (error-label precision)', () => {
  it('labels a server that never answers as timeout, within the (injectable) deadline', async () => {
    const { url, close } = await startServer(() => {
      // Never respond, never end — the client's own deadline must do the work.
    });
    try {
      const service = make(url);
      const started = Date.now();
      const result = await service.deliver('p1', event, 1, SHORT_DEADLINE_MS);
      expect(result).toMatchObject({ delivered: false, status: null, error: 'timeout' });
      expect(Date.now() - started).toBeLessThan(SHORT_DEADLINE_MS + 3000);
    } finally {
      await close();
    }
  }, 10_000);

  it('labels a response over 64 KB as response_too_large', async () => {
    const { url, close } = await startServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('x'.repeat(70 * 1024));
    });
    try {
      const service = make(url);
      const result = await service.deliver('p1', event);
      expect(result).toMatchObject({ delivered: false, status: null, error: 'response_too_large' });
    } finally {
      await close();
    }
  }, 10_000);

  it('does NOT label a connection reset mid-body as response_too_large', async () => {
    const { url, close } = await startServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.write('partial-and-then-nothing');
      // Abrupt disconnect partway through the body — not a size-limit trip.
      req.socket.destroy();
    });
    try {
      const service = make(url);
      const result = await service.deliver('p1', event);
      expect(result.delivered).toBe(false);
      expect(result.error).not.toBe('response_too_large');
      expect(result.error).not.toBe('timeout');
      expect(result.error).toBeTruthy();
    } finally {
      await close();
    }
  }, 10_000);
});
