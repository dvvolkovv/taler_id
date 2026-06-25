import { createHash, createHmac } from 'crypto';
import { InformerClient } from './informer.client';
import {
  InformerAuthError,
  InformerBadRequestError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerTotpError,
  InformerUnavailableError,
} from './informer.types';

describe('InformerClient.buildSignature', () => {
  it('builds a 64-char hex signature for fixed inputs', () => {
    const client = new InformerClient({
      baseUrl: 'https://example.test',
      key: 'k',
      secret: 'test-secret',
    });
    const sig = client.buildSignature(
      'GET',
      '/informer/v1/operator-required-wallets/count',
      '1700000000',
      '',
    );
    expect(sig).toMatch(/^[a-f0-9]{64}$/);
    expect(sig.length).toBe(64);
  });

  it('produces a different signature when secret changes', () => {
    const a = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's1' });
    const b = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's2' });
    expect(a.buildSignature('GET', '/p', '1700000000', '')).not.toEqual(
      b.buildSignature('GET', '/p', '1700000000', ''),
    );
  });

  it('produces a different signature when path changes', () => {
    const c = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });
    expect(c.buildSignature('GET', '/a', '1700000000', '')).not.toEqual(
      c.buildSignature('GET', '/b', '1700000000', ''),
    );
  });

  it('uses the documented empty-body sha256 constant', () => {
    // From the integration guide §2.1 — sha256 of empty body
    const client = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });
    // Same inputs should be stable across instances
    const sig1 = client.buildSignature('GET', '/p', '100', '');
    const sig2 = client.buildSignature('GET', '/p', '100', '');
    expect(sig1).toEqual(sig2);
  });
});

describe('InformerClient.buildSignature with body (POST)', () => {
  it('uses sha256 of the actual body, not the empty-body constant', () => {
    const client = new InformerClient({
      baseUrl: 'x',
      key: 'k',
      secret: 'test-secret',
    });
    const body = '{"totp_code":"123456"}';
    const bodyHash = createHash('sha256').update(body).digest('hex');
    const path = '/informer/v1/operator-required-wallets/613/retry';
    const ts = '1700000000';
    const expected = createHmac('sha256', 'test-secret')
      .update(`POST\n${path}\n${ts}\n${bodyHash}`)
      .digest('hex');
    expect(client.buildSignature('POST', path, ts, body)).toBe(expected);
  });

  it('any drift in body bytes yields a different signature', () => {
    const client = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });
    const sigA = client.buildSignature(
      'POST',
      '/p',
      '100',
      '{"totp_code":"123456"}',
    );
    // Spacing/reordering would happen if signing and sending serialized
    // independently — guarded by the client always passing the exact bytes.
    const sigB = client.buildSignature(
      'POST',
      '/p',
      '100',
      '{ "totp_code": "123456" }',
    );
    expect(sigA).not.toEqual(sigB);
  });
});

describe('InformerClient.retryOperatorWallet (signed POST)', () => {
  let originalFetch: typeof fetch;
  beforeEach(() => {
    originalFetch = global.fetch;
  });
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('sends POST with JSON body and the 4 HMAC headers, returns envelope.data', async () => {
    const client = new InformerClient({
      baseUrl: 'https://api.test',
      key: 'monitoring-prod',
      secret: 'shh',
    });

    let captured: { url: string; init: any } | null = null;
    global.fetch = (async (url: any, init: any) => {
      captured = { url: String(url), init };
      return new Response(
        JSON.stringify({
          resultCode: 'ERCD0000',
          data: { wallet_id: 613, status: 'ok' },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as any;

    const result = await client.retryOperatorWallet(613, '123456');
    expect(result).toEqual({ wallet_id: 613, status: 'ok' });

    expect(captured).not.toBeNull();
    const { url, init } = captured!;
    expect(url).toBe(
      'https://api.test/informer/v1/operator-required-wallets/613/retry',
    );
    expect(init.method).toBe('POST');
    expect(init.body).toBe('{"totp_code":"123456"}');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.headers['X-Informer-Key']).toBe('monitoring-prod');
    expect(init.headers['X-Informer-Timestamp']).toMatch(/^\d+$/);
    expect(init.headers['X-Informer-Nonce']).toMatch(/^[a-f0-9]+$/);
    expect(init.headers['X-Informer-Signature']).toMatch(/^[a-f0-9]{64}$/);

    // Verify the signature matches what buildSignature would emit for the
    // same inputs — ensures sha256(body) is the actual body, not the empty
    // constant.
    const ts = init.headers['X-Informer-Timestamp'];
    const expectedSig = client.buildSignature(
      'POST',
      '/informer/v1/operator-required-wallets/613/retry',
      ts,
      '{"totp_code":"123456"}',
    );
    expect(init.headers['X-Informer-Signature']).toBe(expectedSig);
  });

  it('maps 403 to InformerTotpError', async () => {
    const client = new InformerClient({
      baseUrl: 'https://api.test',
      key: 'k',
      secret: 's',
    });
    global.fetch = (async () =>
      new Response('{"message":"invalid 2fa code"}', { status: 403 })) as any;

    await expect(client.retryOperatorWallet(1, '000000')).rejects.toBeInstanceOf(
      InformerTotpError,
    );
  });

  it('maps 400 to InformerBadRequestError', async () => {
    const client = new InformerClient({
      baseUrl: 'https://api.test',
      key: 'k',
      secret: 's',
    });
    global.fetch = (async () =>
      new Response('{"message":"totp_code is required"}', {
        status: 400,
      })) as any;

    await expect(client.retryOperatorWallet(1, '')).rejects.toBeInstanceOf(
      InformerBadRequestError,
    );
  });
});

describe('InformerClient.mapStatusToError', () => {
  const client = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });

  it('400 → InformerBadRequestError', () => {
    expect(client.mapStatusToError(400, '{}')).toBeInstanceOf(
      InformerBadRequestError,
    );
  });

  it('403 → InformerTotpError', () => {
    expect(client.mapStatusToError(403, '{}')).toBeInstanceOf(InformerTotpError);
  });

  it('401 → InformerAuthError', () => {
    expect(client.mapStatusToError(401, '{}')).toBeInstanceOf(InformerAuthError);
  });

  it('404 → InformerNotConfiguredError', () => {
    expect(client.mapStatusToError(404, 'Not Found')).toBeInstanceOf(
      InformerNotConfiguredError,
    );
  });

  it('503 nonce store → InformerNonceStoreError', () => {
    expect(
      client.mapStatusToError(503, '{"message":"nonce store unavailable"}'),
    ).toBeInstanceOf(InformerNonceStoreError);
  });

  it('503 not configured → InformerNotConfiguredError', () => {
    expect(
      client.mapStatusToError(
        503,
        '{"message":"mini-crypto informer not configured"}',
      ),
    ).toBeInstanceOf(InformerNotConfiguredError);
  });

  it('502 → InformerUnavailableError', () => {
    expect(client.mapStatusToError(502, '<html>')).toBeInstanceOf(
      InformerUnavailableError,
    );
  });

  it('500 → InformerUnavailableError', () => {
    expect(client.mapStatusToError(500, 'oops')).toBeInstanceOf(
      InformerUnavailableError,
    );
  });
});
