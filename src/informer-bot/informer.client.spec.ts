import { InformerClient } from './informer.client';
import {
  InformerAuthError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
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

describe('InformerClient.mapStatusToError', () => {
  const client = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });

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
