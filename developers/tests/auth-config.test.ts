import { describe, it, expect } from 'vitest';
import { authConfig } from '../src/auth-config';

describe('authConfig', () => {
  it('logs in on the server that serves the portal, not on the SDK default', () => {
    // Без явного issuer SDK уводит на TEST (id.taler.tirol), и портал на
    // talerid.io отправлял людей входить в чужое окружение.
    expect(authConfig('https://talerid.io')).toEqual({
      clientId: 'taler-id-developers',
      redirectUri: 'https://talerid.io/developers/',
      issuer: 'https://talerid.io/oauth',
    });
  });

  it('follows the origin on every environment', () => {
    expect(authConfig('https://staging.id.taler.tirol').issuer).toBe(
      'https://staging.id.taler.tirol/oauth',
    );
  });
});
