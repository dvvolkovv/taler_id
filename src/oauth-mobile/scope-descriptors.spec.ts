import { describeScopes, KNOWN_SCOPES } from './scope-descriptors';

describe('scope-descriptors', () => {
  it('returns descriptors for known scopes', () => {
    const result = describeScopes(['profile', 'email']);
    expect(result).toEqual([
      { key: 'profile', label: 'Профиль', description: 'Имя, фамилия, аватар' },
      { key: 'email', label: 'Email', description: 'Email адрес' },
    ]);
  });

  it('falls back to capitalised key for unknown scopes', () => {
    const result = describeScopes(['custom_scope']);
    expect(result).toEqual([
      { key: 'custom_scope', label: 'custom_scope', description: 'Доступ к custom_scope' },
    ]);
  });

  it('preserves order of input', () => {
    const result = describeScopes(['email', 'profile', 'openid']);
    expect(result.map((s) => s.key)).toEqual(['email', 'profile', 'openid']);
  });

  it('exposes KNOWN_SCOPES constant for tests', () => {
    expect(Object.keys(KNOWN_SCOPES)).toEqual(
      expect.arrayContaining(['openid', 'profile', 'email', 'offline_access']),
    );
  });
});
