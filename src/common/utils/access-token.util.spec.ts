import { isApiAccessToken, ACCESS_TOKEN_TYPE } from './access-token.util';

// Shape produced by AuthService.generateTokens after the `typ` claim was added.
const ACCESS_TOKEN = {
  sub: 'user-1',
  email: 'user@example.com',
  phone: null,
  kyc_status: 'VERIFIED',
  session_id: 'session-1',
  typ: ACCESS_TOKEN_TYPE,
};

// Shape of an OIDC ID token minted by oidc-provider with the same key pair.
const ID_TOKEN = {
  sub: 'user-1',
  aud: 'client-abc',
  iss: 'https://id.taler.tirol/oauth',
  exp: 1_900_000_000,
  iat: 1_899_996_400,
  sid: 'oidc-session-1',
};

describe('isApiAccessToken', () => {
  it('accepts an access token issued by AuthService', () => {
    expect(isApiAccessToken(ACCESS_TOKEN)).toBe(true);
  });

  it('rejects an OIDC ID token signed with the same key', () => {
    expect(isApiAccessToken(ID_TOKEN)).toBe(false);
  });

  it('rejects an OIDC token even when it also claims typ', () => {
    // A client cannot set claims on a provider-issued token, but the aud/iss
    // pair must not become acceptable just because typ is present.
    expect(isApiAccessToken({ ...ID_TOKEN, typ: 'id' })).toBe(false);
  });

  it('accepts a legacy access token minted before the typ claim existed', () => {
    const { typ, ...legacy } = ACCESS_TOKEN;
    expect(isApiAccessToken(legacy)).toBe(true);
  });

  it('rejects a legacy-shaped token that carries aud', () => {
    const { typ, ...legacy } = ACCESS_TOKEN;
    expect(isApiAccessToken({ ...legacy, aud: 'client-abc' })).toBe(false);
  });

  it('rejects a legacy-shaped token that carries iss', () => {
    const { typ, ...legacy } = ACCESS_TOKEN;
    expect(isApiAccessToken({ ...legacy, iss: 'https://elsewhere' })).toBe(
      false,
    );
  });

  it('rejects the password-reset token, which has no sub', () => {
    expect(
      isApiAccessToken({ email: 'user@example.com', purpose: 'password_reset' }),
    ).toBe(false);
  });

  it('rejects payloads without a usable sub', () => {
    expect(isApiAccessToken({ ...ACCESS_TOKEN, sub: '' })).toBe(false);
    expect(isApiAccessToken({ ...ACCESS_TOKEN, sub: 42 })).toBe(false);
    expect(isApiAccessToken({ ...ACCESS_TOKEN, sub: undefined })).toBe(false);
  });

  it('rejects non-object payloads', () => {
    expect(isApiAccessToken(null)).toBe(false);
    expect(isApiAccessToken(undefined)).toBe(false);
    expect(isApiAccessToken('token')).toBe(false);
  });
});
