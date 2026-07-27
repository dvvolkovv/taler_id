/**
 * Marker claim added to API access tokens by `AuthService.generateTokens`.
 */
export const ACCESS_TOKEN_TYPE = 'access';

/**
 * Distinguishes our API access tokens from other JWTs that carry a valid
 * signature.
 *
 * The OIDC provider signs its ID tokens (and any JWT-format access tokens) with
 * the SAME RS256 key pair as the API — `oidc.module.ts` reads the provider key
 * from `jwt.privateKeyPath`. So a good signature alone proves nothing about who
 * minted the token: an ID token issued to an OAuth client for the `openid`
 * scope would otherwise be accepted as a full-privilege API bearer, bypassing
 * the whole scope model.
 *
 * Two rules separate them:
 *  - our access tokens carry `typ: 'access'`;
 *  - an OIDC-issued token always carries `aud` (the client_id) and `iss`, which
 *    our tokens never set.
 *
 * The second rule exists so tokens minted before `typ` was introduced keep
 * working — deploying this does not sign anyone out. Once every pre-existing
 * access token has expired (2h TTL), the legacy branch can be dropped and the
 * check tightened to `typ === ACCESS_TOKEN_TYPE` alone.
 */
export function isApiAccessToken(payload: unknown): boolean {
  if (!payload || typeof payload !== 'object') return false;

  const claims = payload as Record<string, unknown>;

  // Every authenticated route resolves the caller through `sub`.
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) return false;

  if (claims.typ === ACCESS_TOKEN_TYPE) return true;

  // Legacy token: accept only when it carries none of the claims that an
  // OIDC-issued token always has.
  return (
    claims.typ === undefined &&
    claims.aud === undefined &&
    claims.iss === undefined
  );
}
