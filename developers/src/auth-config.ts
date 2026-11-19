/** Login settings for the portal on whichever server serves it. */
export function authConfig(origin: string) {
  return {
    clientId: 'taler-id-developers',
    redirectUri: `${origin}/developers/`,
    // The SDK's default issuer is TEST (id.taler.tirol): without this the
    // portal on talerid.io sent people to log in on TEST. Every environment
    // serves /oauth next to /developers/, so the page's own origin is right.
    issuer: `${origin}/oauth`,
  };
}
