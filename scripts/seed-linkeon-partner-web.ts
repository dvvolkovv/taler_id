/**
 * Idempotent seed for the linkeon-partner-web OAuth login client used by
 * account-linking (attach-phone). Public client (PKCE S256), code flow, scope
 * openid — only used to mint an id_token proving the user logged into their
 * existing TalerID account. NOT a verifiedPartner (no offline_access / MCP).
 *
 * Redirect URIs come from LINKEON_PARTNER_WEB_REDIRECT_URIS (comma-separated);
 * pass Linkeon's real callback(s). A placeholder + the e2e test URL are used
 * if unset. Re-run to update redirect_uris.
 *
 *   LINKEON_PARTNER_WEB_REDIRECT_URIS="https://my.linkeon.io/oauth/talerid/callback" \
 *     npx ts-node scripts/seed-linkeon-partner-web.ts
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const redirectUris = (
    process.env.LINKEON_PARTNER_WEB_REDIRECT_URIS ||
    'https://my.linkeon.io/oauth/talerid/callback,https://example.com/callback'
  )
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const client = await prisma.oAuthClient.upsert({
    where: { clientId: 'linkeon-partner-web' },
    update: {
      isDynamic: false,
      redirectUris,
      allowedScopes: ['openid', 'profile', 'email'],
      name: 'Linkeon Account Link (login)',
    },
    create: {
      clientId: 'linkeon-partner-web',
      clientSecret: 'public-client-no-secret',
      name: 'Linkeon Account Link (login)',
      redirectUris,
      allowedScopes: ['openid', 'profile', 'email'],
      verifiedPartner: false,
      isDynamic: false,
    },
  });

  console.log('linkeon-partner-web client ready:', {
    clientId: client.clientId,
    redirectUris: client.redirectUris,
    allowedScopes: client.allowedScopes,
    note: 'public client (token_endpoint_auth_method=none, PKCE S256)',
  });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
