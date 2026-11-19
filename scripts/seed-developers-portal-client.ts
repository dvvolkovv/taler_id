/**
 * Idempotent seed for the Developer Portal's own login client
 * (taler-id-developers): public SPA at /developers/, code flow + PKCE.
 *
 * Redirect URIs differ per environment, so they come from
 * DEVELOPERS_PORTAL_REDIRECT_URIS (comma-separated) and there is no default.
 * The same list is used for logout (see PrismaClientAdapter.find).
 *
 * PROD's row was copied from aeza along with the rest of the data and only
 * allowed aeza pages, so login on talerid.io failed with invalid_redirect_uri.
 * Another resync from aeza overwrites the row again — re-run this after one.
 *
 *   DEVELOPERS_PORTAL_REDIRECT_URIS="https://talerid.io/developers/,https://api.talerid.io/developers/" \
 *     npx ts-node -r dotenv/config scripts/seed-developers-portal-client.ts
 */
import { randomBytes } from 'crypto';
import { PrismaClient } from '@prisma/client';

const CLIENT_ID = 'taler-id-developers';

function parseRedirectUris(raw: string | undefined): string[] {
  const uris = (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (uris.length === 0) {
    throw new Error('DEVELOPERS_PORTAL_REDIRECT_URIS is empty — pass this environment\'s portal pages');
  }
  for (const uri of uris) {
    const url = new URL(uri);
    if (url.protocol !== 'https:' || url.pathname !== '/developers/' || url.search || url.hash) {
      throw new Error(`Not a portal page: ${uri} (expected https://<host>/developers/)`);
    }
  }
  return uris;
}

const prisma = new PrismaClient();

async function main() {
  const redirectUris = parseRedirectUris(process.env.DEVELOPERS_PORTAL_REDIRECT_URIS);

  const before = await prisma.oAuthClient.findUnique({
    where: { clientId: CLIENT_ID },
    select: { redirectUris: true },
  });

  const client = await prisma.oAuthClient.upsert({
    where: { clientId: CLIENT_ID },
    update: { redirectUris },
    create: {
      clientId: CLIENT_ID,
      // Public client: the adapter advertises token_endpoint_auth_method=none,
      // so this secret is never checked. The column is just NOT NULL.
      clientSecret: randomBytes(32).toString('base64'),
      name: 'Taler ID Developer Portal',
      redirectUris,
      allowedScopes: ['openid', 'profile', 'email', 'offline_access'],
      isDynamic: false,
    },
  });

  console.log(`${CLIENT_ID} client ready:`, {
    redirectUrisBefore: before?.redirectUris ?? '(created)',
    redirectUris: client.redirectUris,
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
