/**
 * Idempotent seed for the linkeon-partner verifiedPartner OAuth client.
 *
 * The live client_secret lives in env (LINKEON_PARTNER_CLIENT_SECRET), read by
 * the OIDC client adapter — the DB row only needs to exist with verifiedPartner
 * + allowedScopes, so this stores a non-secret placeholder in clientSecret.
 *
 * Run against the target DB (DEV first):
 *   npx ts-node scripts/seed-linkeon-partner.ts
 *
 * Adding scopes later (e.g. mail): set LINKEON_PARTNER_SCOPES and re-run.
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const scopes = (
    process.env.LINKEON_PARTNER_SCOPES || 'openid mcp:calendar offline_access'
  )
    .split(/\s+/)
    .filter(Boolean);

  const client = await prisma.oAuthClient.upsert({
    where: { clientId: 'linkeon-partner' },
    update: {
      verifiedPartner: true,
      isDynamic: false,
      allowedScopes: scopes,
      name: 'Linkeon Partner (verified)',
    },
    create: {
      clientId: 'linkeon-partner',
      clientSecret: 'env:LINKEON_PARTNER_CLIENT_SECRET',
      name: 'Linkeon Partner (verified)',
      redirectUris: [],
      allowedScopes: scopes,
      verifiedPartner: true,
      isDynamic: false,
    },
  });

  console.log('linkeon-partner client ready:', {
    clientId: client.clientId,
    verifiedPartner: client.verifiedPartner,
    isDynamic: client.isDynamic,
    allowedScopes: client.allowedScopes,
    secretSource: process.env.LINKEON_PARTNER_CLIENT_SECRET
      ? 'env (LINKEON_PARTNER_CLIENT_SECRET)'
      : 'DB placeholder — SET THE ENV VAR, auth will fail otherwise',
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
