import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding database...');

  // Seed WalletX OAuth client
  const walletxClient = await prisma.oAuthClient.upsert({
    where: { clientId: 'walletx' },
    update: {},
    create: {
      clientId: 'walletx',
      clientSecret: await bcrypt.hash('walletx_secret_2026', 12),
      name: 'WalletX Application',
      redirectUris: [
        'http://localhost:3001/auth/callback',
        'http://138.124.61.221:3001/auth/callback',
      ],
      allowedScopes: [
        'openid',
        'profile',
        'email',
        'phone',
        'kyc',
        'wallet',
        'offline_access',
      ],
      logoUri: null,
    },
  });

  console.log('Created OAuth client:', walletxClient.clientId);

  // Seed admin user (dev only)
  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@taler.id' },
    update: {},
    create: {
      email: 'admin@taler.id',
      passwordHash: await bcrypt.hash('Admin@2026!', 12),
      profile: {
        create: {
          firstName: 'Admin',
          lastName: 'Taler',
          language: 'en',
        },
      },
    },
  });

  console.log('Created admin user:', adminUser.email);
  console.log('Seeding complete.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
