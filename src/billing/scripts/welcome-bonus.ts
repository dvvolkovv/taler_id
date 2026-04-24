import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';
import { WalletService } from '../../blockchain/wallet.service';

async function main() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const prisma = app.get(PrismaService);
  const ledger = app.get(LedgerService);
  const wallet = app.get(WalletService);

  const cfg = await prisma.billingConfig.findUnique({ where: { id: 'singleton' } });
  if (!cfg) throw new Error('billing config not seeded');
  const amount = cfg.welcomeBonusPlanck;
  console.log(`welcome bonus amount: ${amount} planck`);

  const users = await prisma.user.findMany({
    where: { deletedAt: null },
    select: { id: true },
  });
  console.log(`${users.length} live users`);

  let credited = 0;
  let skipped = 0;
  let failed = 0;

  for (const u of users) {
    // Idempotency: skip if user already received an initial_bonus ADMIN_CREDIT
    const already = await prisma.billingTransaction.findFirst({
      where: {
        userId: u.id,
        type: 'ADMIN_CREDIT',
        metadata: { path: ['source'], equals: 'initial_bonus' },
      },
    });
    if (already) {
      skipped++;
      continue;
    }

    try {
      // Ensure wallet exists first (credit() requires a wallet row)
      await wallet.getOrCreate(u.id);
      await ledger.credit(u.id, amount, 'ADMIN_CREDIT', {
        source: 'initial_bonus',
        reason: 'welcome bonus at billing enforcement turn-on',
      });
      credited++;
      if (credited % 10 === 0) console.log(`...${credited} credited`);
    } catch (err) {
      failed++;
      console.error(`failed to credit user ${u.id}: ${String(err)}`);
    }
  }

  console.log(`credited ${credited}, skipped ${skipped} (already bonused), failed ${failed}`);
  await app.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
