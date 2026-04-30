import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { WalletService } from '../../blockchain/wallet.service';

async function main() {
  const app = await NestFactory.createApplicationContext(AppModule);
  try {
    const prisma = app.get(PrismaService);
    const wallet = app.get(WalletService);

    const users = await prisma.user.findMany({
      where: { wallet: null, deletedAt: null },
      select: { id: true },
    });
    console.log(`${users.length} users need a wallet`);

    let created = 0;
    for (const u of users) {
      try {
        await wallet.getOrCreate(u.id);
        created++;
        if (created % 10 === 0) console.log(`...${created}`);
      } catch (err) {
        console.error(
          `failed to create wallet for user ${u.id}: ${String(err)}`,
        );
      }
    }
    console.log(`created ${created} wallets`);
  } finally {
    await app.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
