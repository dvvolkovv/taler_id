import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  UseFilters,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';
import { PricingService } from '../services/pricing.service';
import { WalletService } from '../../blockchain/wallet.service';
import { BillingExceptionFilter } from '../filters/billing-exception.filter';
import { PACKAGES, PACKAGES_BY_ID } from '../constants/packages';
import { ALL_FEATURE_KEYS, FeatureKey } from '../constants/feature-keys';
import { UpdateToggleDto } from '../dto/toggle.dto';

function planckToMicroTal(p: bigint): string {
  const whole = p / 1_000_000n;
  const frac = Number(p % 1_000_000n) / 1_000_000;
  return (Number(whole) + frac).toFixed(2);
}

@Controller('billing')
@UseGuards(JwtAuthGuard)
@UseFilters(BillingExceptionFilter)
export class BillingController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
    private readonly wallet: WalletService,
  ) {}

  @Get('balance')
  async getBalance(@CurrentUser() user: any) {
    const userId = user.sub;
    const [balance, txs] = await Promise.all([
      this.ledger.getBalance(userId),
      this.prisma.billingTransaction.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: 10,
      }),
    ]);
    return {
      balancePlanck: balance.toString(),
      balanceMicroTal: planckToMicroTal(balance),
      recentTx: txs.map((t) => ({
        id: t.id,
        type: t.type,
        amountPlanck: t.amountPlanck.toString(),
        featureKey: t.featureKey,
        createdAt: t.createdAt.toISOString(),
      })),
    };
  }

  @Get('packages')
  async getPackages() {
    return PACKAGES.map((p) => ({
      ...p,
      amountPlanck: p.amountPlanck.toString(),
    }));
  }

  @Post('purchase/:pkgId')
  async purchase(@CurrentUser() user: any, @Param('pkgId') pkgId: string) {
    const userId = user.sub;
    const pkg = PACKAGES_BY_ID[pkgId];
    if (!pkg) throw new NotFoundException(`unknown package ${pkgId}`);

    // Ensure a wallet exists before crediting; credit() requires UserWallet to exist.
    await this.wallet.getOrCreate(userId);

    const tx = await this.ledger.credit(userId, pkg.amountPlanck, 'TOPUP_STUB', {
      packageId: pkgId,
      source: 'stub',
    });
    const newBalance = await this.ledger.getBalance(userId);
    return {
      txId: tx.id,
      newBalancePlanck: newBalance.toString(),
      packageId: pkgId,
    };
  }

  @Get('wallet')
  async getWallet(@CurrentUser() user: any) {
    const userId = user.sub;
    const w = await this.wallet.getOrCreate(userId);
    return { custodialAddress: w.custodialAddress };
  }

  @Get('transactions')
  async getTransactions(@CurrentUser() user: any) {
    const userId = user.sub;
    const txs = await this.prisma.billingTransaction.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
    return txs.map((t) => ({
      id: t.id,
      type: t.type,
      status: t.status,
      amountPlanck: t.amountPlanck.toString(),
      featureKey: t.featureKey,
      sessionId: t.sessionId,
      metadata: t.metadata,
      createdAt: t.createdAt.toISOString(),
    }));
  }

  @Get('pricebook')
  async getPricebook() {
    const rows = await this.prisma.aiPricebook.findMany();
    return rows.map((r) => ({
      featureKey: r.featureKey,
      unit: r.unit,
      costUsdPerUnit: r.costUsdPerUnit.toString(),
      markupMultiplier: r.markupMultiplier.toString(),
      minReservePlanck: r.minReservePlanck.toString(),
    }));
  }

  @Get('settings/toggles')
  async getToggles(@CurrentUser() user: any) {
    const userId = user.sub;
    const rows = await this.prisma.userFeatureToggle.findMany({ where: { userId } });
    const map = new Map(rows.map((r) => [r.featureKey, r.enabled]));
    return ALL_FEATURE_KEYS.map((f) => ({
      featureKey: f,
      enabled: map.has(f) ? map.get(f)! : true,
    }));
  }

  @Patch('settings/toggles/:featureKey')
  async patchToggle(
    @CurrentUser() user: any,
    @Param('featureKey') featureKey: string,
    @Body() body: UpdateToggleDto,
  ) {
    const userId = user.sub;
    if (!ALL_FEATURE_KEYS.includes(featureKey as FeatureKey)) {
      throw new NotFoundException(`unknown feature ${featureKey}`);
    }
    await this.prisma.userFeatureToggle.upsert({
      where: { userId_featureKey: { userId, featureKey } },
      create: { userId, featureKey, enabled: body.enabled },
      update: { enabled: body.enabled },
    });
    return { featureKey, enabled: body.enabled };
  }
}
