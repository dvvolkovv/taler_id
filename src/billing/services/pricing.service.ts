import { Injectable, NotFoundException } from '@nestjs/common';
import { AiPricebook, BillingConfig, Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

const CACHE_TTL_MS = 60_000;
const PLANCK_PER_TAL = new Prisma.Decimal('1e12');

/**
 * PricingService converts feature usage into planck cost using:
 *   planck = ceil(units × costUsdPerUnit × markupMultiplier / talUsdRate × 1e12)
 *
 * All multiplications/divisions use Prisma.Decimal (decimal.js) for exact
 * decimal arithmetic; we only touch BigInt at the final conversion.
 *
 * Cache is process-local with a 60s TTL. Admin routes call `invalidateCache()`
 * after writes. If this service is ever run in a multi-instance cluster,
 * broadcast invalidation via Redis pub/sub.
 */
@Injectable()
export class PricingService {
  private pricebookCache = new Map<string, { row: AiPricebook; ts: number }>();
  private configCache: { row: BillingConfig; ts: number } | null = null;

  constructor(private readonly prisma: PrismaService) {}

  invalidateCache(): void {
    this.pricebookCache.clear();
    this.configCache = null;
  }

  async getPricebook(featureKey: string): Promise<AiPricebook> {
    const cached = this.pricebookCache.get(featureKey);
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) return cached.row;

    const row = await this.prisma.aiPricebook.findUnique({
      where: { featureKey },
    });
    if (!row) throw new NotFoundException(`Unknown feature ${featureKey}`);
    this.pricebookCache.set(featureKey, { row, ts: Date.now() });
    return row;
  }

  async getConfig(): Promise<BillingConfig> {
    if (this.configCache && Date.now() - this.configCache.ts < CACHE_TTL_MS) {
      return this.configCache.row;
    }
    const row = await this.prisma.billingConfig.findUnique({
      where: { id: 'singleton' },
    });
    if (!row) throw new NotFoundException('Billing config not seeded');
    this.configCache = { row, ts: Date.now() };
    return row;
  }

  async calculatePlanckCost(
    featureKey: string,
    units: number,
  ): Promise<bigint> {
    if (!Number.isFinite(units) || units < 0) {
      throw new Error(
        `units must be a non-negative finite number, got ${units}`,
      );
    }
    const [pb, cfg] = await Promise.all([
      this.getPricebook(featureKey),
      this.getConfig(),
    ]);

    const costUsd = new Prisma.Decimal(units)
      .mul(pb.costUsdPerUnit)
      .mul(pb.markupMultiplier);
    const costTal = costUsd.div(cfg.talUsdRate);
    const planck = costTal.mul(PLANCK_PER_TAL).ceil();
    return BigInt(planck.toFixed(0));
  }

  async getMinReservePlanck(featureKey: string): Promise<bigint> {
    const pb = await this.getPricebook(featureKey);
    return pb.minReservePlanck;
  }
}
