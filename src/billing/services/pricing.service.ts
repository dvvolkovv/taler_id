import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

const CACHE_TTL_MS = 60_000;

type PricebookRow = {
  featureKey: string;
  unit: string;
  costUsdPerUnit: string | number | bigint | { toString(): string };
  markupMultiplier: string | number | bigint | { toString(): string };
  minReservePlanck: bigint;
};

type ConfigRow = {
  talUsdRate: string | number | bigint | { toString(): string };
};

@Injectable()
export class PricingService {
  private pricebookCache = new Map<string, { row: PricebookRow; ts: number }>();
  private configCache: { row: ConfigRow; ts: number } | null = null;

  constructor(private readonly prisma: PrismaService) {}

  invalidateCache(): void {
    this.pricebookCache.clear();
    this.configCache = null;
  }

  async getPricebook(featureKey: string): Promise<PricebookRow> {
    const cached = this.pricebookCache.get(featureKey);
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) return cached.row;

    const row = await this.prisma.aiPricebook.findUnique({ where: { featureKey } });
    if (!row) throw new NotFoundException(`unknown feature ${featureKey}`);
    this.pricebookCache.set(featureKey, { row: row as unknown as PricebookRow, ts: Date.now() });
    return row as unknown as PricebookRow;
  }

  async getConfig(): Promise<ConfigRow> {
    if (this.configCache && Date.now() - this.configCache.ts < CACHE_TTL_MS) {
      return this.configCache.row;
    }
    const row = await this.prisma.billingConfig.findUnique({ where: { id: 'singleton' } });
    if (!row) throw new NotFoundException('billing config not seeded');
    this.configCache = { row: row as unknown as ConfigRow, ts: Date.now() };
    return row as unknown as ConfigRow;
  }

  async calculatePlanckCost(featureKey: string, units: number): Promise<bigint> {
    const [pb, cfg] = await Promise.all([this.getPricebook(featureKey), this.getConfig()]);

    const costUsd =
      units * Number(pb.costUsdPerUnit.toString()) * Number(pb.markupMultiplier.toString());
    const talRate = Number(cfg.talUsdRate.toString());
    const costTal = costUsd / talRate;
    const planckFloat = costTal * 1e12;
    return BigInt(Math.ceil(planckFloat));
  }

  async getMinReservePlanck(featureKey: string): Promise<bigint> {
    const pb = await this.getPricebook(featureKey);
    return pb.minReservePlanck;
  }
}
