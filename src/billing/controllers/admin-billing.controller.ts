import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';
import { PricingService } from '../services/pricing.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import {
  AdminCreditDto,
  AdminDebitDto,
  AdminUpdatePricebookDto,
  AdminUpdateConfigDto,
} from '../dto/admin.dto';

@Controller('admin/billing')
@UseGuards(JwtAuthGuard)
export class AdminBillingController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
  ) {}

  private async assertAdmin(userId: string): Promise<void> {
    const u = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { isAdmin: true },
    });
    if (!u?.isAdmin) throw new ForbiddenException('admin only');
  }

  @Get('users/:id')
  async getUser(@CurrentUser() actor: any, @Param('id') targetId: string) {
    await this.assertAdmin(actor.sub ?? actor.id);

    const [wallet, txs, sessions] = await Promise.all([
      this.prisma.userWallet.findUnique({ where: { userId: targetId } }),
      this.prisma.billingTransaction.findMany({
        where: { userId: targetId },
        orderBy: { createdAt: 'desc' },
        take: 50,
      }),
      this.prisma.aiSession.findMany({
        where: { userId: targetId },
        orderBy: { startedAt: 'desc' },
        take: 20,
      }),
    ]);

    return {
      wallet: wallet
        ? {
            address: wallet.custodialAddress,
            balancePlanck: wallet.balancePlanck.toString(),
          }
        : null,
      transactions: txs.map((t) => ({
        id: t.id,
        type: t.type,
        status: t.status,
        amountPlanck: t.amountPlanck.toString(),
        featureKey: t.featureKey,
        sessionId: t.sessionId,
        metadata: t.metadata,
        createdAt: t.createdAt.toISOString(),
      })),
      sessions: sessions.map((s) => ({
        id: s.id,
        featureKey: s.featureKey,
        status: s.status,
        startedAt: s.startedAt.toISOString(),
        endedAt: s.endedAt?.toISOString() ?? null,
        totalSpentPlanck: s.totalSpentPlanck.toString(),
        contextRef: s.contextRef,
      })),
    };
  }

  @Post('users/:id/credit')
  async credit(
    @CurrentUser() actor: any,
    @Param('id') targetId: string,
    @Body() body: AdminCreditDto,
  ) {
    const actorId = actor.sub ?? actor.id;
    await this.assertAdmin(actorId);

    const target = await this.prisma.user.findUnique({ where: { id: targetId } });
    if (!target) throw new NotFoundException(`user ${targetId} not found`);

    const tx = await this.ledger.credit(
      targetId,
      BigInt(body.amountPlanck),
      'ADMIN_CREDIT',
      { actor: actorId, reason: body.reason },
    );
    return { txId: tx.id };
  }

  @Post('users/:id/debit')
  async debit(
    @CurrentUser() actor: any,
    @Param('id') targetId: string,
    @Body() body: AdminDebitDto,
  ) {
    const actorId = actor.sub ?? actor.id;
    await this.assertAdmin(actorId);

    const target = await this.prisma.user.findUnique({ where: { id: targetId } });
    if (!target) throw new NotFoundException(`user ${targetId} not found`);

    const tx = await this.ledger.debit(targetId, BigInt(body.amountPlanck), 'ADMIN_DEBIT', {
      metadata: { actor: actorId, reason: body.reason },
    });
    return { txId: tx.id };
  }

  @Patch('pricebook/:featureKey')
  async updatePricebook(
    @CurrentUser() actor: any,
    @Param('featureKey') featureKey: string,
    @Body() body: AdminUpdatePricebookDto,
  ) {
    await this.assertAdmin(actor.sub ?? actor.id);

    const data: any = {};
    if (body.costUsdPerUnit !== undefined) data.costUsdPerUnit = body.costUsdPerUnit;
    if (body.markupMultiplier !== undefined) data.markupMultiplier = body.markupMultiplier;
    if (body.minReservePlanck !== undefined) data.minReservePlanck = BigInt(body.minReservePlanck);

    try {
      const row = await this.prisma.aiPricebook.update({
        where: { featureKey },
        data,
      });
      this.pricing.invalidateCache();
      return {
        featureKey: row.featureKey,
        unit: row.unit,
        costUsdPerUnit: row.costUsdPerUnit.toString(),
        markupMultiplier: row.markupMultiplier.toString(),
        minReservePlanck: row.minReservePlanck.toString(),
      };
    } catch (err: any) {
      // Prisma P2025 = record not found
      if (err?.code === 'P2025') {
        throw new NotFoundException(`unknown feature ${featureKey}`);
      }
      throw err;
    }
  }

  @Patch('config')
  async updateConfig(@CurrentUser() actor: any, @Body() body: AdminUpdateConfigDto) {
    await this.assertAdmin(actor.sub ?? actor.id);

    const data: any = {};
    if (body.talUsdRate !== undefined) data.talUsdRate = body.talUsdRate;
    if (body.billingEnforced !== undefined) data.billingEnforced = body.billingEnforced;
    if (body.welcomeBonusPlanck !== undefined) {
      data.welcomeBonusPlanck = BigInt(body.welcomeBonusPlanck);
    }

    const row = await this.prisma.billingConfig.update({
      where: { id: 'singleton' },
      data,
    });
    this.pricing.invalidateCache();
    return {
      talUsdRate: row.talUsdRate.toString(),
      billingEnforced: row.billingEnforced,
      welcomeBonusPlanck: row.welcomeBonusPlanck.toString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }
}
