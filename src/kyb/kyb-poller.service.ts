import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import type { KycStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { KycService } from '../kyc/kyc.service';
import { mapWelidCompany } from './welid-company.mapper';

/** Ручная проверка компании в welID может идти днями. */
const PENDING_WINDOW_DAYS = 30;

/**
 * Статус KYB компании и снимок её реквизитов — опросом welID.
 *
 * Вебхука KYB нет ни на одном окружении: TenantService.handleKybWebhook ни к
 * чему не подключён, а вебхук welID на TEST приходит в обработчик KYC людей.
 * Поэтому компания не становилась проверенной нигде. Спека
 * 2026-11-19-companies-oauth-design.md, часть 1.
 */
@Injectable()
export class KybPollerService {
  private readonly logger = new Logger(KybPollerService.name);
  /** До 50 запросов по 8 с — круг может пережить минуту; не накладываем. */
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly kyc: KycService,
  ) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async pollCompanies() {
    if (this.running) return;
    this.running = true;
    try {
      await this.pollRound();
    } finally {
      this.running = false;
    }
  }

  private async pollRound() {
    const since = new Date(Date.now() - PENDING_WINDOW_DAYS * 24 * 60 * 60 * 1000);
    const tenants = await this.prisma.tenant.findMany({
      where: {
        OR: [
          { kybStatus: 'PENDING', updatedAt: { gte: since } },
          // одобренные вручную (админка) или до появления снимков
          { kybStatus: 'VERIFIED', kybProfile: { is: null } },
        ],
      },
      select: { id: true, kybStatus: true },
      take: 50,
    });
    for (const t of tenants) {
      try {
        await this.syncTenant(t.id, t.kybStatus);
      } catch (e) {
        this.logger.warn(`KYB poll failed for tenant ${t.id}: ${e}`);
      }
    }
  }

  async syncTenant(tenantId: string, status: KycStatus) {
    const applicant = await this.kyc.getApplicantByExternalUserId(tenantId);
    const answer = applicant?.review?.reviewResult?.reviewAnswer;
    if (!applicant?.id || !answer) return;

    if (answer === 'RED') {
      if (status !== 'PENDING') return;
      await this.prisma.tenant.updateMany({
        where: { id: tenantId, kybStatus: 'PENDING' },
        data: { kybStatus: 'REJECTED', sumsubApplicantId: applicant.id },
      });
      this.logger.log(`KYB poll: tenant=${tenantId} → REJECTED`);
      return;
    }
    if (answer !== 'GREEN') return;

    // Без данных компании снимок всё равно пишем (пустые поля + сырой ответ):
    // иначе VERIFIED без снимка опрашивался бы по кругу.
    const { raw, ...fields } = mapWelidCompany(applicant);
    const data = { ...fields, raw: raw as object, verifiedAt: new Date() };
    await this.prisma.$transaction([
      this.prisma.tenant.update({
        where: { id: tenantId },
        data: { kybStatus: 'VERIFIED', sumsubApplicantId: applicant.id },
      }),
      this.prisma.companyKybProfile.upsert({
        where: { tenantId },
        create: { tenantId, ...data },
        update: data,
      }),
    ]);
    this.logger.log(`KYB poll: tenant=${tenantId} → VERIFIED (snapshot saved)`);
  }
}
