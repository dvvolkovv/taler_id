import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import type { KycStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { KycService } from '../kyc/kyc.service';
import { mapWelidCompany } from './welid-company.mapper';

/**
 * Ручная проверка компании в welID может идти днями; дальше окна не опрашиваем
 * ни ожидающих, ни одобренных без снимка.
 */
const POLL_WINDOW_DAYS = 30;

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
    const since = new Date(Date.now() - POLL_WINDOW_DAYS * 24 * 60 * 60 * 1000);
    const tenants = await this.prisma.tenant.findMany({
      where: {
        OR: [
          { kybStatus: 'PENDING', updatedAt: { gte: since } },
          // Одобренные вручную (админка) или до перехода на welID: GREEN у них
          // в welID может не появиться никогда — окно, чтобы не опрашивать вечно.
          { kybStatus: 'VERIFIED', kybProfile: { is: null }, updatedAt: { gte: since } },
        ],
      },
      select: { id: true, kybStatus: true },
      orderBy: { updatedAt: 'desc' },
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
    const review = applicant?.review;
    // Пока анкета на повторной проверке, reviewResult — старое решение.
    if (review?.reviewStatus !== 'completed') return;
    const answer = review.reviewResult?.reviewAnswer;
    if (!answer) return;

    const { raw, ...fields } = mapWelidCompany(applicant);
    if (!fields.applicantId) return;

    if (answer === 'RED') {
      // RETRY — компания может исправить и отправить заново, это ещё не отказ.
      const rejectType = review.reviewResult?.reviewRejectType;
      if (rejectType && rejectType !== 'FINAL') return;
      if (status !== 'PENDING') return;
      const r = await this.prisma.tenant.updateMany({
        where: { id: tenantId, kybStatus: 'PENDING' },
        data: { kybStatus: 'REJECTED', sumsubApplicantId: fields.applicantId },
      });
      if (r.count > 0) this.logger.log(`KYB poll: tenant=${tenantId} → REJECTED`);
      return;
    }
    if (answer !== 'GREEN') return;

    // Без данных компании снимок всё равно пишем (пустые поля + сырой ответ):
    // иначе VERIFIED без снимка опрашивался бы по кругу.
    const data = { ...fields, raw: raw as object, verifiedAt: reviewDate(review.reviewDate) };
    const saved = await this.prisma.$transaction(async (tx) => {
      // Решение админа, принятое за время запроса к welID, не перебиваем.
      const r = await tx.tenant.updateMany({
        where: { id: tenantId, kybStatus: { in: ['PENDING', 'VERIFIED'] } },
        data: { kybStatus: 'VERIFIED', sumsubApplicantId: fields.applicantId },
      });
      if (r.count !== 1) return false;
      await tx.companyKybProfile.upsert({
        where: { tenantId },
        create: { tenantId, ...data },
        update: data,
      });
      return true;
    });
    if (saved) this.logger.log(`KYB poll: tenant=${tenantId} → VERIFIED (snapshot saved)`);
  }
}

/** Дата решения welID; не разобралась — момент записи снимка. */
function reviewDate(v: unknown): Date {
  if (typeof v === 'string' || typeof v === 'number') {
    const d = new Date(v);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return new Date();
}
