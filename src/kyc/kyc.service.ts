import {
  Injectable,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { BlockchainService } from '../blockchain/blockchain.service';
import { ConfigService } from '@nestjs/config';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
import { verifyWebhookSignature } from './webhook-signature.util';
import { EmailService } from '../email/email.service';

export interface StartKycResponse {
  applicantId: string;
  webSdkUrl: string;
  sdkBaseUrl: string;
  status: string;
  expiresAt: string;
  /** legacy alias for older mobile clients (≤1.0.82) */
  sumsubApplicantId: string;
}

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private blockchain: BlockchainService,
    private email: EmailService,
  ) {}

  private get baseUrl(): string {
    return (
      process.env.SUMSUB_BASE_URL || 'https://mockss-test.up.railway.app'
    ).replace(/\/$/, '');
  }

  private get levelName(): string {
    return process.env.SUMSUB_LEVEL_NAME || 'trientes-kyc-level';
  }

  private get ttlInSecs(): number {
    const raw = parseInt(process.env.SUMSUB_TTL_SECS || '600', 10);
    return Number.isFinite(raw) && raw >= 60 && raw <= 3600 ? raw : 600;
  }

  async startKyc(userId: string): Promise<StartKycResponse> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const token = await this.issueAccessToken(userId);

    // Mock auto-creates the applicant on first token issue. Resolve its id so
    // we can correlate webhooks → KycRecord.
    const applicantId = await this.getApplicantByExternalId(userId);

    await this.prisma.kycRecord.upsert({
      where: { userId },
      create: { userId, sumsubApplicantId: applicantId, status: 'PENDING' },
      update: { sumsubApplicantId: applicantId, status: 'PENDING' },
    });

    const sdkBaseUrl = this.baseUrl;
    const webSdkUrl = `${sdkBaseUrl}/idensic/sdk/checkup?accessToken=${encodeURIComponent(token)}`;
    const expiresAt = new Date(
      Date.now() + this.ttlInSecs * 1000,
    ).toISOString();

    return {
      applicantId,
      sumsubApplicantId: applicantId,
      webSdkUrl,
      sdkBaseUrl,
      status: 'PENDING',
      expiresAt,
    };
  }

  async getKycStatus(userId: string) {
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    if (!kyc) return { status: 'UNVERIFIED' };

    // PENDING is set at /kyc/start, before the user actually walks the wizard.
    // If the provider says the applicant was never submitted for review
    // (init/prechecked), report UNVERIFIED + inProgress so clients re-show the
    // start/continue button instead of a dead-end "under review" screen.
    if (kyc.status === 'PENDING' && kyc.sumsubApplicantId) {
      try {
        const data = await this.apiGet(
          `/resources/applicants/${kyc.sumsubApplicantId}/one`,
        );
        const reviewStatus = data.review?.reviewStatus;
        if (reviewStatus === 'init' || reviewStatus === 'prechecked') {
          return {
            status: 'UNVERIFIED',
            inProgress: true,
            verifiedAt: null,
            rejectionReason: null,
          };
        }
      } catch {
        // provider unreachable — fall back to the DB status
      }
    }

    return {
      status: kyc.status,
      verifiedAt: kyc.verifiedAt,
      rejectionReason: kyc.rejectionReason,
    };
  }

  async handleWebhook(
    body: Buffer,
    signature: string,
    algorithmHeader?: string,
  ) {
    // This endpoint is public and unauthenticated, so the signature is the only
    // thing standing between a stranger and "this applicant is verified".
    const webhookSecret = process.env.SUMSUB_WEBHOOK_SECRET || '';
    if (!webhookSecret) {
      // Verification used to be skipped entirely when the secret was unset,
      // which turns the endpoint into an open door. All three environments set
      // it (checked); refuse rather than accept unsigned callbacks.
      this.logger.error(
        'KYC webhook rejected: SUMSUB_WEBHOOK_SECRET is not configured',
      );
      throw new BadRequestException('Webhook signature verification unavailable');
    }

    if (!verifyWebhookSignature(body, signature, algorithmHeader, webhookSecret)) {
      // Намеренно кратко: подробности превращали публичную ручку в оракул для
      // подбора подписи.
      this.logger.warn('KYC webhook rejected: signature mismatch');
      this.logSignatureDiagnostics(body, signature);
      throw new BadRequestException('Invalid webhook signature');
    }

    // С этого места отвечаем 200 на всё, что прошло подпись. У welid любой
    // не-2xx означает три повтора, а потом DLQ и ручной разбор — жаловаться на
    // тело, которое повтор не исправит, значит потерять событие.
    let payload: any;
    try {
      payload = JSON.parse(body.toString());
    } catch {
      this.logger.warn('KYC webhook: подписанное тело не разобралось как JSON');
      return { received: true };
    }

    const { applicantId, type, reviewResult } = payload || {};

    if (!applicantId) return { received: true };

    const kyc = await this.prisma.kycRecord.findFirst({
      where: { sumsubApplicantId: applicantId },
    });
    if (!kyc) return { received: true };

    const answer = reviewResult?.reviewAnswer;

    // applicantOnMonitoringUpdate — то же решение, но принятое уже после
    // одобрения: санкционное совпадение, истёкший документ. Без этой ветки
    // попавший в списки остаётся VERIFIED навсегда.
    if (type === 'applicantReviewed' || type === 'applicantOnMonitoringUpdate') {
      if (answer === 'GREEN') {
        await this.markVerified(kyc.id, kyc.userId);
      } else if (answer === 'RED') {
        const reason =
          reviewResult?.rejectLabels?.join(', ') || 'Verification failed';
        await this.markRejected(
          kyc.id,
          kyc.userId,
          reason,
          type === 'applicantOnMonitoringUpdate',
        );
      } else if (answer === 'YELLOW') {
        await this.markOnHold(kyc.id);
      }
    } else if (type === 'applicantOnHold') {
      // Решение отозвано на ручную проверку. Раньше событие проваливалось мимо
      // всех веток, и заявка продолжала показываться в прежнем статусе.
      await this.markOnHold(kyc.id);
    } else if (type === 'applicantPending') {
      await this.prisma.kycRecord.update({
        where: { id: kyc.id },
        data: { status: 'PENDING' },
      });
    }

    return { received: true };
  }

  /**
   * Разбор расхождения подписи. Ответ на один вопрос: у нас не тот секрет или
   * они подписывают не то, что прислали?
   *
   * Включается только `KYC_WEBHOOK_DEBUG=true` и только на время разбора:
   * ожидаемый дайджест в логе — это готовая подпись для конкретного тела, то
   * есть подсказка любому, кто до логов дотянется.
   */
  private logSignatureDiagnostics(body: Buffer, signature: string) {
    if (process.env.KYC_WEBHOOK_DEBUG !== 'true') return;
    const secret = process.env.SUMSUB_WEBHOOK_SECRET || '';
    const digest = (alg: string) =>
      crypto.createHmac(alg, secret).update(body).digest('hex');
    this.logger.warn(
      `KYC webhook diag: получено=${signature} ожидалось sha1=${digest('sha1')} ` +
        `sha256=${digest('sha256')} len=${body.length}\n` +
        `тело: ${body.toString('utf8').slice(0, 800)}`,
    );
  }

  /**
   * YELLOW у welid — «нужен человек»: не одобрено и не отказано. Отдельного
   * статуса под это в схеме нет, ближайший честный — PENDING: заявка снова в
   * работе, доступ по ней не выдан.
   */
  private async markOnHold(kycId: string) {
    await this.prisma.kycRecord.update({
      where: { id: kycId },
      data: { status: 'PENDING', rejectionReason: null },
    });
  }

  /**
   * Fallback while the KYC provider (welid) has no webhook callback to us:
   * poll pending applicants once a minute and apply review results.
   * Guarded transitions (status: PENDING in where) make it safe to run on
   * multiple app nodes and alongside webhooks — only one caller fires the
   * email/attestation side effects.
   */
  @Cron(CronExpression.EVERY_MINUTE)
  async pollPendingApplicants() {
    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const pending = await this.prisma.kycRecord.findMany({
      where: {
        status: 'PENDING',
        sumsubApplicantId: { not: null },
        updatedAt: { gte: dayAgo },
      },
      take: 100,
    });

    for (const kyc of pending) {
      try {
        const data = await this.apiGet(
          `/resources/applicants/${kyc.sumsubApplicantId}/one`,
        );
        const answer = data.review?.reviewResult?.reviewAnswer;
        if (answer === 'GREEN') {
          await this.markVerified(kyc.id, kyc.userId);
          this.logger.log(`KYC poll: userId=${kyc.userId} → VERIFIED`);
        } else if (answer === 'RED') {
          const reason =
            data.review?.reviewResult?.rejectLabels?.join(', ') ||
            'Verification failed';
          await this.markRejected(kyc.id, kyc.userId, reason);
          this.logger.log(`KYC poll: userId=${kyc.userId} → REJECTED`);
        }
      } catch (e) {
        this.logger.warn(
          `KYC poll failed for applicant ${kyc.sumsubApplicantId}: ${e}`,
        );
      }
    }
  }

  private async markVerified(kycId: string, userId: string) {
    const res = await this.prisma.kycRecord.updateMany({
      where: { id: kycId, status: { not: 'VERIFIED' } },
      data: {
        status: 'VERIFIED',
        verifiedAt: new Date(),
        rejectionReason: null,
      },
    });
    if (res.count === 0) return; // another node/webhook already handled it

    this.prisma.user
      .findUnique({ where: { id: userId } })
      .then((u) => {
        if (u?.email)
          this.email.sendKycStatusUpdate(u.email, 'VERIFIED').catch(() => {});
      })
      .catch(() => {});

    this.blockchain
      .attestVerification(userId, 2)
      .then((result) => {
        if (result) {
          this.logger.log(
            `On-chain KYC attestation: userId=${userId} tx=${result.txHash}`,
          );
        }
      })
      .catch((err) => {
        this.logger.error(
          `On-chain attestation failed for ${userId}: ${err.message}`,
        );
      });
  }

  private async markRejected(
    kycId: string,
    userId: string,
    reason: string,
    /**
     * Обычный отказ не отменяет уже выданное подтверждение: так опросник и
     * запоздавший колбэк не могут откатить свежее GREEN. Мониторинг — другое
     * дело: он приходит **после** одобрения и именно для того, чтобы его снять.
     */
    revokeVerified = false,
  ) {
    const res = await this.prisma.kycRecord.updateMany({
      where: {
        id: kycId,
        status: { notIn: revokeVerified ? ['REJECTED'] : ['REJECTED', 'VERIFIED'] },
      },
      data: {
        status: 'REJECTED',
        rejectionReason: reason,
        ...(revokeVerified ? { verifiedAt: null } : {}),
      },
    });
    if (res.count === 0) return;

    if (revokeVerified) {
      // Отметка в блокчейне выдавалась при подтверждении и здесь не снимается —
      // отзыв аттестации отдельная задача, но молча забывать об этом нельзя.
      this.logger.warn(
        `KYC ${kycId}: подтверждение отозвано мониторингом (${reason}); ` +
          'аттестация в блокчейне осталась выданной',
      );
    }

    this.prisma.user
      .findUnique({ where: { id: userId } })
      .then((u) => {
        if (u?.email)
          this.email
            .sendKycStatusUpdate(u.email, 'REJECTED', reason)
            .catch(() => {});
      })
      .catch(() => {});
  }

  async getApplicantData(userId: string) {
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    if (!kyc || !kyc.sumsubApplicantId) {
      throw new NotFoundException('KYC record not found');
    }

    let applicantData: any;
    try {
      applicantData = await this.apiGet(
        `/resources/applicants/${kyc.sumsubApplicantId}/one`,
      );
    } catch (e) {
      this.logger.warn(
        `Failed to fetch applicant ${kyc.sumsubApplicantId}: ${e}`,
      );
      // Graceful fallback: return what we have in DB
      return {
        applicantId: kyc.sumsubApplicantId,
        createdAt: kyc.createdAt.toISOString(),
        reviewStatus: kyc.status === 'VERIFIED' ? 'completed' : 'pending',
        reviewResult: {
          reviewAnswer: kyc.status === 'VERIFIED' ? 'GREEN' : null,
          rejectLabels: [],
        },
        info: {
          firstName: null,
          lastName: null,
          middleName: null,
          dob: null,
          placeOfBirth: null,
          country: null,
          nationality: null,
          gender: null,
        },
        addresses: [],
        idDocs: [],
      };
    }

    let docStatus: any = {};
    try {
      docStatus = await this.apiGet(
        `/resources/applicants/${kyc.sumsubApplicantId}/requiredIdDocsStatus`,
      );
    } catch (e) {
      this.logger.warn(
        `Failed to fetch doc status for ${kyc.sumsubApplicantId}: ${e}`,
      );
    }

    const info = applicantData.fixedInfo || applicantData.info || {};
    const idDocs = (info.idDocs || []).map((doc: any) => ({
      idDocType: doc.idDocType,
      number: doc.number,
      firstName: doc.firstName,
      lastName: doc.lastName,
      issuedDate: doc.issuedDate,
      validUntil: doc.validUntil,
      issuedBy: doc.issuedBy,
      country: doc.country,
    }));

    const addresses = (info.addresses || applicantData.addresses || []).map(
      (addr: any) => ({
        street: addr.street,
        buildingNumber: addr.buildingNumber,
        flatNumber: addr.flatNumber,
        town: addr.town,
        state: addr.state,
        postCode: addr.postCode,
        country: addr.country,
      }),
    );

    return {
      applicantId: kyc.sumsubApplicantId,
      createdAt: applicantData.createdAt,
      reviewStatus: applicantData.review?.reviewStatus || null,
      reviewResult: {
        reviewAnswer: applicantData.review?.reviewResult?.reviewAnswer || null,
        rejectLabels: applicantData.review?.reviewResult?.rejectLabels || [],
      },
      info: {
        firstName: info.firstName || info.firstNameEn || null,
        lastName: info.lastName || info.lastNameEn || null,
        middleName: info.middleName || info.middleNameEn || null,
        dob: info.dob || null,
        placeOfBirth: info.placeOfBirth || info.placeOfBirthEn || null,
        country: info.country || null,
        nationality: info.nationality || null,
        gender: info.gender || null,
      },
      addresses,
      idDocs,
      documentStatus: docStatus,
    };
  }

  private async issueAccessToken(externalUserId: string): Promise<string> {
    const url = `${this.baseUrl}/resources/accessTokens/sdk`;
    const body = JSON.stringify({
      userId: externalUserId,
      levelName: this.levelName,
      ttlInSecs: this.ttlInSecs,
    });

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    const data: any = await response.json();
    if (!response.ok) {
      throw new BadRequestException(
        'KYC token error: ' + (data.description || data.detail || response.statusText),
      );
    }
    return data.token;
  }

  private async getApplicantByExternalId(
    externalUserId: string,
  ): Promise<string> {
    const urlPath = `/resources/applicants/-;externalUserId=${encodeURIComponent(externalUserId)}/one`;
    const data = await this.apiGet(urlPath);
    return data.id;
  }

  private async apiGet(urlPath: string): Promise<any> {
    const response = await fetch(this.baseUrl + urlPath, {
      method: 'GET',
      signal: AbortSignal.timeout(8000),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new BadRequestException(
        'KYC API error: ' + (data.description || data.detail || response.statusText),
      );
    }
    return data;
  }
  /**
   * Constant-time signature comparison.
   *
   * `!==` on hex strings returns as soon as two characters differ, which leaks
   * how much of a guess was correct.
   */
  private signaturesMatch(received: string, expected: string): boolean {
    if (typeof received !== 'string' || received.length !== expected.length) {
      return false;
    }
    return crypto.timingSafeEqual(
      Buffer.from(received, 'utf8'),
      Buffer.from(expected, 'utf8'),
    );
  }
}
