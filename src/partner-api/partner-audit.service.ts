import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface PartnerAuditEntry {
  externalId?: string;
  userId?: string | null;
  ip?: string;
  meta?: Record<string, string | number | boolean | null>;
}

/**
 * Изменяющие действия партнёра — в AuditLog с префиксом PARTNER_. Глобальный
 * AuditLogInterceptor пишет только /auth, /profile и /kyc, поэтому здесь явно.
 */
@Injectable()
export class PartnerAuditService {
  private readonly logger = new Logger('PartnerApi');

  constructor(private readonly prisma: PrismaService) {}

  async log(partner: { id: string; slug: string }, action: string, entry: PartnerAuditEntry): Promise<void> {
    this.logger.log(`[${partner.slug}] ${action} externalId=${entry.externalId ?? '-'} user=${entry.userId ?? '-'}`);
    try {
      await this.prisma.auditLog.create({
        data: {
          userId: entry.userId ?? null,
          action: `PARTNER_${action}`,
          ipAddress: entry.ip ?? null,
          meta: { partner: partner.slug, externalId: entry.externalId ?? null, ...(entry.meta ?? {}) },
        },
      });
    } catch (e) {
      this.logger.warn(`audit write failed: ${(e as Error).message}`);
    }
  }
}
