import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PartnerRealtimeService } from './partner-realtime.service';
import { PartnerTokensService } from './partner-tokens.service';

@Injectable()
export class PartnerLinkRevokerService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: PartnerTokensService,
    private readonly realtime: PartnerRealtimeService,
  ) {}

  /**
   * Снимает связку: статус, все её токены, открытые сокеты. Аккаунт TalerID не трогает.
   * grantId обнуляется только ПОСЛЕ отзыва гранта: упади Redis посередине —
   * связка останется REVOKED с grantId, и повторный вызов доделает отзыв
   * (вызывающие считают такую связку незавершённой).
   */
  async revokeLink(link: { id: string }): Promise<void> {
    // Грант берём из той же строки, что переводим в REVOKED, а не у вызывающего:
    // его копия могла устареть, а параллельный выпуск токена после этой записи
    // сменить грант уже не сможет — он меняет его только у ACTIVE-связки.
    const row = await this.prisma.partnerLink.update({
      where: { id: link.id },
      data: { status: 'REVOKED', revokedAt: new Date(), codeHash: null, codeExpiresAt: null, codeAttempts: 0 },
      select: { grantId: true, partnerId: true, userId: true },
    });
    if (row.grantId) {
      await this.tokens.revokeGrant(row.grantId);
      await this.prisma.partnerLink.updateMany({
        where: { id: link.id, grantId: row.grantId },
        data: { grantId: null },
      });
    }
    await this.realtime.disconnectLink(row.partnerId, row.userId);
  }

  /**
   * Все связки пользователя — когда он удаляет аккаунт в самом TalerID: живые и
   * недоотозванные (REVOKED, но грант ещё висит). Сбой одной связки не мешает
   * остальным; обо всех сбоях сообщаем разом в конце.
   */
  async revokeAllForUser(userId: string): Promise<number> {
    const links = await this.prisma.partnerLink.findMany({
      where: { userId, OR: [{ status: { not: 'REVOKED' } }, { grantId: { not: null } }] },
      select: { id: true },
    });
    const failures: string[] = [];
    for (const link of links) {
      try {
        await this.revokeLink(link);
      } catch (e) {
        failures.push(`${link.id}: ${(e as Error).message}`);
      }
    }
    if (failures.length > 0) {
      throw new Error(`partner link revocation failed: ${failures.join('; ')}`);
    }
    return links.length;
  }
}
