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

  /** Снимает связку: статус, все её токены, открытые сокеты. Аккаунт TalerID не трогает. */
  async revokeLink(link: { id: string; grantId: string | null }): Promise<void> {
    await this.prisma.partnerLink.update({
      where: { id: link.id },
      data: {
        status: 'REVOKED',
        revokedAt: new Date(),
        grantId: null,
        codeHash: null,
        codeExpiresAt: null,
        codeAttempts: 0,
      },
    });
    if (link.grantId) {
      await this.tokens.revokeGrant(link.grantId);
      await this.realtime.disconnectGrant(link.grantId);
    }
  }

  /** Все живые связки пользователя — когда он удаляет аккаунт в самом TalerID. */
  async revokeAllForUser(userId: string): Promise<number> {
    const links = await this.prisma.partnerLink.findMany({
      where: { userId, status: { not: 'REVOKED' } },
      select: { id: true, grantId: true },
    });
    for (const link of links) await this.revokeLink(link);
    return links.length;
  }
}
