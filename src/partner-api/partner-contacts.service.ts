import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PartnerRecord } from '../partner-core/partner-registry.service';
import { assertExternalId } from './external-id.util';
import { PartnerAuditService } from './partner-audit.service';

/**
 * «Друзья партнёра = контакты TalerID». Личный чат в TalerID возможен только
 * между контактами, и это правило проверяет сервер мессенджера; партнёр лишь
 * говорит, кто с кем дружит. Блокировок партнёр не снимает.
 */
@Injectable()
export class PartnerContactsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: PartnerAuditService,
  ) {}

  async put(
    partner: PartnerRecord,
    extA: string,
    extB: string,
    ip?: string,
    retried = false,
  ): Promise<{ contact: true; created: boolean }> {
    try {
      return await this.putOnce(partner, extA, extB, ip);
    } catch (e: any) {
      // Тот же PUT пришёл дважды одновременно (оба друга подтвердили дружбу):
      // второй упирается в уникальный индекс. Первый уже всё записал — перечитываем.
      if (e?.code === 'P2002' && !retried) return this.put(partner, extA, extB, ip, true);
      throw e;
    }
  }

  private async putOnce(
    partner: PartnerRecord,
    extA: string,
    extB: string,
    ip?: string,
  ): Promise<{ contact: true; created: boolean }> {
    const [userAId, userBId] = await this.pair(partner, extA, extB, true);
    const blocked = await this.prisma.blockedUser.findFirst({
      where: {
        OR: [
          { blockerId: userAId, blockedId: userBId },
          { blockerId: userBId, blockedId: userAId },
        ],
      },
    });
    if (blocked) throw new ConflictException('blocked');

    const rows = await this.pairRows(userAId, userBId);
    const wasContact = rows.some((r) => r.status === 'ACCEPTED');
    if (!wasContact) {
      if (rows.length > 0) {
        // Все запросы пары, а не первый: висящий встречный запрос иначе
        // остался бы «входящим» от человека, который уже в контактах.
        await this.prisma.contactRequest.updateMany({
          where: { id: { in: rows.map((r) => r.id) } },
          data: { status: 'ACCEPTED' },
        });
      } else {
        await this.prisma.contactRequest.create({
          data: { senderId: userAId, receiverId: userBId, status: 'ACCEPTED' },
        });
      }
    }
    const record = await this.prisma.partnerContact.findUnique({
      where: { partnerId_userAId_userBId: { partnerId: partner.id, userAId, userBId } },
    });
    if (!record) {
      await this.prisma.partnerContact.create({
        data: { partnerId: partner.id, userAId, userBId, createdContact: !wasContact },
      });
    }
    if (!wasContact) {
      await this.audit.log(partner, 'CONTACT_CREATED', {
        externalId: `${extA},${extB}`,
        userId: userAId,
        ip,
        meta: { otherUserId: userBId },
      });
    }
    return { contact: true, created: !wasContact };
  }

  async remove(partner: PartnerRecord, extA: string, extB: string, ip?: string): Promise<{ contact: boolean }> {
    const [userAId, userBId] = await this.pair(partner, extA, extB, false);
    const record = await this.prisma.partnerContact.findUnique({
      where: { partnerId_userAId_userBId: { partnerId: partner.id, userAId, userBId } },
    });
    if (record) {
      // deleteMany: повторный или параллельный DELETE не падает на уже удалённой строке.
      await this.prisma.partnerContact.deleteMany({ where: { id: record.id } });
      // Снимаем только контакт, который завёл сам партнёр, и только если его
      // не держит другой партнёр. Дружба, бывшая в TalerID раньше, остаётся.
      const heldByOthers = await this.prisma.partnerContact.count({ where: { userAId, userBId } });
      if (record.createdContact && heldByOthers === 0) {
        await this.prisma.contactRequest.deleteMany({
          where: {
            OR: [
              { senderId: userAId, receiverId: userBId },
              { senderId: userBId, receiverId: userAId },
            ],
          },
        });
      }
      await this.audit.log(partner, 'CONTACT_REMOVED', {
        externalId: `${extA},${extB}`,
        userId: userAId,
        ip,
        meta: { otherUserId: userBId },
      });
    }
    const rows = await this.pairRows(userAId, userBId);
    return { contact: rows.some((r) => r.status === 'ACCEPTED') };
  }

  /** userId обоих, упорядоченные: так пара хранится в PartnerContact. */
  private async pair(partner: PartnerRecord, extA: string, extB: string, activeOnly: boolean): Promise<[string, string]> {
    assertExternalId(extA);
    assertExternalId(extB);
    if (extA === extB) throw new BadRequestException('same_user');
    const links = await this.prisma.partnerLink.findMany({
      where: {
        partnerId: partner.id,
        externalId: { in: [extA, extB] },
        ...(activeOnly ? { status: 'ACTIVE' as const, user: { deletedAt: null } } : {}),
      },
      select: { externalId: true, userId: true },
    });
    const a = links.find((l) => l.externalId === extA);
    const b = links.find((l) => l.externalId === extB);
    if (!a || !b) {
      if (activeOnly) throw new ConflictException('link_not_active');
      throw new NotFoundException('not_linked');
    }
    return [a.userId, b.userId].sort() as [string, string];
  }

  private pairRows(userAId: string, userBId: string) {
    return this.prisma.contactRequest.findMany({
      where: {
        OR: [
          { senderId: userAId, receiverId: userBId },
          { senderId: userBId, receiverId: userAId },
        ],
      },
      select: { id: true, status: true },
    });
  }
}
