import {
  ConflictException,
  GoneException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ProfileService } from '../profile/profile.service';
import { SystemChannelService } from '../system-channel/system-channel.service';
import { PartnerLinkRevokerService } from '../partner-core/partner-link-revoker.service';
import { PartnerRecord } from '../partner-core/partner-registry.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PartnerAuditService } from './partner-audit.service';
import { PatchUserDto } from './dto/patch-user.dto';
import { ProvisionUserDto } from './dto/provision-user.dto';

export type ProvisionResult =
  | { status: 'active'; talerUserId: string; created: boolean }
  | { status: 'confirmation_required'; talerUserId: null };

type LinkStatus = 'PENDING' | 'ACTIVE' | 'REVOKED';

interface LinkWithUser {
  id: string;
  userId: string;
  status: LinkStatus;
  createdAccount: boolean;
  grantId: string | null;
  activatedAt: Date | null;
  user: { id: string; deletedAt: Date | null; passwordHash: string | null };
}

/** Профиль TalerID знает ru и en; всё остальное (uk и т.д.) — en. */
export function profileLanguage(locale?: string): 'ru' | 'en' {
  return locale?.toLowerCase().startsWith('ru') ? 'ru' : 'en';
}

/**
 * Аккаунт, которым партнёр вправе распоряжаться (переименовать, удалить):
 * он его создал, и человек ни разу не задавал пароль TalerID.
 */
export function isManaged(link: LinkWithUser): boolean {
  return link.createdAccount && link.user.passwordHash === null && link.user.deletedAt === null;
}

/**
 * Люди партнёра в TalerID. Спека, раздел «Партнёрский API»:
 * docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */
@Injectable()
export class PartnerUsersService {
  private readonly logger = new Logger(PartnerUsersService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: PartnerTokensService,
    private readonly revoker: PartnerLinkRevokerService,
    private readonly systemChannel: SystemChannelService,
    private readonly profiles: ProfileService,
    private readonly audit: PartnerAuditService,
  ) {}

  async provision(
    partner: PartnerRecord,
    dto: ProvisionUserDto,
    ip?: string,
    retried = false,
  ): Promise<ProvisionResult> {
    const email = dto.email.trim().toLowerCase();
    try {
      return await this.provisionOnce(partner, dto.externalId, email, dto, ip);
    } catch (e: any) {
      // Два одновременных запроса про одного человека: второй упирается в
      // уникальный индекс. Состояние к этому моменту уже записано — перечитываем.
      if (e?.code === 'P2002' && !retried) return this.provision(partner, dto, ip, true);
      throw e;
    }
  }

  private async provisionOnce(
    partner: PartnerRecord,
    externalId: string,
    email: string,
    dto: ProvisionUserDto,
    ip?: string,
  ): Promise<ProvisionResult> {
    const link = await this.findLink(partner.id, externalId);
    if (link && !link.user.deletedAt) {
      if (link.status === 'ACTIVE') return { status: 'active', talerUserId: link.userId, created: false };
      if (link.status === 'PENDING') return { status: 'confirmation_required', talerUserId: null };
    }
    if (link && (link.status !== 'REVOKED' || link.grantId)) {
      // Строку связки сейчас переиспользуем (аккаунт удалён или связка
      // отозвана). Сначала гасим всё, что за ней числится: действующий доступ
      // удалённого аккаунта или недоделанный прошлый отзыв (REVOKED с грантом).
      await this.revoker.revokeLink(link);
    }

    // Уникальный индекс почты в БД регистрозависим: Ivan@ и ivan@ иначе стали
    // бы двумя аккаунтами.
    const owner = await this.prisma.user.findFirst({
      where: { email: { equals: email, mode: 'insensitive' }, deletedAt: null },
      select: { id: true, passwordHash: true },
    });

    if (!owner) {
      const userId = await this.createAccount(email, dto);
      await this.saveLink(partner.id, externalId, link?.id ?? null, {
        userId,
        status: 'ACTIVE',
        createdAccount: true,
      });
      await this.audit.log(partner, 'USER_CREATED', { externalId, userId, ip });
      return { status: 'active', talerUserId: userId, created: true };
    }

    const other = await this.prisma.partnerLink.findUnique({
      where: { partnerId_userId: { partnerId: partner.id, userId: owner.id } },
    });
    if (other && other.externalId !== externalId) {
      if (other.status !== 'REVOKED') throw new ConflictException('user_linked_to_other_external_id');
      // Отозванная связка того же человека под старым id больше ничего не
      // значит, а уникальный индекс (partnerId, userId) не даст завести новую.
      // Если её отзыв не доделан (остался грант) — доделываем до удаления строки.
      if (other.grantId) await this.revoker.revokeLink(other);
      await this.prisma.partnerLink.delete({ where: { id: other.id } });
    }

    const createdByPartner = [link, other].some(
      (l) => !!l && l.userId === owner.id && l.createdAccount,
    );
    const managed = createdByPartner && owner.passwordHash === null;
    await this.saveLink(partner.id, externalId, link?.id ?? null, {
      userId: owner.id,
      status: managed ? 'ACTIVE' : 'PENDING',
      createdAccount: createdByPartner,
    });
    await this.audit.log(partner, managed ? 'USER_RELINKED' : 'LINK_PENDING', {
      externalId,
      userId: owner.id,
      ip,
    });
    return managed
      ? { status: 'active', talerUserId: owner.id, created: false }
      : { status: 'confirmation_required', talerUserId: null };
  }

  /** Тот же набор, что при обычной регистрации, только без пароля. */
  private async createAccount(email: string, dto: ProvisionUserDto): Promise<string> {
    const user = await this.prisma.user.create({
      data: {
        email,
        // Партнёр проверил почту своим кодом до вызова — это его обязанность.
        emailVerified: true,
        profile: {
          create: {
            firstName: dto.firstName?.trim() || null,
            lastName: dto.lastName?.trim() || null,
            language: profileLanguage(dto.locale),
          },
        },
        kycRecord: { create: {} },
      },
      select: { id: true },
    });
    // Как у всех: ensureSeeded() всё равно подписал бы при следующем рестарте.
    // Партнёрский токен каналов не видит (PartnerConversationScope).
    try {
      await this.systemChannel.subscribeUser(user.id);
    } catch (e) {
      this.logger.warn(`system-channel subscribe failed for ${user.id}: ${(e as Error).message}`);
    }
    return user.id;
  }

  private async saveLink(
    partnerId: string,
    externalId: string,
    existingId: string | null,
    data: { userId: string; status: 'ACTIVE' | 'PENDING'; createdAccount: boolean },
  ): Promise<void> {
    const fields = {
      userId: data.userId,
      status: data.status,
      createdAccount: data.createdAccount,
      activatedAt: data.status === 'ACTIVE' ? new Date() : null,
      revokedAt: null,
      grantId: null,
      codeHash: null,
      codeExpiresAt: null,
      codeAttempts: 0,
    };
    if (existingId) {
      await this.prisma.partnerLink.update({ where: { id: existingId }, data: fields });
    } else {
      await this.prisma.partnerLink.create({ data: { partnerId, externalId, ...fields } });
    }
  }

  private findLink(partnerId: string, externalId: string): Promise<LinkWithUser | null> {
    return this.prisma.partnerLink.findUnique({
      where: { partnerId_externalId: { partnerId, externalId } },
      include: { user: { select: { id: true, deletedAt: true, passwordHash: true } } },
    });
  }
}
