import {
  ConflictException,
  GoneException,
  HttpException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
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

interface AccountState {
  deletedAt: Date | null;
  passwordHash: string | null;
  createdByPartnerId: string | null;
}

interface LinkWithUser {
  id: string;
  userId: string;
  status: LinkStatus;
  grantId: string | null;
  activatedAt: Date | null;
  revokedAt: Date | null;
  user: AccountState & { id: string; email: string | null };
}

interface EmailOwner extends AccountState {
  id: string;
  emailVerified: boolean;
}

/** Сколько раз provision начинает заново, наткнувшись на параллельный запрос. */
const PROVISION_ATTEMPTS = 3;

/** Строку связки изменили между чтением и записью — начать заново. */
class LinkChangedError extends Error {}

function isRace(e: unknown): boolean {
  return (
    e instanceof LinkChangedError ||
    (e as { code?: string } | null)?.code === 'P2002'
  );
}

/** Профиль TalerID знает ru и en; всё остальное (uk и т.д.) — en. */
export function profileLanguage(locale?: string | null): 'ru' | 'en' {
  return locale?.toLowerCase().startsWith('ru') ? 'ru' : 'en';
}

/**
 * Аккаунт, которым партнёр вправе распоряжаться (переименовать, удалить):
 * его завёл этот партнёр, человек ни разу не задавал пароль TalerID, и аккаунт
 * не удалён и не заблокирован.
 */
export function isManagedBy(
  partner: { id: string },
  user: AccountState,
): boolean {
  return (
    user.createdByPartnerId === partner.id &&
    user.passwordHash === null &&
    user.deletedAt === null
  );
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
  ): Promise<ProvisionResult> {
    const email = dto.email.trim().toLowerCase();
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.provisionOnce(
          partner,
          dto.externalId,
          email,
          dto,
          ip,
        );
      } catch (e) {
        // Параллельный запрос про того же человека: уникальный индекс или
        // строка, изменённая между чтением и записью. Он уже всё записал —
        // перечитываем. Не успокоилось за три попытки — пусть партнёр повторит.
        if (!isRace(e)) throw e;
        if (attempt >= PROVISION_ATTEMPTS)
          throw new ServiceUnavailableException('link_busy');
      }
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
      if (link.status === 'ACTIVE')
        return { status: 'active', talerUserId: link.userId, created: false };
      if (link.status === 'PENDING')
        return { status: 'confirmation_required', talerUserId: null };
    }
    if (link && (link.status !== 'REVOKED' || link.grantId)) {
      // Строку связки сейчас переиспользуем (аккаунт удалён или связка
      // отозвана). Сначала гасим всё, что за ней числится: действующий доступ
      // удалённого аккаунта или недоделанный прошлый отзыв (REVOKED с грантом).
      await this.revoke(link);
    }

    const owner = await this.findOwner(email);
    if (owner?.deletedAt) {
      // Почту держит аккаунт, заблокированный администратором: блокировка
      // обратима и почту не обнуляет, второй аккаунт на тот же адрес не завести.
      throw new ConflictException('email_unavailable');
    }

    if (!owner) {
      // Аккаунт и связка — одной транзакцией: аккаунта без связки не бывает,
      // а параллельный запрос видит либо оба, либо ничего.
      const userId = await this.prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: this.newAccount(partner, email, dto),
          select: { id: true },
        });
        await this.saveLink(tx, partner.id, externalId, link, {
          userId: user.id,
          status: 'ACTIVE',
        });
        return user.id;
      });
      await this.subscribeToNews(userId);
      await this.audit.log(partner, 'USER_CREATED', { externalId, userId, ip });
      return { status: 'active', talerUserId: userId, created: true };
    }

    // Без кода снова активен только аккаунт, который завёл этот партнёр и в
    // котором человек не задал пароль; любой другой — через код из письма.
    const managed = isManagedBy(partner, owner);
    // Код из письма доказал бы только владение ящиком, а не аккаунтом: его мог
    // завести кто угодно на чужой адрес, поскольку TalerID не проверяет почту
    // при обычной регистрации. Управляемые партнёром аккаунты всегда создаются
    // с emailVerified=true (newAccount), поэтому это условие их не касается.
    if (!managed && !owner.emailVerified) {
      throw new ConflictException('email_unverified');
    }

    const other = await this.prisma.partnerLink.findUnique({
      where: { partnerId_userId: { partnerId: partner.id, userId: owner.id } },
    });
    const stale = other && other.externalId !== externalId ? other : null;
    if (stale) {
      if (stale.status !== 'REVOKED')
        throw new ConflictException('user_linked_to_other_external_id');
      // Отозванная связка того же человека под старым id больше ничего не
      // значит, а уникальный индекс (partnerId, userId) не даст завести новую.
      // Если её отзыв не доделан (остался грант) — доделываем до удаления строки.
      if (stale.grantId) await this.revoke(stale);
    }

    await this.prisma.$transaction(async (tx) => {
      if (stale) {
        // Удаляем только ту отозванную строку, что видели: если её успели
        // оживить, повтор ответит 409.
        const { count } = await tx.partnerLink.deleteMany({
          where: { id: stale.id, status: 'REVOKED', grantId: null },
        });
        if (count === 0) throw new LinkChangedError();
      }
      await this.saveLink(tx, partner.id, externalId, link, {
        userId: owner.id,
        status: managed ? 'ACTIVE' : 'PENDING',
      });
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

  async issueToken(
    partner: PartnerRecord,
    externalId: string,
  ): Promise<{
    accessToken: string;
    tokenType: 'Bearer';
    expiresIn: number;
    talerUserId: string;
  }> {
    const link = await this.findLink(partner.id, externalId);
    if (!link) throw new NotFoundException('not_linked');
    if (link.user.deletedAt) {
      // Связку мог уже отозвать Task 19 при удалении аккаунта — проверка
      // REVOKED ниже не должна перехватить это раньше: иначе партнёр видит
      // обычный 404 и может молча завести человеку новый аккаунт вместо того,
      // чтобы узнать об удалении. REVOKED с недоотозванным грантом (сбой
      // Redis) — доделываем и здесь, а не только отвечаем по старому статусу.
      if (link.status !== 'REVOKED' || link.grantId) await this.revoke(link);
      // Партнёру сообщаем об удалении только если он был допущен к аккаунту
      // (связка подтверждалась кодом) и сам не отвязал её ещё до удаления —
      // иначе он узнал бы то, чего не знал даже до собственного отказа от связки.
      throw this.knowsAboutDeletion(link)
        ? new GoneException('account_deleted')
        : new NotFoundException('not_linked');
    }
    if (link.status === 'REVOKED') throw new NotFoundException('not_linked');
    if (link.status === 'PENDING')
      throw new ConflictException('confirmation_required');
    const { accessToken, expiresIn } = await this.tokens.issueAccessToken(
      link,
      partner,
    );
    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn,
      talerUserId: link.userId,
    };
  }

  /**
   * Сообщать ли партнёру, что аккаунт удалён: только если он был к аккаунту
   * допущен (связка подтверждалась) и не отвязал его сам ещё до удаления.
   */
  private knowsAboutDeletion(link: LinkWithUser): boolean {
    if (!link.user.deletedAt || !link.activatedAt) return false;
    return !(
      link.status === 'REVOKED' &&
      link.revokedAt &&
      link.revokedAt < link.user.deletedAt
    );
  }

  async getUser(partner: PartnerRecord, externalId: string) {
    const link = await this.findLink(partner.id, externalId);
    // Удалённый аккаунт без ведома партнёра (не было согласия, или партнёр сам
    // отвязал его ещё до удаления) — как будто связки нет вовсе (см. issueToken).
    if (!link || (link.user.deletedAt && !this.knowsAboutDeletion(link))) {
      throw new NotFoundException('not_linked');
    }
    const status =
      link.status === 'REVOKED' || link.user.deletedAt
        ? 'revoked'
        : link.status === 'ACTIVE'
          ? 'active'
          : 'confirmation_required';
    return {
      status,
      // Пока человек не подтвердил привязку кодом, id его аккаунта партнёру не положен.
      talerUserId: status === 'active' ? link.userId : null,
      managed: isManagedBy(partner, link.user),
      linkedAt: link.activatedAt ? link.activatedAt.toISOString() : null,
    };
  }

  async patchUser(
    partner: PartnerRecord,
    externalId: string,
    dto: PatchUserDto,
    ip?: string,
  ) {
    const link = await this.findLink(partner.id, externalId);
    if (!link || link.status !== 'ACTIVE' || link.user.deletedAt)
      throw new NotFoundException('not_linked');
    if (!isManagedBy(partner, link.user))
      throw new ConflictException('profile_not_managed');
    const data: { firstName?: string | null; lastName?: string | null } = {};
    if (dto.firstName !== undefined)
      data.firstName = dto.firstName?.trim() || null;
    if (dto.lastName !== undefined)
      data.lastName = dto.lastName?.trim() || null;
    if (Object.keys(data).length === 0) return { ok: true };
    await this.prisma.profile.upsert({
      where: { userId: link.userId },
      update: data,
      create: { userId: link.userId, ...data },
    });
    await this.audit.log(partner, 'PROFILE_UPDATED', {
      externalId,
      userId: link.userId,
      ip,
    });
    return { ok: true };
  }

  /**
   * Снимает связку. С deleteAccount — ещё и удаляет аккаунт штатной процедурой
   * TalerID, но только управляемый: человек удалился у партнёра и просит
   * стереть данные. Неуправляемый аккаунт — 409, и ничего не меняется.
   * Повтор безопасен: удалённый аккаунт второй раз не удаляется, ответ тот же.
   */
  async deleteUser(
    partner: PartnerRecord,
    externalId: string,
    deleteAccount: boolean,
    ip?: string,
  ): Promise<void> {
    const link = await this.findLink(partner.id, externalId);
    if (!link) throw new NotFoundException('not_linked');
    // Штатное удаление обнуляет почту; у заблокированного администратором она
    // остаётся — такой аккаунт партнёр не удаляет (isManagedBy ложен). И то,
    // и другое — только для аккаунта, который завёл именно этот партнёр:
    // чужой удалённый аккаунт (createdByPartnerId не наш) не «уже удалён»
    // для нас, а просто неуправляем — 409, а не тихий повторный 204.
    const alreadyDeleted =
      link.user.deletedAt !== null &&
      link.user.email === null &&
      link.user.createdByPartnerId === partner.id;
    const deletesNow = deleteAccount && !alreadyDeleted;
    if (deletesNow && !isManagedBy(partner, link.user))
      throw new ConflictException('account_not_managed');
    // REVOKED с грантом — прошлый отзыв не доделан (сбой Redis): доделываем.
    const revokes = link.status !== 'REVOKED' || !!link.grantId;
    if (revokes) await this.revoke(link);
    if (deletesNow) await this.profiles.deleteAccount(link.userId);
    // Журнал — сразу после удаления аккаунта и до очистки каналов: если чистка
    // ниже упадёт, повтор (alreadyDeleted уже true, отзывать больше нечего)
    // не должен молча остаться без строки про само удаление.
    if (revokes || deletesNow) {
      await this.audit.log(
        partner,
        deletesNow ? 'ACCOUNT_DELETED' : 'LINK_REVOKED',
        {
          externalId,
          userId: link.userId,
          ip,
        },
      );
    }
    if (deleteAccount) {
      // Подписки на каналы удалённому ни к чему, а тестовые прогоны иначе
      // копили бы их в системном канале. Повтор после сбоя дочищает.
      await this.prisma.conversationParticipant.deleteMany({
        where: { userId: link.userId, conversation: { type: 'CHANNEL' } },
      });
    }
  }

  /** Тот же набор, что при обычной регистрации, только без пароля и с отметкой партнёра. */
  private newAccount(
    partner: PartnerRecord,
    email: string,
    dto: ProvisionUserDto,
  ): Prisma.UserUncheckedCreateInput {
    return {
      email,
      // Партнёр проверил почту своим кодом до вызова — это его обязанность.
      emailVerified: true,
      createdByPartnerId: partner.id,
      profile: {
        create: {
          firstName: dto.firstName?.trim() || null,
          lastName: dto.lastName?.trim() || null,
          language: profileLanguage(dto.locale),
        },
      },
      kycRecord: { create: {} },
    };
  }

  /**
   * Как у всех: ensureSeeded() всё равно подписал бы при следующем рестарте.
   * Партнёрский токен каналов не видит (PartnerConversationScope).
   */
  private async subscribeToNews(userId: string): Promise<void> {
    try {
      await this.systemChannel.subscribeUser(userId);
    } catch (e) {
      this.logger.warn(
        `system-channel subscribe failed for ${userId}: ${(e as Error).message}`,
      );
    }
  }

  private async saveLink(
    db: Prisma.TransactionClient,
    partnerId: string,
    externalId: string,
    link: LinkWithUser | null,
    data: { userId: string; status: 'ACTIVE' | 'PENDING' },
  ): Promise<void> {
    const fields = {
      userId: data.userId,
      status: data.status,
      activatedAt: data.status === 'ACTIVE' ? new Date() : null,
      revokedAt: null,
      grantId: null,
      codeHash: null,
      codeExpiresAt: null,
      codeAttempts: 0,
    };
    if (!link) {
      await db.partnerLink.create({
        data: { partnerId, externalId, ...fields },
      });
      return;
    }
    // Переиспользуем только полностью отозванную строку, которую прочитали:
    // иначе затёрли бы грант связки, которую параллельный запрос успел оживить.
    const { count } = await db.partnerLink.updateMany({
      where: {
        id: link.id,
        userId: link.userId,
        status: 'REVOKED',
        grantId: null,
      },
      data: fields,
    });
    if (count === 0) throw new LinkChangedError();
  }

  /**
   * Владелец почты — точное совпадение без учёта регистра. Не фильтр Prisma
   * equals + mode: 'insensitive': на PostgreSQL он становится ILIKE, и `_`/`%`
   * в адресе работали бы как шаблон (ivan_petrenko@ находил бы ivan.petrenko@).
   * Уникальный индекс почты регистрозависим, вариантов может быть несколько:
   * живой раньше заблокированного, старший раньше младшего.
   */
  private async findOwner(email: string): Promise<EmailOwner | null> {
    const rows = await this.prisma.$queryRaw<EmailOwner[]>`
      SELECT "id", "passwordHash", "deletedAt", "createdByPartnerId", "emailVerified"
      FROM "User"
      WHERE lower("email") = lower(${email})
      ORDER BY ("deletedAt" IS NOT NULL), "emailVerified" DESC, "createdAt"
      LIMIT 1`;
    return rows[0] ?? null;
  }

  /** Отзыв ходит в Redis (гранты OIDC): его сбой — 503, партнёр повторит, а не 500. */
  private async revoke(link: { id: string }): Promise<void> {
    try {
      await this.revoker.revokeLink(link);
    } catch (e) {
      if (e instanceof HttpException) throw e;
      // P2025 — строку уже удалили. Единственное место, которое удаляет
      // строки связок, удаляет только полностью отозванные (REVOKED,
      // grantId: null) — значит, отзывать уже нечего, это не сбой.
      if ((e as { code?: string } | null)?.code === 'P2025') return;
      this.logger.error(
        `revocation of link ${link.id} failed: ${(e as Error).message}`,
      );
      throw new ServiceUnavailableException('revocation_unavailable');
    }
  }

  private findLink(
    partnerId: string,
    externalId: string,
  ): Promise<LinkWithUser | null> {
    return this.prisma.partnerLink.findUnique({
      where: { partnerId_externalId: { partnerId, externalId } },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            deletedAt: true,
            passwordHash: true,
            createdByPartnerId: true,
          },
        },
      },
    });
  }
}
