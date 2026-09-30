import {
  BadRequestException,
  ConflictException,
  GoneException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { randomInt } from 'crypto';
import { EmailService } from '../email/email.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { PartnerRecord } from '../partner-core/partner-registry.service';
import { hashLinkCode, linkCodeMatches } from '../partner-core/partner-secrets.util';
import { PartnerAuditService } from './partner-audit.service';
import { countInWindow } from './partner-counter.util';

const CODE_TTL_SECONDS = 600;
const CODE_MAX_ATTEMPTS = 5;
const SEND_COOLDOWN_SECONDS = 60;
const SENDS_PER_HOUR = 5;
/**
 * Общий потолок партнёра в сутки: при утёкшем ключе перебор по тысячам чужих
 * аккаунтов упрётся в него. Легитимный партнёр шлёт код только людям, у
 * которых уже есть аккаунт TalerID.
 */
const SENDS_PER_PARTNER_PER_DAY = 1000;
const VERIFIES_PER_PARTNER_PER_DAY = 3000;

/**
 * Привязка существующего аккаунта TalerID к партнёру — только кодом, который
 * TalerID сам шлёт на почту аккаунта. Иначе утёкший ключ партнёра открывал бы
 * чаты любого пользователя по одной почте.
 */
@Injectable()
export class PartnerLinkCodeService {
  private readonly logger = new Logger(PartnerLinkCodeService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly email: EmailService,
    private readonly audit: PartnerAuditService,
  ) {}

  async send(partner: PartnerRecord, externalId: string, ip?: string): Promise<{ sent: true; expiresIn: number }> {
    const link = await this.pendingLink(partner.id, externalId);
    const to = link.user.email;
    if (!to) throw new NotFoundException('not_linked');

    // Общий потолок партнёра в сутки — первым: при утёкшем ключе перебор по
    // тысячам чужих аккаунтов упрётся в него раньше, чем в per-link окна.
    const day = await countInWindow(this.redis, `partner:linkcode:day:${partner.id}`, 86400);
    if (!day) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (day.count > SENDS_PER_PARTNER_PER_DAY) throw tooManyRequests(day.retryAfter);

    // Оба окна берегут почтовый ящик человека: без Redis — отказ (503), а не
    // пропуск, как у лимита запросов партнёра.
    const cooldownKey = `partner:linkcode:cd:${link.id}`;
    const cooldown = await countInWindow(this.redis, cooldownKey, SEND_COOLDOWN_SECONDS);
    if (!cooldown) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (cooldown.count > 1) throw tooManyRequests(cooldown.retryAfter);
    const hour = await countInWindow(this.redis, `partner:linkcode:h:${link.id}`, 3600);
    if (!hour) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (hour.count > SENDS_PER_HOUR) throw tooManyRequests(hour.retryAfter);

    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    await this.prisma.partnerLink.update({
      where: { id: link.id },
      data: {
        codeHash: hashLinkCode(link.id, code),
        codeExpiresAt: new Date(Date.now() + CODE_TTL_SECONDS * 1000),
        codeAttempts: 0,
      },
    });
    try {
      await this.email.sendPartnerLinkCode(to, code, partner.name, link.user.profile?.language ?? 'en');
    } catch (e) {
      // Письмо не ушло — человек не должен ждать минуту до следующей попытки.
      // Ответ про почту не держим ради Redis: del — без ожидания.
      this.redis.del(cooldownKey).catch(() => undefined);
      this.logger.error(`link code mail failed for ${link.id}: ${(e as Error).message}`);
      throw new ServiceUnavailableException('email_send_failed');
    }
    await this.audit.log(partner, 'LINK_CODE_SENT', { externalId, userId: link.userId, ip });
    return { sent: true, expiresIn: CODE_TTL_SECONDS };
  }

  async verify(
    partner: PartnerRecord,
    externalId: string,
    code: string,
    ip?: string,
  ): Promise<{ status: 'active'; talerUserId: string }> {
    const link = await this.pendingLink(partner.id, externalId);
    // Кода не отправляли — и попытку тратить не на что.
    if (!link.codeHash) throw new GoneException('code_expired');
    const codeHash = link.codeHash;
    // Тот же общий потолок партнёра в сутки, что и у send: подбор кода по
    // множеству чужих связок иначе вообще не встретил бы бюджета.
    const verifyDay = await countInWindow(this.redis, `partner:linkcode:verify:${partner.id}`, 86400);
    if (!verifyDay) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (verifyDay.count > VERIFIES_PER_PARTNER_PER_DAY) throw tooManyRequests(verifyDay.retryAfter);
    // Попытку списываем ДО сравнения и одним условным UPDATE, привязанным к
    // этому самому коду. Иначе параллельные запросы успевали бы сравнить
    // десятки кодов, пока счётчик ещё не вырос, — а подбирать код может как
    // раз партнёр, от которого этот код защищает чужой аккаунт.
    const spent = await this.prisma.partnerLink.updateMany({
      where: {
        id: link.id,
        status: 'PENDING',
        codeHash,
        codeExpiresAt: { gt: new Date() },
        codeAttempts: { lt: CODE_MAX_ATTEMPTS },
      },
      data: { codeAttempts: { increment: 1 } },
    });
    if (spent.count === 0) throw new GoneException('code_expired');
    // Дальше пишем только пока код тот же: гонка с повторной отправкой не
    // сотрёт свежий код, а гонка с отзывом не оживит отозванную связку.
    const sameCode = { id: link.id, status: 'PENDING' as const, codeHash };
    if (!linkCodeMatches(link.id, code, codeHash)) {
      const { codeAttempts } = await this.prisma.partnerLink.findUniqueOrThrow({
        where: { id: link.id },
        select: { codeAttempts: true },
      });
      if (codeAttempts >= CODE_MAX_ATTEMPTS) {
        await this.prisma.partnerLink.updateMany({
          where: sameCode,
          data: { codeHash: null, codeExpiresAt: null },
        });
        await this.audit.log(partner, 'LINK_CODE_FAILED', {
          externalId,
          userId: link.userId,
          ip,
          meta: { attemptsLeft: 0, burned: true },
        });
        throw new GoneException('code_expired');
      }
      await this.audit.log(partner, 'LINK_CODE_FAILED', {
        externalId,
        userId: link.userId,
        ip,
        meta: { attemptsLeft: CODE_MAX_ATTEMPTS - codeAttempts, burned: false },
      });
      throw new BadRequestException({ message: 'invalid_code', attemptsLeft: CODE_MAX_ATTEMPTS - codeAttempts });
    }
    const activated = await this.prisma.partnerLink.updateMany({
      where: sameCode,
      data: { status: 'ACTIVE', activatedAt: new Date(), codeHash: null, codeExpiresAt: null, codeAttempts: 0 },
    });
    if (activated.count === 0) throw new GoneException('code_expired');
    await this.audit.log(partner, 'LINK_CONFIRMED', { externalId, userId: link.userId, ip });
    return { status: 'active', talerUserId: link.userId };
  }

  private async pendingLink(partnerId: string, externalId: string) {
    const link = await this.prisma.partnerLink.findUnique({
      where: { partnerId_externalId: { partnerId, externalId } },
      include: {
        user: { select: { email: true, deletedAt: true, profile: { select: { language: true } } } },
      },
    });
    if (!link || link.status === 'REVOKED' || link.user.deletedAt) throw new NotFoundException('not_linked');
    if (link.status !== 'PENDING') throw new ConflictException('not_pending');
    return link;
  }
}

function tooManyRequests(retryAfter: number): HttpException {
  return new HttpException({ message: 'too_many_requests', retryAfter }, HttpStatus.TOO_MANY_REQUESTS);
}
