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
import {
  hashLinkCode,
  linkCodeMatches,
} from '../partner-core/partner-secrets.util';
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

  async send(
    partner: PartnerRecord,
    externalId: string,
    ip?: string,
  ): Promise<{ sent: true; expiresIn: number }> {
    const link = await this.pendingLink(partner.id, externalId);
    const to = link.user.email;
    if (!to) throw new NotFoundException('not_linked');

    // Кулдаун и часовое окно — по человеку (partner.id + userId), а не по id
    // связки: relink под другим externalId переиздаёт строку PartnerLink с
    // новым id и иначе тихо сбрасывал бы историю отправок. Оба берегут
    // почтовый ящик человека: без Redis — отказ (503), а не пропуск, как у
    // лимита запросов партнёра.
    const cooldownKey = `partner:linkcode:cd:${partner.id}:${link.userId}`;
    const cooldown = await countInWindow(
      this.redis,
      cooldownKey,
      SEND_COOLDOWN_SECONDS,
    );
    if (!cooldown)
      throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (cooldown.count > 1) throw tooManyRequests(cooldown.retryAfter);
    const hourKey = `partner:linkcode:h:${partner.id}:${link.userId}`;
    const hour = await countInWindow(this.redis, hourKey, 3600);
    if (!hour)
      throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (hour.count > SENDS_PER_HOUR) throw tooManyRequests(hour.retryAfter);

    // Общий потолок партнёра в сутки — последним и считает уже ВЫДАННЫЕ коды,
    // а не запросы: иначе ретраи клиента на свои же per-link 429 (120 запросов
    // в минуту от лимита партнёра) исчерпывали бы его за ~8 минут и запирали
    // линковку всем людям партнёра на сутки, хотя виноват один клиент.
    const dayKey = `partner:linkcode:day:${partner.id}`;
    const day = await countInWindow(this.redis, dayKey, 86400);
    if (!day) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (day.count > SENDS_PER_PARTNER_PER_DAY) {
      this.logCapExceededOnce(
        partner,
        'send',
        SENDS_PER_PARTNER_PER_DAY,
        day.count,
      );
      throw tooManyRequests(day.retryAfter);
    }

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
      await this.email.sendPartnerLinkCode(
        to,
        code,
        partner.name,
        link.user.profile?.language ?? 'en',
      );
    } catch (e) {
      // Письмо не ушло — человек не должен ждать минуту до следующей попытки,
      // а выданный, но не доставленный код не должен списываться ни с часового
      // окна на человека, ни с суточного бюджета партнёра: иначе пять ретраев
      // за время SMTP-аутажа (документированное «можно сразу повторить»)
      // заперли бы человека на час, хотя письма не доходят не по его вине.
      // Ответ про почту не держим ради Redis: без ожидания.
      this.redis.del(cooldownKey).catch(() => undefined);
      this.redis
        .getClient()
        .decr(hourKey)
        .catch(() => undefined);
      this.redis
        .getClient()
        .decr(dayKey)
        .catch(() => undefined);
      this.logger.error(
        `link code mail failed for ${link.id}: ${(e as Error).message}`,
      );
      throw new ServiceUnavailableException('email_send_failed');
    }
    await this.audit.log(partner, 'LINK_CODE_SENT', {
      externalId,
      userId: link.userId,
      ip,
    });
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
    const verifyDayKey = `partner:linkcode:verify:${partner.id}`;
    const verifyDay = await countInWindow(this.redis, verifyDayKey, 86400);
    if (!verifyDay)
      throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (verifyDay.count > VERIFIES_PER_PARTNER_PER_DAY) {
      this.logCapExceededOnce(
        partner,
        'verify',
        VERIFIES_PER_PARTNER_PER_DAY,
        verifyDay.count,
      );
      throw tooManyRequests(verifyDay.retryAfter);
    }
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
    if (spent.count === 0) {
      // Сравнения не случилось — отдать суточный слот обратно.
      this.redis
        .getClient()
        .decr(verifyDayKey)
        .catch(() => undefined);
      throw new GoneException('code_expired');
    }
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
      throw new BadRequestException({
        message: 'invalid_code',
        attemptsLeft: CODE_MAX_ATTEMPTS - codeAttempts,
      });
    }
    const activated = await this.prisma.partnerLink.updateMany({
      where: sameCode,
      data: {
        status: 'ACTIVE',
        activatedAt: new Date(),
        codeHash: null,
        codeExpiresAt: null,
        codeAttempts: 0,
      },
    });
    if (activated.count === 0) throw new GoneException('code_expired');
    await this.audit.log(partner, 'LINK_CONFIRMED', {
      externalId,
      userId: link.userId,
      ip,
    });
    return { status: 'active', talerUserId: link.userId };
  }

  /**
   * Первое превышение суточного потолка партнёра за окно — сигнал человеку:
   * это либо перебор (атака утёкшим ключом), либо сломанный клиент, который
   * ретраит не переставая. Дальше по тому же окну логировать незачем — сигнал
   * не станет громче, а лог не должен захлёбываться повтором одного и того же.
   */
  private logCapExceededOnce(
    partner: PartnerRecord,
    capName: 'send' | 'verify',
    cap: number,
    count: number,
  ): void {
    if (count === cap + 1) {
      this.logger.error(
        `partner ${partner.slug} exceeded the daily link-code ${capName} cap (${cap}/day)`,
      );
    }
  }

  private async pendingLink(partnerId: string, externalId: string) {
    const link = await this.prisma.partnerLink.findUnique({
      where: { partnerId_externalId: { partnerId, externalId } },
      include: {
        user: {
          select: {
            email: true,
            deletedAt: true,
            profile: { select: { language: true } },
          },
        },
      },
    });
    if (!link || link.status === 'REVOKED' || link.user.deletedAt)
      throw new NotFoundException('not_linked');
    if (link.status !== 'PENDING') throw new ConflictException('not_pending');
    return link;
  }
}

function tooManyRequests(retryAfter: number): HttpException {
  return new HttpException(
    { message: 'too_many_requests', retryAfter },
    HttpStatus.TOO_MANY_REQUESTS,
  );
}
