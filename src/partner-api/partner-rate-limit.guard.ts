import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RedisService } from '../redis/redis.service';
import {
  currentMinute,
  incrementCounter,
  throwTooManyRequests,
} from './partner-counter.util';

export type PartnerRateBucketName = 'token' | 'default';

/** Запросов в минуту на партнёра. Токен просят чаще всего: каждые 15 минут на человека. */
export const PARTNER_RATE_LIMITS: Record<PartnerRateBucketName, number> = {
  token: 600,
  default: 120,
};

export const PARTNER_RATE_BUCKET = 'partnerRateBucket';
export const PartnerRateBucket = (bucket: PartnerRateBucketName) =>
  SetMetadata(PARTNER_RATE_BUCKET, bucket);

/**
 * Лимит по партнёру, а не по IP: весь партнёр ходит с одного сервера, и
 * глобальные лимиты по IP (1000 в час на эндпоинт) упёрлись бы в него на
 * первых же сотнях активных людей. Счётчик — в Redis, общий для всех нод.
 * Ставится после PartnerKeyGuard: без req.partner считать нечего, и если
 * порядок guard'ов где-то нарушен — лучше упасть 500-й, чем молча пропускать
 * запросы без лимита.
 *
 * Redis недоступен → пропускаем: лимит — это про справедливость между
 * партнёрами, а не про безопасность (партнёр уже прошёл проверку ключа в
 * PartnerKeyGuard). Предупреждение в лог — не чаще раза в минуту на процесс,
 * иначе падение Redis утопит лог тем же warn на каждый запрос.
 */
@Injectable()
export class PartnerRateLimitGuard implements CanActivate {
  private readonly logger = new Logger('PartnerApi');
  private lastOutageWarnAt = 0;

  constructor(
    private readonly reflector: Reflector,
    private readonly redis: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const partner = req.partner as { id: string } | undefined;
    if (!partner) {
      throw new Error('PartnerRateLimitGuard must run after PartnerKeyGuard');
    }
    const bucket =
      this.reflector.getAllAndOverride<PartnerRateBucketName>(
        PARTNER_RATE_BUCKET,
        [context.getHandler(), context.getClass()],
      ) ?? 'default';
    const { minute, retryAfter } = currentMinute();
    const key = `partner:rl:${partner.id}:${bucket}:${minute}`;
    const count = await incrementCounter(this.redis, key, 120);
    if (count === null) {
      const now = Date.now();
      if (now - this.lastOutageWarnAt > 60_000) {
        this.lastOutageWarnAt = now;
        this.logger.warn(
          'partner rate limit: counter unavailable, letting the request through',
        );
      }
      return true;
    }
    if (count > PARTNER_RATE_LIMITS[bucket]) {
      throwTooManyRequests(
        context.switchToHttp().getResponse(),
        'rate_limited',
        retryAfter,
      );
    }
    return true;
  }
}
