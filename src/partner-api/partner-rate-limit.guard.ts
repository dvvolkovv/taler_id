import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RedisService } from '../redis/redis.service';

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
 * Ставится после PartnerKeyGuard: без req.partner считать нечего.
 */
@Injectable()
export class PartnerRateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly redis: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const partner = req.partner as { id: string } | undefined;
    if (!partner) return true;
    const bucket =
      this.reflector.getAllAndOverride<PartnerRateBucketName>(PARTNER_RATE_BUCKET, [
        context.getHandler(),
        context.getClass(),
      ]) ?? 'default';
    const nowSec = Math.floor(Date.now() / 1000);
    const key = `partner:rl:${partner.id}:${bucket}:${Math.floor(nowSec / 60)}`;
    const count = await this.redis.incr(key);
    if (count === 1) await this.redis.expire(key, 120);
    if (count > PARTNER_RATE_LIMITS[bucket]) {
      throw new HttpException(
        { message: 'rate_limited', retryAfter: 60 - (nowSec % 60) },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    return true;
  }
}
