import { applyDecorators, UseGuards } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { PartnerKeyGuard } from './partner-key.guard';
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';

/**
 * Единый декоратор на партнёрский контроллер/ручку вместо двух отдельных:
 *   - порядок guard'ов фиксирован и важен — PartnerRateLimitGuard читает
 *     req.partner, который выставляет только PartnerKeyGuard, и обязан идти
 *     после него;
 *   - голый `@SkipThrottle()` снимает только безымянный (default) лимит.
 *     Именованные лимитеры short/medium/long из ThrottlerModule.forRoot
 *     (app.module.ts) снимаются каждый отдельно — без этого общий per-IP
 *     throttler продолжил бы считать партнёрские запросы наравне с обычными
 *     пользователями.
 * Собраны в одном месте, чтобы автор новой партнёрской ручки не забыл
 * какую-то из двух частей.
 */
export const PartnerApi = () =>
  applyDecorators(
    SkipThrottle({ short: true, medium: true, long: true }),
    UseGuards(PartnerKeyGuard, PartnerRateLimitGuard),
  );
