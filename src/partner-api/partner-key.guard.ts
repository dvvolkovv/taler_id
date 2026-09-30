import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  HttpException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { parsePartnerKey, partnerKeyMatches } from '../partner-core/partner-key.util';
import { PartnerRegistryService } from '../partner-core/partner-registry.service';
import { RedisService } from '../redis/redis.service';
import { currentMinute, incrementCounter, throwTooManyRequests } from './partner-counter.util';

/** Адрес клиента, как его видит Express за нашим nginx, без префикса IPv4-in-IPv6. */
export function clientIp(req: { ip?: string }): string {
  return String(req.ip ?? '').replace(/^::ffff:/, '');
}

/**
 * Порог отказов ключа с одного IP в минуту. Задача 18 снимает общий per-IP
 * throttler с партнёрских маршрутов (он мерял бы одним счётчиком и
 * добросовестных клиентов партнёра, и перебор чужих ключей), а
 * HttpExceptionFilter пишет warn-строку на каждый 401/403, но не на 429 —
 * без собственного потолка поток мусорных ключей писал бы в лог
 * неограниченно. Считаем по IP, а не по slug партнёра: угадывающий чужой
 * ключ не должен уметь запереть снаружи сам партнёрский сервис.
 */
export const PARTNER_AUTH_FAILURES_PER_MINUTE = 30;

/**
 * Пускает в /partner/v1/* только сервер партнёра:
 *   1. партнёрский API выключен на окружении → 403 (по умолчанию выключен);
 *   2. ключа нет, формат чужой, ключ не подходит → 401;
 *   3. партнёр выключен → 403;
 *   4. IP не из белого списка партнёра (если список задан) → 401.
 * req.ip берётся с доверием только к loopback (main.ts, trust proxy), поэтому
 * подделать его заголовком X-Forwarded-For снаружи нельзя — но это верно
 * только пока nginx сам переписывает X-Forwarded-For своим реальным адресом
 * клиента, а не слепо пропускает входящее значение дальше. План проверяет
 * это на PROD живыми пробами с подделанным заголовком через балансировщик и
 * RU-edge (Task 43, Step 7).
 */
@Injectable()
export class PartnerKeyGuard implements CanActivate {
  constructor(
    private readonly registry: PartnerRegistryService,
    private readonly redis: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const rejection = await this.authenticate(req);
    if (!rejection) return true;
    const { minute, retryAfter } = currentMinute();
    const key = `partner:authfail:${clientIp(req)}:${minute}`;
    const count = await incrementCounter(this.redis, key, 120);
    if (count !== null && count > PARTNER_AUTH_FAILURES_PER_MINUTE) {
      throwTooManyRequests(context.switchToHttp().getResponse(), 'too_many_auth_failures', retryAfter);
    }
    throw rejection;
  }

  /**
   * null — ключ подошёл, req.partner выставлен. Иначе — отказ, который
   * canActivate посчитает на IP и либо перебросит как есть, либо заменит
   * на 429. Исключение НЕ из этого метода (например 503 реестра партнёров)
   * улетает прямо из canActivate, минуя счётчик — оно не отказ по ключу.
   */
  private async authenticate(req: { headers?: Record<string, unknown>; ip?: string }): Promise<HttpException | null> {
    if (process.env.PARTNER_API_ENABLED !== 'true') {
      return new ForbiddenException('partner_api_disabled');
    }
    const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers?.authorization ?? ''));
    const key = match?.[1] ?? '';
    const parsed = parsePartnerKey(key);
    const partner = parsed ? await this.registry.findBySlug(parsed.slug) : null;
    if (!partner || !partnerKeyMatches(key, partner.keyHash)) {
      return new UnauthorizedException('invalid_partner_key');
    }
    if (!partner.enabled) return new ForbiddenException('partner_disabled');
    if (partner.ipAllowlist.length > 0 && !partner.ipAllowlist.includes(clientIp(req))) {
      return new UnauthorizedException('ip_not_allowed');
    }
    (req as { partner?: unknown }).partner = partner;
    return null;
  }
}
