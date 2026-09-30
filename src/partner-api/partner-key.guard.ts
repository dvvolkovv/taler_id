import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { parsePartnerKey, partnerKeyMatches } from '../partner-core/partner-key.util';
import { PartnerRegistryService } from '../partner-core/partner-registry.service';

/** Адрес клиента, как его видит Express за нашим nginx, без префикса IPv4-in-IPv6. */
export function clientIp(req: { ip?: string }): string {
  return String(req.ip ?? '').replace(/^::ffff:/, '');
}

/**
 * Пускает в /partner/v1/* только сервер партнёра:
 *   1. партнёрский API выключен на окружении → 403 (по умолчанию выключен);
 *   2. ключа нет, формат чужой, ключ не подходит → 401;
 *   3. партнёр выключен → 403;
 *   4. IP не из белого списка партнёра (если список задан) → 401.
 * req.ip берётся с доверием только к loopback (main.ts, trust proxy), поэтому
 * подделать его заголовком X-Forwarded-For снаружи нельзя.
 */
@Injectable()
export class PartnerKeyGuard implements CanActivate {
  constructor(private readonly registry: PartnerRegistryService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (process.env.PARTNER_API_ENABLED !== 'true') {
      throw new ForbiddenException('partner_api_disabled');
    }
    const req = context.switchToHttp().getRequest();
    const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers?.authorization ?? ''));
    const key = match?.[1] ?? '';
    const parsed = parsePartnerKey(key);
    const partner = parsed ? await this.registry.findBySlug(parsed.slug) : null;
    if (!partner || !partnerKeyMatches(key, partner.keyHash)) {
      throw new UnauthorizedException('invalid_partner_key');
    }
    if (!partner.enabled) throw new ForbiddenException('partner_disabled');
    if (partner.ipAllowlist.length > 0 && !partner.ipAllowlist.includes(clientIp(req))) {
      throw new UnauthorizedException('ip_not_allowed');
    }
    req.partner = partner;
    return true;
  }
}
