import * as crypto from 'crypto';
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

/**
 * Guards POST /partner/provision.
 *
 * Order matters and mirrors the contract:
 *   1. kill-switch off  -> 403 (default off; PROD stays off until explicitly enabled)
 *   2. missing/wrong x-partner-secret -> 401 (constant-time compare)
 *   3. optional IP allow-list -> 401 (belt-and-suspenders; default: no restriction)
 */
@Injectable()
export class PartnerSecretGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();

    if (process.env.PARTNER_PROVISION_ENABLED !== 'true') {
      throw new ForbiddenException('partner provisioning disabled');
    }

    const expected = process.env.LINKEON_PARTNER_SECRET ?? '';
    const provided = String(req.headers?.['x-partner-secret'] ?? '');
    if (!expected || !timingSafeEqual(provided, expected)) {
      throw new UnauthorizedException('invalid partner secret');
    }

    const allowList = (process.env.PARTNER_PROVISION_IP_ALLOWLIST ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (allowList.length > 0) {
      const ip = clientIp(req);
      if (!allowList.includes(ip)) {
        throw new UnauthorizedException('source IP not allowed');
      }
    }

    return true;
  }
}

// Constant-time string compare that does not leak length via early return:
// both sides are hashed to a fixed 32-byte digest first.
function timingSafeEqual(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Trust the first X-Forwarded-For hop (nginx/LB set it) then the socket peer.
function clientIp(req: any): string {
  const xff = String(req.headers?.['x-forwarded-for'] ?? '')
    .split(',')[0]
    .trim();
  return xff || req.socket?.remoteAddress || req.ip || '';
}
