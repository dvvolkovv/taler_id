import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { timingSafeEqual } from 'crypto';

@Injectable()
export class MeteringSecretGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const expected = this.config.get<string>('METERING_SHARED_SECRET');
    if (!expected) throw new UnauthorizedException('metering secret not configured');

    const raw = req.headers['x-metering-secret'];
    // Express may return string | string[] | undefined. Normalize to a single string.
    const header = Array.isArray(raw) ? raw[0] : raw;
    if (typeof header !== 'string') throw new UnauthorizedException('bad metering secret');

    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new UnauthorizedException('bad metering secret');
    }
    return true;
  }
}
