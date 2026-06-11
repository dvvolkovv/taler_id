import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { timingSafeEqual } from 'crypto';

@Injectable()
export class RecorderSecretGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const expected = process.env.RECORDER_SHARED_SECRET;
    if (!expected)
      throw new UnauthorizedException('recorder secret not configured');

    const raw = req.headers['x-recorder-secret'];
    const header = Array.isArray(raw) ? raw[0] : raw;
    if (typeof header !== 'string')
      throw new UnauthorizedException('bad recorder secret');

    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new UnauthorizedException('bad recorder secret');
    }
    return true;
  }
}
