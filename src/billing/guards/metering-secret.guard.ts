import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MeteringSecretGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const header = req.headers['x-metering-secret'];
    const expected = this.config.get<string>('METERING_SHARED_SECRET');
    if (!expected) throw new UnauthorizedException('metering secret not configured');
    if (header !== expected) throw new UnauthorizedException('bad metering secret');
    return true;
  }
}
