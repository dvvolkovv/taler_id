import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';

@Injectable()
export class AdminGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const auth = req.headers['authorization'];
    if (!auth?.startsWith('Bearer ')) throw new UnauthorizedException('No token');
    const token = auth.slice(7);
    try {
      const publicKeyPath = this.config.get<string>('jwt.publicKeyPath') ?? '';
      const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
      const payload = this.jwt.verify(token, { algorithms: ['RS256'], publicKey } as any);
      if (!payload.isAdmin) throw new ForbiddenException('Admin access required');
      req.user = payload;
      return true;
    } catch (e) {
      if (e instanceof ForbiddenException) throw e;
      throw new UnauthorizedException('Invalid token');
    }
  }
}
