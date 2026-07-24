import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { OIDC_PROVIDER } from '../oidc/oidc.service';

export interface McpAuthContext {
  userId: string;
  clientId: string;
  scopes: string[];
}

@Injectable()
export class McpAuthGuard implements CanActivate {
  private readonly logger = new Logger(McpAuthGuard.name);

  constructor(@Inject(OIDC_PROVIDER) private readonly provider: any) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();

    // OIDC_ISSUER is the canonical env var used throughout this codebase
    // (configuration.ts: process.env.OIDC_ISSUER || BASE_URL + '/oauth';
    //  main.ts line 611 logs the same variable)
    const issuer =
      process.env.OIDC_ISSUER ||
      `${process.env.BASE_URL || 'https://staging.id.taler.tirol'}/oauth`;
    const resourceBase = issuer.replace(/\/oauth$/, '');
    res.setHeader(
      'WWW-Authenticate',
      `Bearer resource_metadata="${resourceBase}/.well-known/oauth-protected-resource"`,
    );

    const auth: string = req.headers?.authorization ?? '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer' || !token) {
      throw new UnauthorizedException('Missing bearer token');
    }

    let at: any;
    try {
      at = await this.provider.AccessToken.find(token);
    } catch (err) {
      this.logger.warn(
        `Token store lookup failed: ${(err as Error).message}`,
      );
      throw new ServiceUnavailableException('Token validation unavailable');
    }

    if (!at?.accountId || (at as any).isExpired) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    req.mcpAuth = {
      userId: at.accountId,
      clientId: at.clientId,
      scopes: String(at.scope ?? '')
        .split(' ')
        .filter(Boolean),
    } satisfies McpAuthContext;

    return true;
  }
}
