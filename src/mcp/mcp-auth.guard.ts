import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
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

    const at = await this.provider.AccessToken.find(token).catch(
      () => undefined,
    );
    if (!at?.accountId) {
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
