import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { OidcService } from '../oidc/oidc.service';

/**
 * Validates an OIDC access token issued by our own oidc-provider.
 *
 * Used by /oauth/clients endpoints when called from the Developer Portal SPA,
 * which authenticates via the OAuth flow (PKCE) and gets an opaque access
 * token, NOT a regular Taler ID JWT. The token cannot be verified by
 * JwtAuthGuard because it is not a JWT — instead we look it up in oidc-provider's
 * own storage (Redis) to get the associated accountId.
 */
@Injectable()
export class OidcBearerGuard implements CanActivate {
  constructor(private readonly oidc: OidcService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const auth = request.headers['authorization'] as string | undefined;
    if (!auth || !auth.toLowerCase().startsWith('bearer ')) {
      throw new UnauthorizedException('Missing Bearer token');
    }
    const token = auth.slice('bearer '.length).trim();
    if (!token) {
      throw new UnauthorizedException('Empty Bearer token');
    }

    const provider = this.oidc.getProvider();
    let accessToken: any;
    try {
      accessToken = await provider.AccessToken.find(token);
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
    if (!accessToken) {
      throw new UnauthorizedException('Invalid or expired token');
    }
    if (accessToken.isExpired) {
      throw new UnauthorizedException('Token expired');
    }
    if (!accessToken.accountId) {
      throw new UnauthorizedException('Token has no associated user');
    }

    // Mirror JwtAuthGuard's req.user shape: { sub: <userId> }.
    request.user = { sub: accessToken.accountId };
    return true;
  }
}
