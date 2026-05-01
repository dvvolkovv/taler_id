import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { OidcService } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';
import { describeScopes, ScopeDescriptor } from './scope-descriptors';
import type { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';

export interface GrantInfo {
  client_name: string;
  client_logo?: string;
  scopes: ScopeDescriptor[];
  remembered: boolean;
}

// oidc-provider's Client.find() wraps PrismaClientAdapter's snake_case payload
// into a Client instance with camelCase accessors. We only need the subset
// of metadata that this service touches.
interface OidcClientMetadata {
  clientId: string;
  clientName: string;
  logoUri?: string;
  redirectUris: string[];
  scope: string;
  tokenEndpointAuthMethod: string;
}

@Injectable()
export class OAuthMobileService {
  constructor(
    private readonly oidc: OidcService,
    private readonly prisma: PrismaService,
  ) {}

  async getGrantInfo(userId: string, params: OAuthAuthorizeQueryDto): Promise<GrantInfo> {
    const client = await this.findAndValidateClient(params);
    const requestedScopes = params.scope.trim().split(/\s+/).filter(Boolean);

    const grant = await (this.prisma as any).oAuthGrant.findFirst({
      where: { userId, clientId: params.client_id },
    });

    let remembered = false;
    if (grant) {
      const grantedScopes = new Set(
        (grant.scope as string).trim().split(/\s+/).filter(Boolean),
      );
      remembered = requestedScopes.every((s) => grantedScopes.has(s));
    }

    return {
      client_name: client.clientName,
      client_logo: client.logoUri ?? undefined,
      scopes: describeScopes(requestedScopes),
      remembered,
    };
  }

  private async findAndValidateClient(params: {
    client_id: string;
    redirect_uri: string;
    scope: string;
  }): Promise<OidcClientMetadata> {
    const provider = this.oidc.getProvider();
    const client = (await provider.Client.find(params.client_id)) as
      | OidcClientMetadata
      | undefined;
    if (!client) {
      throw new NotFoundException({ error: 'unknown_client' });
    }

    const allowedRedirectUris: string[] = client.redirectUris ?? [];
    if (!allowedRedirectUris.includes(params.redirect_uri)) {
      throw new BadRequestException({ error: 'redirect_uri_mismatch' });
    }

    const allowedScopes = ((client.scope ?? '') as string).split(/\s+/).filter(Boolean);
    const requestedScopes = params.scope.trim().split(/\s+/).filter(Boolean);
    if (requestedScopes.length === 0) {
      throw new BadRequestException({
        error: 'invalid_scope',
        error_description: 'At least one scope is required',
      });
    }
    const invalid = requestedScopes.filter((s) => !allowedScopes.includes(s));
    if (invalid.length > 0) {
      throw new BadRequestException({
        error: 'invalid_scope',
        error_description: `Scope not allowed: ${invalid.join(' ')}`,
      });
    }

    if (client.tokenEndpointAuthMethod !== 'none') {
      throw new BadRequestException({
        error: 'confidential_client_not_supported_via_mobile',
        error_description:
          'This client requires client_secret; only public PKCE clients are supported in mobile flow.',
      });
    }

    return client;
  }
}
