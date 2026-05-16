import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { OidcService } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';
import { describeScopes, ScopeDescriptor } from './scope-descriptors';
import type { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';
import type { OAuthApproveDto } from './dto/oauth-approve.dto';

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

/**
 * Validates whether a redirect_uri is allowed for the given client.
 *
 * RFC 8252 §7.3 — Native apps (isDesktopClient=true) may use any loopback port:
 *   "the authorization server MUST allow any port to be specified at the time of
 *    the request for loopback IP redirect URIs, to accommodate clients that obtain
 *    an available ephemeral port from the operating system at the time of the request."
 *
 * Only http://127.0.0.1:<any port>/... is permitted; HTTPS loopback and
 * non-loopback hosts are rejected.
 */
export function validateRedirectUri(
  client: { redirectUris: string[]; isDesktopClient: boolean },
  redirectUri: string,
): boolean {
  // Always allow exact-match registered URIs regardless of client type.
  if ((client.redirectUris ?? []).includes(redirectUri)) {
    return true;
  }

  if (client.isDesktopClient) {
    try {
      const url = new URL(redirectUri);
      // RFC 8252: native apps may use loopback IP (127.0.0.1) with any port.
      // Protocol must be http: (not https: — no TLS on loopback per the RFC).
      if (url.hostname === '127.0.0.1' && url.protocol === 'http:') {
        return true;
      }
    } catch (_) {
      // Malformed URI — fall through to reject.
    }
  }

  return false;
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

  async approve(
    userId: string,
    params: OAuthApproveDto,
  ): Promise<{ redirect_uri: string }> {
    await this.findAndValidateClient(params);
    const requestedScope = params.scope.trim().split(/\s+/).filter(Boolean).join(' ');

    const provider = this.oidc.getProvider();

    const grant = new provider.Grant({
      accountId: userId,
      clientId: params.client_id,
    });
    grant.addOIDCScope(requestedScope);
    await grant.save();

    const code = new provider.AuthorizationCode({
      accountId: userId,
      clientId: params.client_id,
      redirectUri: params.redirect_uri,
      scope: requestedScope,
      grantId: grant.jti,
      codeChallenge: params.code_challenge,
      codeChallengeMethod: params.code_challenge_method,
      nonce: params.nonce,
    });
    const codeValue = await code.save();

    const existing = await (this.prisma as any).oAuthGrant.findFirst({
      where: { userId, clientId: params.client_id },
    });
    const mergedScopes = mergeScopes(existing?.scope ?? '', requestedScope);
    await (this.prisma as any).oAuthGrant.upsert({
      where: { userId_clientId: { userId, clientId: params.client_id } },
      create: { userId, clientId: params.client_id, scope: mergedScopes },
      update: { scope: mergedScopes },
    });

    const url = new URL(params.redirect_uri);
    url.searchParams.set('code', codeValue);
    if (params.state) url.searchParams.set('state', params.state);
    return { redirect_uri: url.toString() };
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

    // Fetch isDesktopClient directly from Prisma — oidc-provider may not
    // surface unknown fields through its Client wrapper.
    const dbClient = await this.prisma.oAuthClient.findUnique({
      where: { clientId: params.client_id },
      select: { isDesktopClient: true },
    });
    const isDesktopClient = dbClient?.isDesktopClient ?? false;

    if (!validateRedirectUri(
      { redirectUris: client.redirectUris, isDesktopClient },
      params.redirect_uri,
    )) {
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

export function mergeScopes(existing: string, added: string): string {
  const set = new Set([
    ...existing.split(/\s+/).filter(Boolean),
    ...added.split(/\s+/).filter(Boolean),
  ]);
  return Array.from(set).join(' ');
}
