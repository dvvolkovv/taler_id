import type { PrismaService } from '../../prisma/prisma.service';

export class PrismaClientAdapter {
  constructor(
    private readonly prisma: PrismaService,
    private readonly walletxClientSecret: string,
  ) {}

  async find(id: string): Promise<Record<string, any> | undefined> {
    const c = await this.prisma.oAuthClient.findUnique({ where: { clientId: id } });
    if (!c) return undefined;

    // Dynamic clients registered via DCR: return stored metadata as-is.
    if (c.isDynamic) return c.dcrMetadata as Record<string, any>;

    // Hardcoded post-logout redirect URIs for system clients until the
    // OAuthClient model gains a postLogoutRedirectUris column.
    let postLogoutRedirectUris: string[] | undefined;
    if (c.clientId === 'taler-id-demo') {
      postLogoutRedirectUris = [
        'https://staging.id.taler.tirol/demo/',
        'https://id.taler.tirol/demo/',
      ];
    } else if (c.clientId === 'taler-id-developers') {
      postLogoutRedirectUris = [
        'https://staging.id.taler.tirol/developers/',
        'https://id.taler.tirol/developers/',
      ];
    }

    // Public clients (browser SPAs using PKCE) authenticate via PKCE alone —
    // no client_secret, so token_endpoint_auth_method must be 'none'.
    // Confidential clients (server-side integrations with stored secrets) use
    // 'client_secret_basic'. The Developer Portal SPA at /developers/ is the
    // canonical public client.
    const isPublicClient = c.clientId === 'taler-id-developers';
    const tokenEndpointAuthMethod = isPublicClient ? 'none' : 'client_secret_basic';

    return {
      client_id: c.clientId,
      client_secret: c.clientId === 'walletx' ? this.walletxClientSecret : c.clientSecret,
      client_name: c.name,
      redirect_uris: c.redirectUris,
      scope: c.allowedScopes.join(' '),
      logo_uri: c.logoUri ?? undefined,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      ...(postLogoutRedirectUris
        ? { post_logout_redirect_uris: postLogoutRedirectUris }
        : {}),
    };
  }

  // Dynamic Client Registration (DCR): oidc-provider calls upsert() to persist
  // a newly-registered client. We strip offline_access from scope — that grant
  // is reserved for manually-verified B2B partners (verifiedPartner=true) and
  // must not be auto-granted via open registration.
  async upsert(id: string, payload: any, _expiresIn: number): Promise<void> {
    const scope = String(payload.scope ?? '')
      .split(' ')
      .filter((s) => s && s !== 'offline_access')
      .join(' ');
    const metadata = { ...payload, scope };
    await this.prisma.oAuthClient.upsert({
      where: { clientId: id },
      create: {
        clientId: id,
        clientSecret: payload.client_secret ?? '',
        name: payload.client_name ?? id,
        redirectUris: payload.redirect_uris ?? [],
        allowedScopes: scope.split(' ').filter(Boolean),
        isDynamic: true,
        dcrMetadata: metadata,
      },
      update: { dcrMetadata: metadata, redirectUris: payload.redirect_uris ?? [] },
    });
  }

  async findByUserCode(_userCode: string): Promise<undefined> { return undefined; }
  async findByUid(_uid: string): Promise<undefined> { return undefined; }
  async consume(_id: string): Promise<void> {
    throw new Error('PrismaClientAdapter.consume is not implemented');
  }

  // DCR: oidc-provider calls destroy() when a client is deleted. We guard with
  // isDynamic=true so that accidental calls cannot remove statically-configured
  // clients even if a bug passes the wrong id.
  async destroy(id: string): Promise<void> {
    await this.prisma.oAuthClient.deleteMany({ where: { clientId: id, isDynamic: true } });
  }

  async revokeByGrantId(_grantId: string): Promise<void> {
    throw new Error('PrismaClientAdapter.revokeByGrantId is not implemented');
  }
}
