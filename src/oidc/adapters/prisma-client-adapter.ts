import type { PrismaService } from '../../prisma/prisma.service';

export class PrismaClientAdapter {
  constructor(
    private readonly prisma: PrismaService,
    private readonly walletxClientSecret: string,
    // Confidential B2B partner secrets are kept in env (like walletx) rather
    // than in the DB row, so the OAuthClient table never stores a live secret.
    private readonly linkeonPartnerClientSecret?: string,
  ) {}

  async find(id: string): Promise<Record<string, any> | undefined> {
    const c = await this.prisma.oAuthClient.findUnique({ where: { clientId: id } });
    if (!c) return undefined;

    // Dynamic clients registered via DCR: return stored metadata with canonical
    // client_id injected so oidc-provider always sees a consistent client_id field
    // regardless of what was persisted in dcrMetadata.
    if (c.isDynamic) {
      const meta = c.dcrMetadata as Record<string, any>;
      return { ...meta, client_id: c.clientId };
    }

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
    // canonical public client; linkeon-partner-web is the account-linking
    // login client (code flow + PKCE, no secret — only mints an id_token).
    const PUBLIC_CLIENTS = new Set(['taler-id-developers', 'linkeon-partner-web']);
    const isPublicClient = PUBLIC_CLIENTS.has(c.clientId);
    const tokenEndpointAuthMethod = isPublicClient ? 'none' : 'client_secret_basic';

    // Server-to-server clients (no redirect_uris, e.g. the verifiedPartner
    // provisioning client) don't use the interactive code flow — their tokens
    // are minted server-side and refreshed via grant_type=refresh_token. Giving
    // them response_types:['code'] would force a redirect_uri (oidc-provider:
    // "redirect_uris must contain members"), so we advertise refresh_token only.
    const serverToServer = !isPublicClient && c.redirectUris.length === 0;

    return {
      client_id: c.clientId,
      client_secret:
        c.clientId === 'walletx'
          ? this.walletxClientSecret
          : c.clientId === 'linkeon-partner' && this.linkeonPartnerClientSecret
            ? this.linkeonPartnerClientSecret
            : c.clientSecret,
      client_name: c.name,
      redirect_uris: c.redirectUris,
      scope: c.allowedScopes.join(' '),
      logo_uri: c.logoUri ?? undefined,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      grant_types: serverToServer
        ? ['refresh_token']
        : ['authorization_code', 'refresh_token'],
      response_types: serverToServer ? [] : ['code'],
      ...(postLogoutRedirectUris
        ? { post_logout_redirect_uris: postLogoutRedirectUris }
        : {}),
    };
  }

  // Dynamic Client Registration (DCR): oidc-provider calls upsert() to persist
  // a newly-registered client. We strip offline_access from scope — that grant
  // is reserved for manually-verified B2B partners (verifiedPartner=true) and
  // must not be auto-granted via open registration.
  //
  // Security: we explicitly check whether the target row is a static client
  // before updating, so a DCR PUT /reg/:clientId request cannot overwrite
  // redirect_uris of system clients like 'walletx' or 'taler-id-developers'.
  async upsert(id: string, payload: any, _expiresIn: number): Promise<void> {
    const scope = String(payload.scope ?? '')
      .split(' ')
      .filter((s) => s && s !== 'offline_access')
      .join(' ');
    const metadata = { ...payload, scope };

    const existing = await this.prisma.oAuthClient.findUnique({
      where: { clientId: id },
      select: { isDynamic: true },
    });

    if (existing && !existing.isDynamic) {
      throw new Error(`Refusing DCR upsert over static client ${id}`);
    }

    if (existing) {
      // Dynamic client update — only touch DCR-owned fields.
      await this.prisma.oAuthClient.update({
        where: { clientId: id },
        data: { dcrMetadata: metadata, redirectUris: payload.redirect_uris ?? [] },
      });
    } else {
      // New dynamic client registration.
      await this.prisma.oAuthClient.create({
        data: {
          clientId: id,
          clientSecret: payload.client_secret ?? '',
          name: payload.client_name ?? id,
          redirectUris: payload.redirect_uris ?? [],
          allowedScopes: scope.split(' ').filter(Boolean),
          isDynamic: true,
          dcrMetadata: metadata,
        },
      });
    }
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
