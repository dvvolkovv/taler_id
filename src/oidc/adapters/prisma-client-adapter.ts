import type { PrismaService } from '../../prisma/prisma.service';

export class PrismaClientAdapter {
  constructor(
    private readonly prisma: PrismaService,
    private readonly walletxClientSecret: string,
  ) {}

  async find(id: string): Promise<Record<string, any> | undefined> {
    const c = await this.prisma.oAuthClient.findUnique({ where: { clientId: id } });
    if (!c) return undefined;

    // Hardcoded post-logout redirect URIs for the demo client until the
    // OAuthClient model gains a postLogoutRedirectUris column (planned for
    // Phase 4 — developer portal).
    const postLogoutRedirectUris =
      c.clientId === 'taler-id-demo'
        ? [
            'https://staging.id.taler.tirol/demo/',
            'https://id.taler.tirol/demo/',
          ]
        : undefined;

    return {
      client_id: c.clientId,
      client_secret: c.clientId === 'walletx' ? this.walletxClientSecret : c.clientSecret,
      client_name: c.name,
      redirect_uris: c.redirectUris,
      scope: c.allowedScopes.join(' '),
      logo_uri: c.logoUri ?? undefined,
      token_endpoint_auth_method: 'client_secret_basic' as const,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      ...(postLogoutRedirectUris
        ? { post_logout_redirect_uris: postLogoutRedirectUris }
        : {}),
    };
  }

  // The remaining Adapter methods are required by the oidc-provider interface
  // but are never invoked for the Client model in this project. Clients are
  // managed via the OAuthRegistrationController, not via OIDC dynamic
  // registration exposed by oidc-provider itself. Throwing is intentional —
  // any call here would indicate a misconfiguration.
  async upsert(_id: string, _payload: any, _expiresIn: number): Promise<void> {
    throw new Error('PrismaClientAdapter.upsert is not implemented');
  }
  async findByUserCode(_userCode: string): Promise<undefined> { return undefined; }
  async findByUid(_uid: string): Promise<undefined> { return undefined; }
  async consume(_id: string): Promise<void> {
    throw new Error('PrismaClientAdapter.consume is not implemented');
  }
  async destroy(_id: string): Promise<void> {
    throw new Error('PrismaClientAdapter.destroy is not implemented');
  }
  async revokeByGrantId(_grantId: string): Promise<void> {
    throw new Error('PrismaClientAdapter.revokeByGrantId is not implemented');
  }
}
