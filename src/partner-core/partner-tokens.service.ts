import {
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { OIDC_PROVIDER } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';
import { PartnerRecord, PartnerRegistryService } from './partner-registry.service';
import {
  MESSENGER_SCOPE,
  PARTNER_ACCESS_TOKEN_TTL_SECONDS,
  PartnerPrincipal,
} from './partner.constants';

/**
 * Токены партнёра — обычные опаковые access-токены oidc-provider со scope
 * `messenger`, выпущенные на сервере (как у Linkeon в PartnerService.mintTokens).
 * Refresh-токенов нет: бэкенд партнёра просто просит новый access-токен.
 */
@Injectable()
export class PartnerTokensService {
  private readonly logger = new Logger(PartnerTokensService.name);

  constructor(
    @Inject(OIDC_PROVIDER) private readonly provider: any,
    private readonly prisma: PrismaService,
    private readonly registry: PartnerRegistryService,
  ) {}

  /**
   * Токен мессенджера для действующей связки. Грант один на связку: по нему
   * отзываются сразу все токены, когда связку снимают. Гранты в Redis живут
   * 30 дней, поэтому истёкший грант пересоздаётся здесь же.
   */
  async issueAccessToken(
    link: { id: string; userId: string; grantId: string | null },
    partner: PartnerRecord,
  ): Promise<{ accessToken: string; expiresIn: number; grantId: string }> {
    const client = await this.provider.Client.find(partner.oauthClientId);
    if (!client) throw new InternalServerErrorException('partner oauth client not configured');

    let grantId = link.grantId;
    const live = grantId ? await this.provider.Grant.find(grantId) : undefined;
    if (!live) {
      const grant = new this.provider.Grant({ accountId: link.userId, clientId: partner.oauthClientId });
      grant.addOIDCScope(MESSENGER_SCOPE);
      grantId = (await grant.save()) as string;
      await this.prisma.partnerLink.update({ where: { id: link.id }, data: { grantId } });
    }

    const at = new this.provider.AccessToken({
      accountId: link.userId,
      client,
      grantId,
      scope: MESSENGER_SCOPE,
      gty: 'authorization_code',
    });
    const accessToken: string = await at.save();
    // Срок — из настроек провайдера (ttl.AccessToken), а не из своей копии:
    // поменяют TTL глобально — партнёр получит правду, а не старые 900 секунд.
    const expiresIn =
      typeof at.expiration === 'number' ? at.expiration : PARTNER_ACCESS_TOKEN_TTL_SECONDS;
    return { accessToken, expiresIn, grantId: grantId as string };
  }

  /** Гасит все токены гранта и сам грант. Повторный вызов безопасен. */
  async revokeGrant(grantId: string): Promise<void> {
    await this.provider.AccessToken.adapter.revokeByGrantId(grantId);
    const grant = await this.provider.Grant.find(grantId);
    if (grant) await grant.destroy();
  }

  /**
   * Опознаёт партнёрский токен мессенджера. null — это не он: не наш формат,
   * истёк, без scope, партнёр выключен или весь API выключен. Сбой хранилища
   * токенов — 503, а не «неверный токен» (как в McpAuthGuard).
   */
  async verify(token: string): Promise<PartnerPrincipal | null> {
    if (process.env.PARTNER_API_ENABLED !== 'true' || !token) return null;
    let at: any;
    try {
      at = await this.provider.AccessToken.find(token);
    } catch (err) {
      this.logger.warn(`partner token lookup failed: ${(err as Error).message}`);
      throw new ServiceUnavailableException('Token validation unavailable');
    }
    if (!at?.accountId || at.isExpired || !at.grantId) return null;
    const scopes = String(at.scope ?? '').split(' ');
    if (!scopes.includes(MESSENGER_SCOPE)) return null;
    const partner = await this.registry.findByClientId(at.clientId);
    if (!partner?.enabled) return null;
    return {
      userId: at.accountId,
      partnerId: partner.id,
      partnerSlug: partner.slug,
      grantId: at.grantId,
      expiresAt: at.exp,
    };
  }
}
