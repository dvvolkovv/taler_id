import {
  ConflictException,
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
  PARTNER_TOKEN_GTY,
  PartnerPrincipal,
} from './partner.constants';

/** Партнёрский токен oidc-provider — 43 символа base64url; всё прочее не наше. */
const PARTNER_TOKEN_FORMAT = /^[A-Za-z0-9_-]{43}$/;
/** Грант, которому осталось меньше минуты, не продлеваем токенами — меняем. */
const GRANT_MIN_REMAINING_SECONDS = 60;

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
   * Токен мессенджера для действующей связки. Грант один на связку: его
   * уничтожение гасит сразу все токены, когда связку снимают. Гранты в Redis
   * живут 30 дней, поэтому истёкший (или чужой) грант заменяется здесь же,
   * а заменённый уничтожается.
   */
  async issueAccessToken(
    link: { id: string; userId: string; grantId: string | null },
    partner: PartnerRecord,
    retried = false,
  ): Promise<{ accessToken: string; expiresIn: number; grantId: string }> {
    const client = await this.provider.Client.find(partner.oauthClientId);
    if (!client) throw new InternalServerErrorException('partner oauth client not configured');

    const now = Math.floor(Date.now() / 1000);
    const live = link.grantId ? await this.provider.Grant.find(link.grantId) : undefined;
    const usable =
      !!live &&
      live.accountId === link.userId &&
      live.clientId === partner.oauthClientId &&
      live.exp - now >= GRANT_MIN_REMAINING_SECONDS;

    let grantId = link.grantId;
    if (!usable) {
      const grant = new this.provider.Grant({ accountId: link.userId, clientId: partner.oauthClientId });
      grant.addOIDCScope(MESSENGER_SCOPE);
      const fresh: string = await grant.save();
      // Сравнение с обменом: грант меняем, только если связка всё ещё ACTIVE и на
      // ней тот грант, что мы видели. Параллельный выпуск или отзыв не должны
      // оставить живой грант, о котором связка не знает: его токены было бы
      // нечем отозвать.
      const { count } = await this.prisma.partnerLink.updateMany({
        where: { id: link.id, status: 'ACTIVE', grantId: link.grantId },
        data: { grantId: fresh },
      });
      if (count === 0) {
        await this.provider.Grant.adapter.destroy(fresh);
        if (retried) throw new ConflictException('link_changed');
        const current = await this.prisma.partnerLink.findUnique({
          where: { id: link.id },
          select: { userId: true, grantId: true, status: true },
        });
        if (!current || current.status !== 'ACTIVE') throw new ConflictException('link_not_active');
        return this.issueAccessToken(
          { id: link.id, userId: current.userId, grantId: current.grantId },
          partner,
          true,
        );
      }
      // У связки никогда не бывает двух живых грантов: иначе отзыв в это окно
      // уничтожил бы только новый, и токены старого пережили бы его. Цена —
      // токены старого гранта (ему оставалось меньше минуты, или он чужой)
      // гаснут раньше срока; клиенты на 401 просто просят новый. При проигранном
      // обмене старый грант не трогаем: им распоряжается победитель.
      if (link.grantId) await this.provider.Grant.adapter.destroy(link.grantId);
      grantId = fresh;
    }

    const at = new this.provider.AccessToken({
      accountId: link.userId,
      client,
      grantId,
      scope: MESSENGER_SCOPE,
      gty: PARTNER_TOKEN_GTY,
    });
    // Токен не должен пережить свой грант: verify требует живой грант, и токен,
    // выданный «на 15 минут», умер бы молча раньше срока.
    if (live && usable && live.exp - now < at.expiration) at.expiresIn = live.exp - now;
    const accessToken: string = await at.save();
    // Срок — из настроек провайдера (ttl.AccessToken), а не из своей копии:
    // поменяют TTL глобально — партнёр получит правду, а не старые 900 секунд.
    const expiresIn =
      typeof at.expiration === 'number' ? at.expiration : PARTNER_ACCESS_TOKEN_TTL_SECONDS;
    return { accessToken, expiresIn, grantId: grantId as string };
  }

  /**
   * Гасит грант и все его токены. Сначала сам грант: verify требует живой грант,
   * поэтому его уничтожение разом гасит все токены, включая выпущенные в эту
   * самую секунду. Потом — уборка записей токенов. Повторный вызов безопасен.
   */
  async revokeGrant(grantId: string): Promise<void> {
    await this.provider.Grant.adapter.destroy(grantId);
    await this.provider.AccessToken.revokeByGrantId(grantId);
  }

  /**
   * Опознаёт партнёрский токен мессенджера. null — это не он: не наш формат,
   * не выпущен партнёрским API, истёк, грант отозван, без scope, партнёр
   * выключен или весь API выключен. Сбой хранилища токенов — 503, а не
   * «неверный токен» (как в McpAuthGuard).
   */
  async verify(token: string): Promise<PartnerPrincipal | null> {
    // Чужой токен (прежде всего истёкший JWT приложения TalerID — самый частый 401)
    // не должен ходить в Redis: иначе при сбое Redis он получит 503 вместо 401,
    // и приложение так и не станет обновлять токен.
    if (process.env.PARTNER_API_ENABLED !== 'true' || !PARTNER_TOKEN_FORMAT.test(token ?? '')) return null;
    let at: any;
    let grant: any;
    try {
      at = await this.provider.AccessToken.find(token);
      grant = at?.grantId ? await this.provider.Grant.find(at.grantId) : undefined;
    } catch (err) {
      this.logger.warn(`partner token lookup failed: ${(err as Error).message}`);
      throw new ServiceUnavailableException('Token validation unavailable');
    }
    if (!at?.accountId || at.isExpired || at.gty !== PARTNER_TOKEN_GTY) return null;
    // Грант жив и принадлежит тому же человеку и клиенту — то же правило, что
    // oidc-provider применяет в userinfo и introspection. Отзыв связки уничтожает
    // её грант, поэтому все её токены перестают приниматься разом.
    if (!grant || grant.accountId !== at.accountId || grant.clientId !== at.clientId) return null;
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
