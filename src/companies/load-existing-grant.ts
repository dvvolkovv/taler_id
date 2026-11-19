import { COMPANIES_SCOPE } from './companies.constants';
import { loadCompanies } from './company-eligibility';

/** PrismaService, PrismaClient и клиент транзакции подходят одинаково. */
type GrantDb = Parameters<typeof loadCompanies>[0];

/**
 * loadExistingGrant для oidc-provider: выбор «войти как» — на каждом входе.
 *
 * Запомненное согласие не подставляем, если сайт просит `companies`, а у
 * человека есть подходящая компания, — тогда провайдер покажет экран
 * согласия. Согласие, данное в этом же взаимодействии (result.consent),
 * подставляем всегда, иначе экран показывался бы по кругу. В остальном —
 * поведение oidc-provider по умолчанию.
 */
export function createLoadExistingGrant(db: GrantDb) {
  return async (ctx: any) => {
    const oidc = ctx.oidc;
    const fresh = oidc.result?.consent?.grantId;
    if (fresh) return oidc.provider.Grant.find(fresh);

    const accountId = oidc.session?.accountId;
    const scopes = String(oidc.params?.scope ?? '').split(' ');
    if (accountId && scopes.includes(COMPANIES_SCOPE)) {
      const { eligible } = await loadCompanies(db, accountId);
      if (eligible.length > 0) return undefined;
    }

    const remembered = oidc.session?.grantIdFor(oidc.client.clientId);
    return remembered ? oidc.provider.Grant.find(remembered) : undefined;
  };
}
