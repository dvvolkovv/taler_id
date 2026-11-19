import { EligibleCompany, loadCompanies } from './company-eligibility';
import { findSelection } from './company-selection';

export type ActingAsClaim =
  | { type: 'person' }
  | { type: 'company'; company_id: string; name: string | null; revoked?: true };

export interface CompanyClaim {
  company_id: string;
  /** Название в Taler ID — владелец может менять, не проверено. */
  name: string;
  legal_name: string | null;
  registration_number: string | null;
  tax_id: string | null;
  legal_form: string | null;
  incorporated_on: string | null;
  country: string | null;
  city: string | null;
  legal_address: string | null;
  website: string | null;
  logo_url: string | null;
  logo_verified: false;
  kyb_status: 'verified';
  kyb_verified_at: string;
  role: string;
}

interface SelectionLike {
  actAsTenantId: string | null;
  sharedTenantIds: string[];
}

function toClaim(c: EligibleCompany): CompanyClaim {
  const p = c.profile;
  return {
    company_id: c.tenantId,
    name: c.name,
    legal_name: p.legalName,
    registration_number: p.registrationNumber,
    tax_id: p.taxId,
    legal_form: p.legalForm,
    incorporated_on: p.incorporatedOn ? p.incorporatedOn.toISOString().slice(0, 10) : null,
    country: p.country,
    city: p.city,
    legal_address: p.legalAddress,
    website: p.website,
    logo_url: c.logoUrl,
    logo_verified: false,
    kyb_status: 'verified',
    kyb_verified_at: p.verifiedAt.toISOString(),
    role: c.role,
  };
}

/**
 * Что сайт видит в /oauth/me по scope `companies`. Подходящие компании
 * проверяются на каждый запрос: снятая роль или отозванный KYB убирают компанию
 * сразу, а `acting_as` получает `revoked: true`.
 */
export function buildCompanyClaims(
  selection: SelectionLike | null,
  eligible: EligibleCompany[],
  knownNames: ReadonlyMap<string, string>,
): { acting_as: ActingAsClaim; companies: CompanyClaim[] } {
  if (!selection) return { acting_as: { type: 'person' }, companies: [] };
  const byId = new Map(eligible.map((c) => [c.tenantId, c]));

  let acting_as: ActingAsClaim = { type: 'person' };
  // Сравнение с null, а не проверка на истинность — то же правило, что в
  // resolveSelection (company-selection.ts): пустая строка — тоже id компании.
  if (selection.actAsTenantId !== null) {
    const id = selection.actAsTenantId;
    const company = byId.get(id);
    acting_as = company
      ? { type: 'company', company_id: id, name: company.name }
      : { type: 'company', company_id: id, name: knownNames.get(id) ?? null, revoked: true };
  }

  const companies = selection.sharedTenantIds
    .map((id) => byId.get(id))
    .filter((c): c is EligibleCompany => !!c)
    .map(toClaim);
  return { acting_as, companies };
}

/** Для findAccount провайдера: выбор этого согласия + текущая проверка. */
export async function companyClaimsFor(db: any, userId: string, grantId: string | undefined) {
  if (!grantId) return buildCompanyClaims(null, [], new Map());
  const [stored, { eligible }] = await Promise.all([
    findSelection(db, grantId),
    loadCompanies(db, userId),
  ]);
  // Выбор принадлежит тому, кто дал согласие; чужой — как будто выбора нет.
  const selection = stored && stored.userId === userId ? stored : null;
  const knownNames = new Map<string, string>();
  const actAs = selection?.actAsTenantId ?? null;
  if (actAs !== null && !eligible.some((c) => c.tenantId === actAs)) {
    const rows = await db.tenant.findMany({ where: { id: actAs }, select: { id: true, name: true } });
    for (const r of rows) knownNames.set(r.id, r.name);
  }
  return buildCompanyClaims(selection, eligible, knownNames);
}
