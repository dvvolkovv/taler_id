import type { CompanyKybProfile, KycStatus, TenantRole } from '@prisma/client';
import { COMPANY_ACTOR_ROLES } from './companies.constants';

export interface EligibleCompany {
  tenantId: string;
  name: string;
  logoUrl: string | null;
  role: TenantRole;
  profile: CompanyKybProfile;
}

export interface UnverifiedCompany {
  tenantId: string;
  name: string;
}

export interface MembershipRow {
  role: TenantRole;
  tenant: {
    id: string;
    name: string;
    logoUrl: string | null;
    kybStatus: KycStatus;
    kybProfile: CompanyKybProfile | null;
  };
}

/**
 * Одно правило на всё: и экран согласия, и выдача claims.
 * Подходит — человек OWNER/ADMIN, KYB пройден и есть снимок реквизитов.
 * OWNER/ADMIN без KYB — подсказка «пройдите проверку», а не вариант выбора.
 */
export function classifyCompanies(rows: MembershipRow[]): {
  eligible: EligibleCompany[];
  unverified: UnverifiedCompany[];
} {
  const eligible: EligibleCompany[] = [];
  const unverified: UnverifiedCompany[] = [];
  for (const { role, tenant } of rows) {
    if (!COMPANY_ACTOR_ROLES.includes(role)) continue;
    if (tenant.kybStatus === 'VERIFIED' && tenant.kybProfile) {
      eligible.push({
        tenantId: tenant.id,
        name: tenant.name,
        logoUrl: tenant.logoUrl,
        role,
        profile: tenant.kybProfile,
      });
    } else {
      unverified.push({ tenantId: tenant.id, name: tenant.name });
    }
  }
  return { eligible, unverified };
}

type Db = { tenantMember: { findMany: (args: any) => Promise<any[]> } };

/** Все компании человека, разложенные по правилу выше. */
export async function loadCompanies(db: Db, userId: string) {
  const rows = await db.tenantMember.findMany({
    // Заблокированный админом (выставлен только deletedAt) не должен по живому
    // refresh-токену представлять компанию — у такого человека компаний нет.
    where: { userId, user: { deletedAt: null } },
    include: { tenant: { include: { kybProfile: true } } },
    // tenantId — чтобы порядок на экране согласия не прыгал при равном invitedAt.
    orderBy: [{ invitedAt: 'asc' }, { tenantId: 'asc' }],
  });
  return classifyCompanies(rows as MembershipRow[]);
}
