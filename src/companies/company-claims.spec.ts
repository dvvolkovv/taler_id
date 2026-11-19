import { buildCompanyClaims, companyClaimsFor } from './company-claims';
import type { EligibleCompany } from './company-eligibility';

const romashka: EligibleCompany = {
  tenantId: 'a',
  name: 'Ромашка',
  logoUrl: 'https://cdn/a.png',
  role: 'OWNER',
  profile: {
    legalName: 'ООО «Ромашка»', registrationNumber: '1027700132195', taxId: '7701234567',
    legalForm: 'LLC', incorporatedOn: new Date('2015-03-02T00:00:00Z'), country: 'RUS',
    city: 'Москва', legalAddress: 'Москва, ул. Пробная, 1', website: 'https://romashka.example',
    verifiedAt: new Date('2026-11-20T10:00:00Z'),
    // Поля снимка, которые сайту отдавать нельзя.
    raw: { beneficiaries: [{ name: 'X' }] }, applicantId: 'app-secret', id: 'p-1',
    tenantId: 'a', updatedAt: new Date(),
  } as any,
};

const CARD_KEYS = [
  'company_id', 'name', 'legal_name', 'registration_number', 'tax_id', 'legal_form',
  'incorporated_on', 'country', 'city', 'legal_address', 'website', 'logo_url',
  'logo_verified', 'kyb_status', 'kyb_verified_at', 'role',
];

describe('buildCompanyClaims', () => {
  it('no selection (old app, no companies) → person, nothing shared', () => {
    expect(buildCompanyClaims(null, [romashka], new Map())).toEqual({
      acting_as: { type: 'person' }, companies: [],
    });
  });

  it('signed in as a company: acting_as and its full card', () => {
    const c = buildCompanyClaims({ actAsTenantId: 'a', sharedTenantIds: ['a'] }, [romashka], new Map());
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: 'Ромашка' });
    expect(c.companies).toEqual([{
      company_id: 'a', name: 'Ромашка', legal_name: 'ООО «Ромашка»',
      registration_number: '1027700132195', tax_id: '7701234567', legal_form: 'LLC',
      incorporated_on: '2015-03-02', country: 'RUS', city: 'Москва',
      legal_address: 'Москва, ул. Пробная, 1', website: 'https://romashka.example',
      logo_url: 'https://cdn/a.png', logo_verified: false,
      kyb_status: 'verified', kyb_verified_at: '2026-11-20T10:00:00.000Z', role: 'OWNER',
    }]);
    // Только перечисленные поля: ни raw, ни applicantId, ни служебные id снимка.
    expect(Object.keys(c.companies[0]).sort()).toEqual([...CARD_KEYS].sort());
    expect(JSON.stringify(c)).not.toContain('app-secret');
    expect(JSON.stringify(c)).not.toContain('beneficiaries');
  });

  it('an empty act-as id is a company id, not a person: revoked, not silently person', () => {
    const c = buildCompanyClaims({ actAsTenantId: '', sharedTenantIds: [] }, [romashka], new Map());
    expect(c.acting_as).toEqual({ type: 'company', company_id: '', name: null, revoked: true });
    expect(c.companies).toEqual([]);
  });

  it('a company that lost eligibility since sign-in: acting_as revoked, card gone', () => {
    const c = buildCompanyClaims(
      { actAsTenantId: 'a', sharedTenantIds: ['a', 'b'] }, [], new Map([['a', 'Ромашка']]),
    );
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: 'Ромашка', revoked: true });
    expect(c.companies).toEqual([]);
  });

  it('a deleted company: revoked with name null', () => {
    const c = buildCompanyClaims({ actAsTenantId: 'a', sharedTenantIds: ['a'] }, [], new Map());
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: null, revoked: true });
  });

  it('shared companies keep the order of the selection and skip ones no longer eligible', () => {
    const lutik = { ...romashka, tenantId: 'b', name: 'Лютик' };
    const c = buildCompanyClaims({ actAsTenantId: null, sharedTenantIds: ['b', 'x', 'a'] }, [romashka, lutik], new Map());
    expect(c.companies.map((x) => x.company_id)).toEqual(['b', 'a']);
  });
});

describe('companyClaimsFor', () => {
  it('reads the selection of this grant and the current eligibility', async () => {
    const db: any = {
      oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue({ userId: 'u', actAsTenantId: null, sharedTenantIds: ['a'] }) },
      tenantMember: { findMany: jest.fn().mockResolvedValue([{
        role: 'OWNER',
        tenant: { id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED', kybProfile: romashka.profile },
      }]) },
      tenant: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const c = await companyClaimsFor(db, 'u', 'g-1');
    expect(db.oAuthCompanySelection.findUnique).toHaveBeenCalledWith({ where: { grantId: 'g-1' } });
    expect(c.acting_as).toEqual({ type: 'person' });
    expect(c.companies.map((x) => x.company_id)).toEqual(['a']);
  });

  it('no grant id on the token → person, nothing shared', async () => {
    const db: any = { oAuthCompanySelection: { findUnique: jest.fn() }, tenantMember: { findMany: jest.fn().mockResolvedValue([]) }, tenant: { findMany: jest.fn().mockResolvedValue([]) } };
    expect(await companyClaimsFor(db, 'u', undefined)).toEqual({ acting_as: { type: 'person' }, companies: [] });
    expect(db.oAuthCompanySelection.findUnique).not.toHaveBeenCalled();
  });

  it('a selection stored for another person is ignored', async () => {
    const db: any = {
      oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue({ userId: 'someone-else', actAsTenantId: 'a', sharedTenantIds: ['a'] }) },
      tenantMember: { findMany: jest.fn().mockResolvedValue([{
        role: 'OWNER',
        tenant: { id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED', kybProfile: romashka.profile },
      }]) },
      tenant: { findMany: jest.fn().mockResolvedValue([]) },
    };
    expect(await companyClaimsFor(db, 'u', 'g-1')).toEqual({ acting_as: { type: 'person' }, companies: [] });
    expect(db.tenant.findMany).not.toHaveBeenCalled();
  });

  it('act-as company still eligible: no extra name lookup, not revoked', async () => {
    const db: any = {
      oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue({ userId: 'u', actAsTenantId: 'a', sharedTenantIds: ['a'] }) },
      tenantMember: { findMany: jest.fn().mockResolvedValue([{
        role: 'OWNER',
        tenant: { id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED', kybProfile: romashka.profile },
      }]) },
      tenant: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const c = await companyClaimsFor(db, 'u', 'g-1');
    expect(db.tenant.findMany).not.toHaveBeenCalled();
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: 'Ромашка' });
    expect(c.acting_as).not.toHaveProperty('revoked');
  });

  it('stored empty act-as id: revoked, and its name is looked up like any other id', async () => {
    const db: any = {
      oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue({ userId: 'u', actAsTenantId: '', sharedTenantIds: [] }) },
      tenantMember: { findMany: jest.fn().mockResolvedValue([]) },
      tenant: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const c = await companyClaimsFor(db, 'u', 'g-1');
    expect(db.tenant.findMany).toHaveBeenCalledWith({ where: { id: '' }, select: { id: true, name: true } });
    expect(c.acting_as).toEqual({ type: 'company', company_id: '', name: null, revoked: true });
  });

  it('revoked act-as company: its name is looked up in the tenant table', async () => {
    const db: any = {
      oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue({ userId: 'u', actAsTenantId: 'a', sharedTenantIds: ['a'] }) },
      tenantMember: { findMany: jest.fn().mockResolvedValue([]) },
      tenant: { findMany: jest.fn().mockResolvedValue([{ id: 'a', name: 'Ромашка' }]) },
    };
    const c = await companyClaimsFor(db, 'u', 'g-1');
    expect(db.tenant.findMany).toHaveBeenCalledWith({ where: { id: 'a' }, select: { id: true, name: true } });
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: 'Ромашка', revoked: true });
  });
});
