import { BadRequestException } from '@nestjs/common';
import { CompanyConsentService } from './company-consent.service';

const verifiedRow = {
  role: 'OWNER',
  tenant: { id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED',
    kybProfile: { legalName: 'ООО «Ромашка»', verifiedAt: new Date() } },
};
const pendingRow = { role: 'ADMIN', tenant: { id: 'b', name: 'Лютик', logoUrl: null, kybStatus: 'PENDING', kybProfile: null } };

describe('CompanyConsentService', () => {
  let prisma: any;
  let svc: CompanyConsentService;

  beforeEach(() => {
    prisma = {
      tenantMember: { findMany: jest.fn().mockResolvedValue([verifiedRow, pendingRow]) },
      profile: { findUnique: jest.fn().mockResolvedValue({ firstName: 'Иван', lastName: 'Петров' }) },
      oAuthCompanySelection: {
        findFirst: jest.fn().mockResolvedValue({ actAsTenantId: 'a', sharedTenantIds: ['a'] }),
        deleteMany: jest.fn().mockResolvedValue({}),
        create: jest.fn().mockResolvedValue({}),
      },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
      $transaction: jest.fn((fn: any) => fn(prisma)),
    };
    svc = new CompanyConsentService(prisma);
  });

  it('describes the choice for the consent screen', async () => {
    expect(await svc.consentBlock('u', 'trientes')).toEqual({
      person: { name: 'Иван Петров' },
      eligible: [{ id: 'a', name: 'Ромашка', legal_name: 'ООО «Ромашка»', logo_url: null, role: 'OWNER' }],
      unverified: [{ id: 'b', name: 'Лютик' }],
      last_selection: { act_as: 'a', company_ids: ['a'] },
    });
    expect(prisma.oAuthCompanySelection.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'u', clientId: 'trientes' } }),
    );
    expect(prisma.profile.findUnique).toHaveBeenCalledWith({
      where: { userId: 'u' },
      select: { firstName: true, lastName: true },
    });
  });

  it('a stale last choice keeps only companies still eligible', async () => {
    prisma.oAuthCompanySelection.findFirst.mockResolvedValue({ actAsTenantId: 'gone', sharedTenantIds: ['gone', 'a'] });
    const b = await svc.consentBlock('u', 'trientes');
    expect(b.last_selection).toEqual({ act_as: 'person', company_ids: ['a'] });
  });

  it('no previous choice on this site → last_selection null; no profile → empty name', async () => {
    prisma.oAuthCompanySelection.findFirst.mockResolvedValue(null);
    prisma.profile.findUnique.mockResolvedValue(null);
    const b = await svc.consentBlock('u', 'trientes');
    expect(b.last_selection).toBeNull();
    expect(b.person).toEqual({ name: '' });
  });

  it('whitespace-only name parts are dropped', async () => {
    prisma.profile.findUnique.mockResolvedValue({ firstName: '  ', lastName: 'Петров' });
    const b = await svc.consentBlock('u', 'trientes');
    expect(b.person).toEqual({ name: 'Петров' });
  });

  it('the consent block carries no KYB internals', async () => {
    const leakyRow = {
      role: 'OWNER',
      tenant: {
        id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED',
        kybProfile: {
          legalName: 'ООО «Ромашка»', verifiedAt: new Date(),
          raw: { beneficiaries: [] }, applicantId: 'app-secret', taxId: '7701234567',
        },
      },
    };
    prisma.tenantMember.findMany.mockResolvedValue([leakyRow]);
    const s = JSON.stringify(await svc.consentBlock('u', 'trientes'));
    expect(s).not.toContain('app-secret');
    expect(s).not.toContain('beneficiaries');
    expect(s).not.toContain('7701234567');
  });

  it('validate refuses a company that is not eligible with 400', async () => {
    await expect(svc.validate('u', { actAs: 'b' })).rejects.toBeInstanceOf(BadRequestException);
  });

  it('validate returns the resolved selection for an eligible company', async () => {
    await expect(svc.validate('u', { actAs: 'a', companyIds: [] })).resolves.toEqual({ actAsTenantId: 'a', sharedTenantIds: ['a'] });
  });

  it('validate rethrows a non-selection error as is, not as 400', async () => {
    prisma.tenantMember.findMany.mockRejectedValue(new Error('db down'));
    const e = await svc.validate('u', { actAs: 'a' }).catch((err) => err);
    expect(e).toBeInstanceOf(Error);
    expect(e.message).toBe('db down');
    expect(e).not.toBeInstanceOf(BadRequestException);
  });

  it('save stores the selection and audits only when a company is shared', async () => {
    await svc.save({ grantId: 'g', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: null, sharedTenantIds: [] } });
    expect(prisma.oAuthCompanySelection.create).toHaveBeenCalledTimes(1);
    expect(prisma.auditLog.create).not.toHaveBeenCalled();
    await svc.save({ grantId: 'g2', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] } });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: { userId: 'u', action: 'OAUTH_COMPANIES_SHARED', meta: { grantId: 'g2', clientId: 'trientes', actAs: 'a', companyIds: ['a'] } },
    });
  });

  it('signed in as the person but shared a company → audited with actAs person', async () => {
    await svc.save({ grantId: 'g3', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: null, sharedTenantIds: ['a'] } });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: { userId: 'u', action: 'OAUTH_COMPANIES_SHARED', meta: { grantId: 'g3', clientId: 'trientes', actAs: 'person', companyIds: ['a'] } },
    });
  });

  it('save writes the selection and the audit in one transaction and fails if the audit fails', async () => {
    const boom = new Error('audit down');
    prisma.auditLog.create.mockRejectedValue(boom);
    await expect(
      svc.save({ grantId: 'g4', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] } }),
    ).rejects.toBe(boom);
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(prisma.oAuthCompanySelection.create).toHaveBeenCalledTimes(1);
  });
});
