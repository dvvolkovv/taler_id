import { classifyCompanies, loadCompanies } from './company-eligibility';

const profile = { legalName: 'ООО «Ромашка»', verifiedAt: new Date('2026-11-20T10:00:00Z') } as any;
const row = (role: string, kybStatus: string, kybProfile: any = profile, id = 't-1') => ({
  role,
  tenant: { id, name: `Компания ${id}`, logoUrl: null, kybStatus, kybProfile },
});

describe('classifyCompanies', () => {
  it('OWNER and ADMIN of a verified company with a snapshot are eligible', () => {
    const { eligible } = classifyCompanies([row('OWNER', 'VERIFIED', profile, 'a'), row('ADMIN', 'VERIFIED', profile, 'b')] as any);
    expect(eligible.map((c) => [c.tenantId, c.role])).toEqual([['a', 'OWNER'], ['b', 'ADMIN']]);
    expect(eligible[0].profile).toBe(profile);
  });

  it('OPERATOR and VIEWER never act for the company and get no hint either', () => {
    const r = classifyCompanies([row('OPERATOR', 'VERIFIED'), row('VIEWER', 'PENDING', null, 't-2')] as any);
    expect(r).toEqual({ eligible: [], unverified: [] });
  });

  it('an OWNER whose company has not passed KYB gets a hint, not an option', () => {
    const r = classifyCompanies([row('OWNER', 'PENDING', null), row('ADMIN', 'REJECTED', null, 't-2')] as any);
    expect(r.eligible).toEqual([]);
    expect(r.unverified).toEqual([{ tenantId: 't-1', name: 'Компания t-1' }, { tenantId: 't-2', name: 'Компания t-2' }]);
  });

  it('VERIFIED without a snapshot is not eligible yet', () => {
    const r = classifyCompanies([row('OWNER', 'VERIFIED', null)] as any);
    expect(r.eligible).toEqual([]);
    expect(r.unverified).toEqual([{ tenantId: 't-1', name: 'Компания t-1' }]);
  });
});

describe('loadCompanies', () => {
  it('reads all memberships of the person with the company snapshot, oldest first, and classifies them', async () => {
    const findMany = jest.fn().mockResolvedValue([row('OWNER', 'VERIFIED', profile, 'a'), row('VIEWER', 'VERIFIED', profile, 'b')]);
    const r = await loadCompanies({ tenantMember: { findMany } }, 'u-1');
    expect(findMany).toHaveBeenCalledWith({
      where: { userId: 'u-1' },
      include: { tenant: { include: { kybProfile: true } } },
      orderBy: { invitedAt: 'asc' },
    });
    expect(r.eligible.map((c) => c.tenantId)).toEqual(['a']);
    expect(r.unverified).toEqual([]);
  });
});
