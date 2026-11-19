import {
  CompanySelectionError,
  findLastSelection,
  resolveSelection,
  saveSelection,
} from './company-selection';

const eligible = new Set(['a', 'b']);

describe('resolveSelection', () => {
  it('nothing chosen → signed in as a person, nothing shared', () => {
    expect(resolveSelection({}, eligible)).toEqual({ actAsTenantId: null, sharedTenantIds: [] });
  });

  it('the company you sign in as is always shared, first', () => {
    expect(resolveSelection({ actAs: 'b', companyIds: ['a'] }, eligible)).toEqual({
      actAsTenantId: 'b',
      sharedTenantIds: ['b', 'a'],
    });
  });

  it('duplicates collapse', () => {
    expect(resolveSelection({ actAs: 'person', companyIds: ['a', 'a'] }, eligible).sharedTenantIds).toEqual(['a']);
  });

  it('a company that is not eligible is refused, whether act-as or shared', () => {
    expect(() => resolveSelection({ actAs: 'zzz' }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: ['a', 'zzz'] }, eligible)).toThrow(CompanySelectionError);
  });

  it('malformed input is refused', () => {
    expect(() => resolveSelection({ actAs: 42 as any }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: 'a' as any }, eligible)).toThrow(CompanySelectionError);
  });
});

describe('saveSelection / findLastSelection', () => {
  it('stores one row per grant and drops this pair’s rows older than a grant lives', async () => {
    const db: any = {
      oAuthCompanySelection: {
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        create: jest.fn().mockResolvedValue({}),
      },
    };
    await saveSelection(db, {
      grantId: 'g-1', userId: 'u', clientId: 'c',
      selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
    const cutoff = db.oAuthCompanySelection.deleteMany.mock.calls[0][0].where.createdAt.lt as Date;
    expect(Date.now() - cutoff.getTime()).toBeGreaterThanOrEqual(30 * 864e5 - 1000);
    expect(db.oAuthCompanySelection.create).toHaveBeenCalledWith({
      data: { grantId: 'g-1', userId: 'u', clientId: 'c', actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
  });

  it('the last selection for this site is the newest row', async () => {
    const db: any = { oAuthCompanySelection: { findFirst: jest.fn().mockResolvedValue(null) } };
    await findLastSelection(db, 'u', 'c');
    expect(db.oAuthCompanySelection.findFirst).toHaveBeenCalledWith({
      where: { userId: 'u', clientId: 'c' },
      orderBy: { createdAt: 'desc' },
    });
  });
});
