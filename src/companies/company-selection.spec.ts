import {
  CompanySelectionError,
  findLastSelection,
  findSelection,
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

  it('an empty act_as is not "person" — it is a company id that is not available', () => {
    expect(() => resolveSelection({ actAs: '' }, eligible)).toThrow(CompanySelectionError);
  });

  it('the refusal does not echo the submitted id back', () => {
    const huge = 'x'.repeat(10_000);
    expect(() => resolveSelection({ actAs: huge }, eligible)).toThrow(
      new CompanySelectionError('company is not available'),
    );
    expect(() => resolveSelection({ companyIds: [huge] }, eligible)).toThrow(
      new CompanySelectionError('company is not available'),
    );
  });

  it('malformed input is refused', () => {
    expect(() => resolveSelection({ actAs: 42 as any }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: 'a' as any }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: [1] }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: [null] }, eligible)).toThrow(CompanySelectionError);
  });
});

describe('saveSelection / findSelection / findLastSelection', () => {
  afterEach(() => jest.restoreAllMocks());

  it('stores one row per grant and drops this pair’s rows older than a grant lives', async () => {
    const now = Date.UTC(2026, 10, 19, 12, 0, 0);
    jest.spyOn(Date, 'now').mockReturnValue(now);
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
    const where = db.oAuthCompanySelection.deleteMany.mock.calls[0][0].where;
    expect(where).toEqual({ userId: 'u', clientId: 'c', createdAt: { lt: expect.any(Date) } });
    const cutoff = (where.createdAt.lt as Date).getTime();
    const ttl = 30 * 864e5;
    expect(cutoff).toBeGreaterThanOrEqual(now - ttl - 1000);
    expect(cutoff).toBeLessThanOrEqual(now - ttl + 1000);
    expect(db.oAuthCompanySelection.create).toHaveBeenCalledWith({
      data: { grantId: 'g-1', userId: 'u', clientId: 'c', actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
  });

  it('the selection of a grant is looked up by its id', async () => {
    const db: any = { oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue(null) } };
    await findSelection(db, 'g-1');
    expect(db.oAuthCompanySelection.findUnique).toHaveBeenCalledWith({ where: { grantId: 'g-1' } });
  });

  it('the last selection for this site is the newest row, ties broken stably', async () => {
    const db: any = { oAuthCompanySelection: { findFirst: jest.fn().mockResolvedValue(null) } };
    await findLastSelection(db, 'u', 'c');
    expect(db.oAuthCompanySelection.findFirst).toHaveBeenCalledWith({
      where: { userId: 'u', clientId: 'c' },
      orderBy: [{ createdAt: 'desc' }, { grantId: 'desc' }],
    });
  });
});
