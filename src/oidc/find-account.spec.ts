import { createFindAccount } from './find-account';
import { companyClaimsFor } from '../companies/company-claims';

jest.mock('../companies/company-claims', () => ({
  companyClaimsFor: jest.fn(),
}));

const claimsFor = companyClaimsFor as jest.MockedFunction<
  typeof companyClaimsFor
>;

const user = (over: Record<string, unknown> = {}) => ({
  id: 'u-1',
  email: 'anna@example.com',
  emailVerified: true,
  phone: '+43123',
  phoneVerified: false,
  deletedAt: null,
  profile: {
    firstName: 'Anna',
    lastName: 'Berger',
    middleName: null,
    language: 'de',
    updatedAt: new Date('2026-11-01T10:00:00Z'),
    walletAddress: '0xabc',
  },
  kycRecord: null,
  ...over,
});

const mockDb = (row: unknown): any => ({
  user: { findUnique: jest.fn().mockResolvedValue(row) },
});

describe('findAccount', () => {
  beforeEach(() => claimsFor.mockReset());

  it('unknown user → undefined', async () => {
    const db = mockDb(null);
    expect(await createFindAccount(db)({}, 'nobody')).toBeUndefined();
    expect(db.user.findUnique).toHaveBeenCalledWith({
      where: { id: 'nobody' },
      include: { profile: true, kycRecord: true },
    });
  });

  it('deleted or blocked account (deletedAt) → undefined, no claims', async () => {
    const db = mockDb(user({ deletedAt: new Date('2026-11-18T00:00:00Z') }));
    expect(
      await createFindAccount(db)({}, 'u-1', { grantId: 'g-1' }),
    ).toBeUndefined();
    expect(claimsFor).not.toHaveBeenCalled();
  });

  it('normal user: profile and email claims as before', async () => {
    const account = await createFindAccount(mockDb(user()))({}, 'u-1');
    expect(account?.accountId).toBe('u-1');
    expect(await account!.claims('userinfo', 'openid profile email')).toEqual({
      sub: 'u-1',
      given_name: 'Anna',
      family_name: 'Berger',
      middle_name: null,
      name: 'Anna Berger',
      locale: 'de',
      updated_at: Math.floor(Date.parse('2026-11-01T10:00:00Z') / 1000),
      email: 'anna@example.com',
      email_verified: true,
    });
    expect(claimsFor).not.toHaveBeenCalled();
  });

  it('companies scope in the ID token → no company lookup', async () => {
    const account = await createFindAccount(mockDb(user()))({}, 'u-1', {
      grantId: 'g-1',
    });
    expect(await account!.claims('id_token', 'openid companies')).toEqual({
      sub: 'u-1',
    });
    expect(claimsFor).not.toHaveBeenCalled();
  });

  it('companies scope in userinfo → acting_as/companies by this grant', async () => {
    const companies = {
      acting_as: { type: 'company' as const, company_id: 't-1', name: 'ACME' },
      companies: [],
    };
    claimsFor.mockResolvedValue(companies);
    const db = mockDb(user());
    const account = await createFindAccount(db)({}, 'u-1', {
      grantId: 'g-1',
    });
    expect(await account!.claims('userinfo', 'openid companies')).toEqual({
      sub: 'u-1',
      ...companies,
    });
    expect(claimsFor).toHaveBeenCalledWith(db, 'u-1', 'g-1');
  });
});
