import { createLoadExistingGrant } from './load-existing-grant';

const ctx = (opts: {
  scope: string;
  fresh?: string;
  remembered?: string;
  accountId?: string | null;
}) => ({
  oidc: {
    params: { scope: opts.scope },
    result: opts.fresh ? { consent: { grantId: opts.fresh } } : undefined,
    session: {
      // null — сессии без accountId (undefined оставляет значение по умолчанию)
      accountId: opts.accountId === null ? undefined : (opts.accountId ?? 'u'),
      grantIdFor: () => opts.remembered,
    },
    client: { clientId: 'trientes' },
    provider: { Grant: { find: jest.fn(async (id: string) => ({ id })) } },
  },
});

const verified = [
  {
    role: 'OWNER',
    tenant: {
      id: 'a',
      name: 'A',
      logoUrl: null,
      kybStatus: 'VERIFIED',
      kybProfile: {},
    },
  },
];

// Есть членство, но не подходит: KYB не пройден, реквизитов нет.
const notEligible = [
  {
    role: 'OWNER',
    tenant: {
      id: 'a',
      name: 'A',
      logoUrl: null,
      kybStatus: 'PENDING',
      kybProfile: null,
    },
  },
];

const mockDb = (members: unknown[], selection: unknown = null): any => ({
  tenantMember: { findMany: jest.fn().mockResolvedValue(members) },
  oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue(selection) },
});

describe('loadExistingGrant', () => {
  it('a remembered grant is reused when companies are not requested', async () => {
    const db = mockDb(verified, { actAsTenantId: 'a', sharedTenantIds: ['a'] });
    expect(
      await createLoadExistingGrant(db)(
        ctx({ scope: 'openid profile', remembered: 'g-old' }),
      ),
    ).toEqual({ id: 'g-old' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
    expect(db.oAuthCompanySelection.findUnique).not.toHaveBeenCalled();
  });

  it('companies requested and an eligible company exists → no grant, consent screen shows', async () => {
    const db = mockDb(verified);
    expect(
      await createLoadExistingGrant(db)(
        ctx({
          scope: 'openid companies',
          remembered: 'g-old',
          accountId: 'u-42',
        }),
      ),
    ).toBeUndefined();
    expect(db.tenantMember.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ userId: 'u-42' }),
      }),
    );
  });

  it('companies requested but nothing eligible → remembered grant as usual', async () => {
    const db = mockDb(notEligible);
    expect(
      await createLoadExistingGrant(db)(
        ctx({ scope: 'openid companies', remembered: 'g-old' }),
      ),
    ).toEqual({ id: 'g-old' });
  });

  describe('nothing eligible, remembered grant chose a company', () => {
    it('it acted as a company that no longer qualifies → no grant, consent screen shows', async () => {
      const db = mockDb(notEligible, {
        actAsTenantId: 'a',
        sharedTenantIds: ['a'],
      });
      expect(
        await createLoadExistingGrant(db)(
          ctx({ scope: 'openid companies', remembered: 'g-old' }),
        ),
      ).toBeUndefined();
      expect(db.oAuthCompanySelection.findUnique).toHaveBeenCalledWith({
        where: { grantId: 'g-old' },
      });
    });

    it('it signed in as a person and only shared a company → remembered grant', async () => {
      const db = mockDb(notEligible, {
        actAsTenantId: null,
        sharedTenantIds: ['a'],
      });
      expect(
        await createLoadExistingGrant(db)(
          ctx({ scope: 'openid companies', remembered: 'g-old' }),
        ),
      ).toEqual({ id: 'g-old' });
    });

    it('no selection stored for it → remembered grant', async () => {
      const db = mockDb(notEligible, null);
      expect(
        await createLoadExistingGrant(db)(
          ctx({ scope: 'openid companies', remembered: 'g-old' }),
        ),
      ).toEqual({ id: 'g-old' });
    });
  });

  it('the consent just given in this interaction is always used — no consent loop', async () => {
    const db = mockDb(verified);
    expect(
      await createLoadExistingGrant(db)(
        ctx({ scope: 'openid companies', fresh: 'g-new', remembered: 'g-old' }),
      ),
    ).toEqual({ id: 'g-new' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
    expect(db.oAuthCompanySelection.findUnique).not.toHaveBeenCalled();
  });

  it('nothing remembered → undefined', async () => {
    const db = mockDb([]);
    expect(
      await createLoadExistingGrant(db)(ctx({ scope: 'openid' })),
    ).toBeUndefined();
  });

  it('no accountId in the session → remembered grant, no DB query', async () => {
    const db = mockDb(verified, { actAsTenantId: 'a', sharedTenantIds: ['a'] });
    expect(
      await createLoadExistingGrant(db)(
        ctx({
          scope: 'openid companies',
          remembered: 'g-old',
          accountId: null,
        }),
      ),
    ).toEqual({ id: 'g-old' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
    expect(db.oAuthCompanySelection.findUnique).not.toHaveBeenCalled();
  });

  // Подстрока не считается: 'companies_x' — не 'companies'.
  it('only the exact scope token counts', async () => {
    const db = mockDb(verified);
    expect(
      await createLoadExistingGrant(db)(
        ctx({ scope: 'openid companies_x', remembered: 'g-old' }),
      ),
    ).toEqual({ id: 'g-old' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
  });
});
