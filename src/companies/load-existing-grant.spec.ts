import { createLoadExistingGrant } from './load-existing-grant';

const ctx = (opts: { scope: string; fresh?: string; remembered?: string; accountId?: string }) => ({
  oidc: {
    params: { scope: opts.scope },
    result: opts.fresh ? { consent: { grantId: opts.fresh } } : undefined,
    session: { accountId: opts.accountId ?? 'u', grantIdFor: () => opts.remembered },
    client: { clientId: 'trientes' },
    provider: { Grant: { find: jest.fn(async (id: string) => ({ id })) } },
  },
});

const verified = [{ role: 'OWNER', tenant: { id: 'a', name: 'A', logoUrl: null, kybStatus: 'VERIFIED', kybProfile: {} } }];

describe('loadExistingGrant', () => {
  it('a remembered grant is reused when companies are not requested', async () => {
    const db: any = { tenantMember: { findMany: jest.fn() } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid profile', remembered: 'g-old' }))).toEqual({ id: 'g-old' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
  });

  it('companies requested and an eligible company exists → no grant, consent screen shows', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue(verified) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies', remembered: 'g-old' }))).toBeUndefined();
  });

  it('companies requested but nothing eligible → remembered grant as usual', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue([]) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies', remembered: 'g-old' }))).toEqual({ id: 'g-old' });
  });

  it('the consent just given in this interaction is always used — no consent loop', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue(verified) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies', fresh: 'g-new', remembered: 'g-old' }))).toEqual({ id: 'g-new' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
  });

  it('nothing remembered → undefined', async () => {
    const db: any = { tenantMember: { findMany: jest.fn() } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid' }))).toBeUndefined();
  });

  // Подстрока не считается: 'companies_x' — не 'companies'.
  it('only the exact scope token counts', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue(verified) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies_x', remembered: 'g-old' }))).toEqual({ id: 'g-old' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
  });
});
