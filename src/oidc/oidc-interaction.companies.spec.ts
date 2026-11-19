import { BadRequestException } from '@nestjs/common';
import { OidcInteractionController } from './oidc-interaction.controller';

describe('OidcInteractionController — companies', () => {
  let oidc: any;
  let companies: any;
  let prisma: any;
  let ctrl: OidcInteractionController;
  const res = () => ({
    json: jest.fn((x) => x),
    setHeader: jest.fn(),
    send: jest.fn(),
  });
  const req = (accept = 'application/json') => ({
    headers: { accept },
    ip: '1.1.1.1',
  });
  const grantSave = jest.fn().mockResolvedValue('g-1');
  const addOIDCScope = jest.fn();

  beforeEach(() => {
    oidc = {
      getInteractionDetails: jest.fn().mockResolvedValue({
        prompt: { name: 'consent' },
        params: { client_id: 'trientes', scope: 'openid profile companies' },
        session: { accountId: 'u' },
      }),
      findClient: jest
        .fn()
        .mockResolvedValue({ name: 'Trientes', logoUri: null }),
      getProvider: () => ({
        Grant: jest.fn().mockImplementation(() => ({
          addOIDCScope,
          save: grantSave,
        })),
      }),
      resolveInteractionRedirect: jest
        .fn()
        .mockResolvedValue('https://trientes.org/cb?code=x'),
    };
    companies = {
      consentBlock: jest.fn().mockResolvedValue({
        person: { name: 'Иван' },
        eligible: [],
        unverified: [],
        last_selection: null,
      }),
      validate: jest
        .fn()
        .mockResolvedValue({ actAsTenantId: 'a', sharedTenantIds: ['a'] }),
      save: jest.fn().mockResolvedValue(undefined),
    };
    prisma = { auditLog: { create: jest.fn() } };
    ctrl = new OidcInteractionController(oidc, prisma, {} as any, companies);
    grantSave.mockClear();
    addOIDCScope.mockClear();
  });

  it('consent details carry the companies block when companies is requested', async () => {
    const out: any = await ctrl.interaction('uid', req(), res());
    expect(companies.consentBlock).toHaveBeenCalledWith('u', 'trientes');
    expect(out.companies).toEqual({
      person: { name: 'Иван' },
      eligible: [],
      unverified: [],
      last_selection: null,
    });
  });

  it('no companies block when companies is not requested', async () => {
    oidc.getInteractionDetails.mockResolvedValue({
      prompt: { name: 'consent' },
      params: { client_id: 'x', scope: 'openid' },
      session: { accountId: 'u' },
    });
    const out: any = await ctrl.interaction('uid', req(), res());
    expect(out.companies).toBeUndefined();
    expect(companies.consentBlock).not.toHaveBeenCalled();
  });

  it('no companies block without a session, even when companies is requested', async () => {
    oidc.getInteractionDetails.mockResolvedValue({
      prompt: { name: 'consent' },
      params: { client_id: 'trientes', scope: 'openid profile companies' },
      session: undefined,
    });
    const out: any = await ctrl.interaction('uid', req(), res());
    expect(out.companies).toBeUndefined();
    expect(companies.consentBlock).not.toHaveBeenCalled();
  });

  it('consent validates the choice before the grant and stores it under the grant id', async () => {
    await ctrl.consent(
      'uid',
      { act_as: 'a', company_ids: ['a'] },
      req(),
      res(),
    );
    expect(companies.validate).toHaveBeenCalledWith('u', {
      actAs: 'a',
      companyIds: ['a'],
    });
    expect(companies.save).toHaveBeenCalledWith({
      grantId: 'g-1',
      userId: 'u',
      clientId: 'trientes',
      selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
    expect(companies.validate.mock.invocationCallOrder[0]).toBeLessThan(
      grantSave.mock.invocationCallOrder[0],
    );
  });

  it('a forged company: 400 and no grant', async () => {
    companies.validate.mockRejectedValue(
      new BadRequestException('company is not available'),
    );
    await expect(
      ctrl.consent('uid', { act_as: 'zzz' }, req(), res()),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(grantSave).not.toHaveBeenCalled();
  });

  it('companies not requested → no validation, no selection stored', async () => {
    oidc.getInteractionDetails.mockResolvedValue({
      prompt: { name: 'consent' },
      params: { client_id: 'x', scope: 'openid profile' },
      session: { accountId: 'u' },
    });
    await ctrl.consent('uid', { act_as: 'a' }, req(), res());
    expect(companies.validate).not.toHaveBeenCalled();
    expect(companies.save).not.toHaveBeenCalled();
    expect(grantSave).toHaveBeenCalledTimes(1);
  });

  it('storing the selection fails → the interaction is not finished (no redirect)', async () => {
    companies.save.mockRejectedValue(new Error('db down'));
    await expect(
      ctrl.consent('uid', { act_as: 'a', company_ids: ['a'] }, req(), res()),
    ).rejects.toThrow('db down');
    expect(oidc.resolveInteractionRedirect).not.toHaveBeenCalled();
    expect(prisma.auditLog.create).not.toHaveBeenCalled();
  });

  it('companies requested but not approved → no validation, no selection stored', async () => {
    await ctrl.consent(
      'uid',
      { approved_scopes: ['openid', 'profile'], act_as: 'a' },
      req(),
      res(),
    );
    expect(companies.validate).not.toHaveBeenCalled();
    expect(companies.save).not.toHaveBeenCalled();
    expect(grantSave).toHaveBeenCalledTimes(1);
  });

  it('approved scopes are cut down to the requested ones', async () => {
    await ctrl.consent(
      'uid',
      {
        approved_scopes: ['openid', 'companies', 'admin'],
        act_as: 'a',
        company_ids: ['a'],
      },
      req(),
      res(),
    );
    expect(addOIDCScope).toHaveBeenCalledTimes(1);
    expect(addOIDCScope).toHaveBeenCalledWith('openid companies');
    expect(companies.validate).toHaveBeenCalledWith('u', {
      actAs: 'a',
      companyIds: ['a'],
    });
  });

  it('approved_scopes that is not an array of strings: 400 and no grant', async () => {
    await expect(
      ctrl.consent(
        'uid',
        { approved_scopes: 'companies', act_as: 'a' },
        req(),
        res(),
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(grantSave).not.toHaveBeenCalled();
    expect(companies.validate).not.toHaveBeenCalled();
  });

  it('the JSON caller gets redirectTo after a company consent', async () => {
    const out: any = await ctrl.consent(
      'uid',
      { act_as: 'a', company_ids: ['a'] },
      req(),
      res(),
    );
    expect(out).toEqual({ redirectTo: 'https://trientes.org/cb?code=x' });
  });
});
