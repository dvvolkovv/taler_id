import { KybPollerService } from './kyb-poller.service';

// ⚠️ welID отдаёт реквизиты в корневом companyInfo (не info.companyInfo).
const applicant = (answer?: 'GREEN' | 'RED', companyInfo: object = { companyName: 'ООО «Ромашка»' }) => ({
  id: 'app-1',
  companyInfo,
  ...(answer ? { review: { reviewResult: { reviewAnswer: answer } } } : {}),
});

describe('KybPollerService', () => {
  let prisma: any;
  let kyc: any;
  let svc: KybPollerService;

  beforeEach(() => {
    prisma = {
      tenant: {
        findMany: jest.fn().mockResolvedValue([]),
        update: jest.fn().mockReturnValue('tenant-update'),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      companyKybProfile: { upsert: jest.fn().mockReturnValue('profile-upsert') },
      $transaction: jest.fn().mockResolvedValue([]),
    };
    kyc = { getApplicantByExternalUserId: jest.fn() };
    svc = new KybPollerService(prisma, kyc);
  });

  it('polls pending companies and verified ones still missing a snapshot', async () => {
    await svc.pollCompanies();
    const where = prisma.tenant.findMany.mock.calls[0][0].where;
    expect(where.OR).toEqual([
      { kybStatus: 'PENDING', updatedAt: { gte: expect.any(Date) } },
      { kybStatus: 'VERIFIED', kybProfile: { is: null } },
    ]);
  });

  it('GREEN → VERIFIED and the snapshot in one transaction', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN'));
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.tenant.update).toHaveBeenCalledWith({
      where: { id: 't-1' },
      data: { kybStatus: 'VERIFIED', sumsubApplicantId: 'app-1' },
    });
    const upsert = prisma.companyKybProfile.upsert.mock.calls[0][0];
    expect(upsert.where).toEqual({ tenantId: 't-1' });
    expect(upsert.create).toMatchObject({ tenantId: 't-1', applicantId: 'app-1', legalName: 'ООО «Ромашка»' });
    expect(prisma.$transaction).toHaveBeenCalledWith(['tenant-update', 'profile-upsert']);
  });

  it('RED → REJECTED only from PENDING', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED'));
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.tenant.updateMany).toHaveBeenCalledWith({
      where: { id: 't-1', kybStatus: 'PENDING' },
      data: { kybStatus: 'REJECTED', sumsubApplicantId: 'app-1' },
    });
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('an applicant without id is skipped — no snapshot keyed by an empty id', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValue({ ...applicant('GREEN'), id: undefined });
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('no applicant yet or no decision yet → nothing changes', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValueOnce(null).mockResolvedValueOnce(applicant());
    await svc.syncTenant('t-1', 'PENDING');
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.tenant.update).not.toHaveBeenCalled();
    expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
  });

  it('a round still running → the next tick is skipped (rounds never overlap)', async () => {
    let release!: () => void;
    prisma.tenant.findMany.mockReturnValueOnce(new Promise((r) => { release = () => r([]); }));
    const first = svc.pollCompanies();
    await svc.pollCompanies(); // второй тик, пока первый ждёт
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(1);
    release();
    await first;
    await svc.pollCompanies();
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(2);
  });

  it('one failing company does not stop the round', async () => {
    prisma.tenant.findMany.mockResolvedValue([
      { id: 't-1', kybStatus: 'PENDING' },
      { id: 't-2', kybStatus: 'PENDING' },
    ]);
    kyc.getApplicantByExternalUserId
      .mockRejectedValueOnce(new Error('welID down'))
      .mockResolvedValueOnce(applicant('GREEN'));
    await svc.pollCompanies();
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
  });
});
