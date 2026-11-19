import { KybPollerService } from './kyb-poller.service';

const DAY_MS = 24 * 60 * 60 * 1000;

interface ApplicantOpts {
  id?: unknown;
  reviewStatus?: string;
  reviewRejectType?: string;
  reviewDate?: string;
  companyInfo?: object;
}

// ⚠️ welID отдаёт реквизиты в корневом companyInfo (не info.companyInfo).
const applicant = (answer?: 'GREEN' | 'RED', opts: ApplicantOpts = {}) => {
  const {
    reviewStatus = 'completed',
    reviewRejectType,
    reviewDate,
    companyInfo = { companyName: 'ООО «Ромашка»' },
  } = opts;
  // Не дефолт деструктуризации: явный { id: undefined } должен остаться без id.
  const id = 'id' in opts ? opts.id : 'app-1';
  return {
    id,
    companyInfo,
    ...(answer
      ? {
          review: {
            reviewStatus,
            ...(reviewDate ? { reviewDate } : {}),
            reviewResult: {
              reviewAnswer: answer,
              ...(reviewRejectType ? { reviewRejectType } : {}),
            },
          },
        }
      : {}),
  };
};

describe('KybPollerService', () => {
  let prisma: any;
  let tx: any;
  let kyc: any;
  let svc: KybPollerService;
  let log: jest.SpyInstance;

  beforeEach(() => {
    tx = {
      tenant: { updateMany: jest.fn().mockResolvedValue({ count: 1 }) },
      companyKybProfile: { upsert: jest.fn().mockResolvedValue({}) },
    };
    prisma = {
      tenant: {
        findMany: jest.fn().mockResolvedValue([]),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      $transaction: jest.fn(async (fn: (t: any) => unknown) => fn(tx)),
    };
    kyc = { getApplicantByExternalUserId: jest.fn() };
    svc = new KybPollerService(prisma, kyc);
    log = jest.spyOn(svc['logger'], 'log').mockImplementation(() => undefined);
    jest.spyOn(svc['logger'], 'warn').mockImplementation(() => undefined);
  });

  describe('selection', () => {
    it('polls pending and snapshot-less verified companies, both within 30 days, newest first', async () => {
      await svc.pollCompanies();
      const args = prisma.tenant.findMany.mock.calls[0][0];
      expect(args.where.OR).toEqual([
        { kybStatus: 'PENDING', updatedAt: { gte: expect.any(Date) } },
        { kybStatus: 'VERIFIED', kybProfile: { is: null }, updatedAt: { gte: expect.any(Date) } },
      ]);
      expect(args.orderBy).toEqual({ updatedAt: 'desc' });
      const [pending, verified] = args.where.OR;
      expect(verified.updatedAt.gte).toEqual(pending.updatedAt.gte);
      const age = Date.now() - pending.updatedAt.gte.getTime();
      expect(age).toBeGreaterThanOrEqual(30 * DAY_MS);
      expect(age).toBeLessThan(30 * DAY_MS + 60_000);
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
      expect(tx.tenant.updateMany).toHaveBeenCalledTimes(1);
      expect(tx.tenant.updateMany.mock.calls[0][0].where.id).toBe('t-2');
      expect(tx.companyKybProfile.upsert.mock.calls[0][0].where).toEqual({ tenantId: 't-2' });
    });
  });

  describe('GREEN', () => {
    it('→ VERIFIED and the snapshot in one transaction, only over PENDING or VERIFIED', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN'));
      await svc.syncTenant('t-1', 'PENDING');
      expect(tx.tenant.updateMany).toHaveBeenCalledWith({
        where: { id: 't-1', kybStatus: { in: ['PENDING', 'VERIFIED'] } },
        data: { kybStatus: 'VERIFIED', sumsubApplicantId: 'app-1' },
      });
      const upsert = tx.companyKybProfile.upsert.mock.calls[0][0];
      expect(upsert.where).toEqual({ tenantId: 't-1' });
      const fields = { applicantId: 'app-1', legalName: 'ООО «Ромашка»', raw: { companyName: 'ООО «Ромашка»' } };
      expect(upsert.create).toMatchObject({ tenantId: 't-1', ...fields, verifiedAt: expect.any(Date) });
      expect(upsert.update).toMatchObject({ ...fields, verifiedAt: expect.any(Date) });
      expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
      expect(log).toHaveBeenCalledWith(expect.stringContaining('→ VERIFIED'));
    });

    it('an admin decision made meanwhile wins: status not PENDING/VERIFIED → no snapshot', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN'));
      tx.tenant.updateMany.mockResolvedValue({ count: 0 }); // админ успел выставить REJECTED
      await svc.syncTenant('t-1', 'PENDING');
      expect(tx.companyKybProfile.upsert).not.toHaveBeenCalled();
      expect(log).not.toHaveBeenCalledWith(expect.stringContaining('→ VERIFIED'));
    });

    it('verifiedAt is the welID review date when it parses', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(
        applicant('GREEN', { reviewDate: '2026-11-18 14:05:00+0000' }),
      );
      await svc.syncTenant('t-1', 'PENDING');
      const upsert = tx.companyKybProfile.upsert.mock.calls[0][0];
      expect(upsert.create.verifiedAt).toEqual(new Date('2026-11-18T14:05:00.000Z'));
      expect(upsert.update.verifiedAt).toEqual(new Date('2026-11-18T14:05:00.000Z'));
    });

    it('an unparseable review date → verifiedAt is now', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN', { reviewDate: 'вчера' }));
      const before = Date.now();
      await svc.syncTenant('t-1', 'PENDING');
      const at: Date = tx.companyKybProfile.upsert.mock.calls[0][0].create.verifiedAt;
      expect(at.getTime()).toBeGreaterThanOrEqual(before);
      expect(at.getTime()).toBeLessThanOrEqual(Date.now());
    });

    it('a numeric welID id is stored normalized, as the mapper gives it', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN', { id: 42 }));
      await svc.syncTenant('t-1', 'PENDING');
      expect(tx.tenant.updateMany.mock.calls[0][0].data.sumsubApplicantId).toBe('42');
      expect(tx.companyKybProfile.upsert.mock.calls[0][0].create.applicantId).toBe('42');
    });
  });

  describe('RED', () => {
    it('FINAL → REJECTED only from PENDING', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED', { reviewRejectType: 'FINAL' }));
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.tenant.updateMany).toHaveBeenCalledWith({
        where: { id: 't-1', kybStatus: 'PENDING' },
        data: { kybStatus: 'REJECTED', sumsubApplicantId: 'app-1' },
      });
      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(log).toHaveBeenCalledWith(expect.stringContaining('→ REJECTED'));
    });

    it('without reviewRejectType is treated as final', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED'));
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.tenant.updateMany).toHaveBeenCalledWith({
        where: { id: 't-1', kybStatus: 'PENDING' },
        data: { kybStatus: 'REJECTED', sumsubApplicantId: 'app-1' },
      });
    });

    it('RETRY → stays PENDING, nothing written (the company may fix and resubmit)', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED', { reviewRejectType: 'RETRY' }));
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('for a VERIFIED company changes nothing', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED', { reviewRejectType: 'FINAL' }));
      await svc.syncTenant('t-1', 'VERIFIED');
      expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('a status already moved on (count 0) → no "REJECTED" log', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED', { reviewRejectType: 'FINAL' }));
      prisma.tenant.updateMany.mockResolvedValue({ count: 0 });
      await svc.syncTenant('t-1', 'PENDING');
      expect(log).not.toHaveBeenCalledWith(expect.stringContaining('→ REJECTED'));
    });
  });

  describe('nothing to act on', () => {
    it('an applicant without id is skipped — no snapshot keyed by an empty id', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN', { id: undefined }));
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('no applicant yet or no decision yet → nothing changes', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValueOnce(null).mockResolvedValueOnce(applicant());
      await svc.syncTenant('t-1', 'PENDING');
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });

    it('a review not completed yet (resubmission pending) with an old GREEN → nothing written', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN', { reviewStatus: 'pending' }));
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.$transaction).not.toHaveBeenCalled();
      expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
    });

    it('a review not completed yet with an old RED → nothing written', async () => {
      kyc.getApplicantByExternalUserId.mockResolvedValue(
        applicant('RED', { reviewStatus: 'onHold', reviewRejectType: 'FINAL' }),
      );
      await svc.syncTenant('t-1', 'PENDING');
      expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
    });
  });
});
