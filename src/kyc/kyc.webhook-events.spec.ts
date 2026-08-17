import { createHmac } from 'crypto';
import { KycService } from './kyc.service';

/**
 * Контракт welid (`webhooks.md`): любой ответ не-2xx означает повтор доставки, а
 * затем событие уходит в DLQ. Поэтому проверяется не только «правильно
 * обработали», но и «не ответили ошибкой на то, чего не знаем».
 */
describe('KYC webhook events', () => {
  const SECRET = 'shared-secret';
  let service: KycService;
  let prisma: any;

  const sign = (body: string) =>
    createHmac('sha1', SECRET).update(Buffer.from(body)).digest('hex');

  const call = (payload: any) => {
    const body = JSON.stringify(payload);
    return service.handleWebhook(Buffer.from(body), sign(body), undefined);
  };

  beforeEach(() => {
    process.env.SUMSUB_WEBHOOK_SECRET = SECRET;
    prisma = {
      kycRecord: {
        findFirst: jest.fn().mockResolvedValue({ id: 'k-1', userId: 'u-1', status: 'PENDING' }),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      user: { findUnique: jest.fn().mockResolvedValue(null) },
    };
    const blockchain = { attestVerification: jest.fn().mockResolvedValue(null) };
    const email = { sendKycStatusUpdate: jest.fn().mockResolvedValue(undefined) };
    service = new KycService(prisma, {} as any, blockchain as any, email as any);
  });

  it('acknowledges an event type it does not handle', async () => {
    // applicantOnLivenessCheck — событие, которого нет у Sumsub. Ответить
    // ошибкой значит отправить его в DLQ.
    await expect(call({ applicantId: 'a-1', type: 'applicantOnLivenessCheck' }))
      .resolves.toEqual({ received: true });
  });

  it('acknowledges a body that is not JSON at all', async () => {
    // Повтор доставки того же мусора ничего не изменит — незачем гонять его
    // по кругу до DLQ.
    const body = 'не json';
    await expect(
      service.handleWebhook(Buffer.from(body), sign(body), undefined),
    ).resolves.toEqual({ received: true });
  });

  it('acknowledges an applicant we have never seen', async () => {
    prisma.kycRecord.findFirst.mockResolvedValue(null);
    await expect(call({ applicantId: 'stranger', type: 'applicantReviewed' }))
      .resolves.toEqual({ received: true });
  });

  it('marks GREEN as verified', async () => {
    await call({
      applicantId: 'a-1', type: 'applicantReviewed',
      reviewResult: { reviewAnswer: 'GREEN' },
    });
    expect(prisma.kycRecord.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'VERIFIED' }) }),
    );
  });

  it('marks RED as rejected with the reason codes', async () => {
    await call({
      applicantId: 'a-1', type: 'applicantReviewed',
      reviewResult: { reviewAnswer: 'RED', rejectLabels: ['FORGERY', 'ID_INVALID'] },
    });
    expect(prisma.kycRecord.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: 'REJECTED',
          rejectionReason: 'FORGERY, ID_INVALID',
        }),
      }),
    );
  });

  it('puts a YELLOW decision back into review instead of ignoring it', async () => {
    // Раньше applicantOnHold проваливался мимо всех веток, и заявка оставалась
    // в прежнем статусе — человек висел «проверено» или «отклонено», хотя
    // решение отозвано на ручную проверку.
    await call({
      applicantId: 'a-1', type: 'applicantOnHold',
      reviewResult: { reviewAnswer: 'YELLOW' },
    });
    expect(prisma.kycRecord.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'PENDING' }) }),
    );
  });

  it('acts on monitoring flipping an approved applicant to RED', async () => {
    // Санкционное совпадение после одобрения: без этой ветки человек оставался
    // бы VERIFIED навсегда.
    await call({
      applicantId: 'a-1', type: 'applicantOnMonitoringUpdate',
      reviewResult: {
        reviewAnswer: 'RED', originalReviewAnswer: 'GREEN', rejectLabels: ['sanctions'],
      },
    });
    expect(prisma.kycRecord.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: 'REJECTED', rejectionReason: 'sanctions' }),
      }),
    );
  });

  it('revokes an already verified applicant when monitoring says RED', async () => {
    // Обычный отказ намеренно не трогает VERIFIED (защита от гонки с
    // опросником) — без снятия этой защиты мониторинговая ветка была бы
    // безвредной и бесполезной.
    prisma.kycRecord.findFirst.mockResolvedValue({
      id: 'k-1', userId: 'u-1', status: 'VERIFIED',
    });
    await call({
      applicantId: 'a-1', type: 'applicantOnMonitoringUpdate',
      reviewResult: { reviewAnswer: 'RED', rejectLabels: ['sanctions'] },
    });
    const { where, data } = prisma.kycRecord.updateMany.mock.calls[0][0];
    expect(where.status.notIn).toEqual(['REJECTED']);
    expect(data).toMatchObject({ status: 'REJECTED', verifiedAt: null });
  });

  it('does not let a plain review RED undo a verification', async () => {
    // Запоздавший колбэк или опросник не должны откатывать свежее GREEN.
    prisma.kycRecord.findFirst.mockResolvedValue({
      id: 'k-1', userId: 'u-1', status: 'VERIFIED',
    });
    await call({
      applicantId: 'a-1', type: 'applicantReviewed',
      reviewResult: { reviewAnswer: 'RED', rejectLabels: ['ID_INVALID'] },
    });
    const { where } = prisma.kycRecord.updateMany.mock.calls[0][0];
    expect(where.status.notIn).toEqual(['REJECTED', 'VERIFIED']);
  });

  it('acts on monitoring clearing an applicant back to GREEN', async () => {
    await call({
      applicantId: 'a-1', type: 'applicantOnMonitoringUpdate',
      reviewResult: { reviewAnswer: 'GREEN', originalReviewAnswer: 'RED' },
    });
    expect(prisma.kycRecord.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'VERIFIED' }) }),
    );
  });

  it('keeps handling applicantPending', async () => {
    await call({ applicantId: 'a-1', type: 'applicantPending' });
    expect(prisma.kycRecord.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'PENDING' }) }),
    );
  });

  it('tolerates unknown extra keys in the envelope', async () => {
    await expect(call({
      applicantId: 'a-1', type: 'applicantReviewed',
      reviewResult: { reviewAnswer: 'GREEN' },
      documents: [{ idDocType: 'PASSPORT' }],
      scoringResult: { score: 12, band: 'LOW' },
      somethingWeHaveNeverSeen: true,
      createdAtMs: '1755408900123',
    })).resolves.toEqual({ received: true });
  });

  it('still refuses a bad signature', async () => {
    await expect(
      service.handleWebhook(Buffer.from('{"applicantId":"a-1"}'), 'deadbeef', undefined),
    ).rejects.toThrow();
  });
});
