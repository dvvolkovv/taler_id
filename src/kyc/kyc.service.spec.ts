import { Test, TestingModule } from '@nestjs/testing';
import { KycService } from './kyc.service';
import { BlockchainService } from '../blockchain/blockchain.service';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { EmailService } from '../email/email.service';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import * as crypto from 'crypto';

const mockPrisma = {
  kycRecord: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    findMany: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
    upsert: jest.fn(),
  },
  user: { findUnique: jest.fn() },
};

const mockConfig = {
  get: jest.fn((key: string) => {
    const config: Record<string, any> = {
      'sumsub.appToken': 'test_token',
      'sumsub.secretKey': 'test_secret',
      'sumsub.baseUrl': 'https://api.sumsub.com',
      'sumsub.webhookSecret': 'webhook_secret',
    };
    return config[key];
  }),
};

const mockEmail = {
  sendKycStatusUpdate: jest.fn().mockResolvedValue(undefined),
  sendInvite: jest.fn().mockResolvedValue(undefined),
  sendOtp: jest.fn().mockResolvedValue(undefined),
};

describe('KycService', () => {
  let service: KycService;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(async () => {
    jest.clearAllMocks();
    // Override Sumsub env vars so service uses mock paths (test_token triggers mock branches)
    originalEnv = { ...process.env };
    process.env.SUMSUB_APP_TOKEN = 'test_token';
    process.env.SUMSUB_SECRET_KEY = 'test_secret';
    process.env.SUMSUB_WEBHOOK_SECRET = 'test_secret';
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        KycService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: ConfigService, useValue: mockConfig },
        {
          provide: BlockchainService,
          useValue: {
            attestVerification: jest.fn().mockResolvedValue(null),
            attestKyb: jest.fn().mockResolvedValue(null),
            revokeVerification: jest.fn().mockResolvedValue(null),
            isConnected: false,
          },
        },
        { provide: EmailService, useValue: mockEmail },
      ],
    }).compile();
    service = module.get<KycService>(KycService);
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
  });

  describe('getKycStatus', () => {
    it('returns UNVERIFIED when no KYC record exists', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      const result = await service.getKycStatus('user-1');
      expect(result.status).toBe('UNVERIFIED');
    });

    it('returns existing status when record exists', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue({
        id: 'k1',
        status: 'VERIFIED',
        verifiedAt: new Date(),
        rejectionReason: null,
      });
      const result = await service.getKycStatus('user-1');
      expect(result.status).toBe('VERIFIED');
    });

    it('returns PENDING status', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue({
        id: 'k2',
        status: 'PENDING',
        verifiedAt: null,
        rejectionReason: null,
      });
      const result = await service.getKycStatus('user-2');
      expect(result.status).toBe('PENDING');
    });

    it('returns rejection reason when REJECTED', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue({
        id: 'k3',
        status: 'REJECTED',
        verifiedAt: null,
        rejectionReason: 'Document expired',
      });
      const result = await service.getKycStatus('user-3');
      expect(result.status).toBe('REJECTED');
      expect(result.rejectionReason).toBe('Document expired');
    });
  });

  describe('handleWebhook', () => {
    it('throws BadRequestException for invalid HMAC signature', async () => {
      const body = Buffer.from(
        JSON.stringify({ type: 'applicantReviewed', applicantId: 'app-1' }),
      );
      await expect(
        service.handleWebhook(body, 'wrong-signature'),
      ).rejects.toThrow(BadRequestException);
    });

    it('updates status to VERIFIED on GREEN review', async () => {
      const secretKey = 'test_secret';
      const payload = {
        type: 'applicantReviewed',
        applicantId: 'sumsub-1',
        reviewResult: { reviewAnswer: 'GREEN' },
      };
      const body = Buffer.from(JSON.stringify(payload));
      const sig = crypto
        .createHmac('sha256', secretKey)
        .update(body)
        .digest('hex');

      mockPrisma.kycRecord.findFirst.mockResolvedValue({
        id: 'k1',
        userId: 'user-verified',
        sumsubApplicantId: 'sumsub-1',
      });
      mockPrisma.kycRecord.updateMany.mockResolvedValue({ count: 1 });
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-verified',
        email: 'verified@example.com',
      });

      const result = await service.handleWebhook(body, sig);
      expect(result).toHaveProperty('received', true);
      expect(mockPrisma.kycRecord.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'VERIFIED' }),
        }),
      );
    });

    it('updates status to REJECTED on RED review', async () => {
      const secretKey = 'test_secret';
      const payload = {
        type: 'applicantReviewed',
        applicantId: 'sumsub-2',
        reviewResult: { reviewAnswer: 'RED', rejectLabels: ['DOC_EXPIRED'] },
      };
      const body = Buffer.from(JSON.stringify(payload));
      const sig = crypto
        .createHmac('sha256', secretKey)
        .update(body)
        .digest('hex');

      mockPrisma.kycRecord.findFirst.mockResolvedValue({
        id: 'k2',
        userId: 'user-rejected',
        sumsubApplicantId: 'sumsub-2',
      });
      mockPrisma.kycRecord.updateMany.mockResolvedValue({ count: 1 });
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-rejected',
        email: 'rejected@example.com',
      });

      const result = await service.handleWebhook(body, sig);
      expect(result).toHaveProperty('received', true);
      expect(mockPrisma.kycRecord.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'REJECTED' }),
        }),
      );
    });

    it('skips processing if applicantId not found in DB', async () => {
      const secretKey = 'test_secret';
      const payload = {
        type: 'applicantReviewed',
        applicantId: 'unknown',
        reviewResult: { reviewAnswer: 'GREEN' },
      };
      const body = Buffer.from(JSON.stringify(payload));
      const sig = crypto
        .createHmac('sha256', secretKey)
        .update(body)
        .digest('hex');

      mockPrisma.kycRecord.findFirst.mockResolvedValue(null);
      const result = await service.handleWebhook(body, sig);
      expect(result).toHaveProperty('received', true);
      expect(mockPrisma.kycRecord.updateMany).not.toHaveBeenCalled();
    });
  });

  describe('pollPendingApplicants', () => {
    afterEach(() => {
      (global.fetch as jest.Mock | undefined)?.mockRestore?.();
    });

    it('marks record VERIFIED when provider review is GREEN', async () => {
      mockPrisma.kycRecord.findMany.mockResolvedValue([
        { id: 'k1', userId: 'user-1', sumsubApplicantId: 'app-1' },
      ]);
      mockPrisma.kycRecord.updateMany.mockResolvedValue({ count: 1 });
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-1',
        email: 'u1@example.com',
      });
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'app-1',
          review: { reviewResult: { reviewAnswer: 'GREEN' } },
        }),
      }) as any;

      await service.pollPendingApplicants();

      expect(mockPrisma.kycRecord.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'VERIFIED' }),
        }),
      );
    });

    it('does nothing while review is still pending', async () => {
      mockPrisma.kycRecord.findMany.mockResolvedValue([
        { id: 'k1', userId: 'user-1', sumsubApplicantId: 'app-1' },
      ]);
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: 'app-1',
          review: { reviewStatus: 'init', reviewResult: null },
        }),
      }) as any;

      await service.pollPendingApplicants();

      expect(mockPrisma.kycRecord.updateMany).not.toHaveBeenCalled();
    });
  });

  describe('HMAC signature logic', () => {
    it('produces different signatures for different secrets', () => {
      const body = JSON.stringify({ type: 'test' });
      const sig1 = crypto
        .createHmac('sha256', 'secret-a')
        .update(body)
        .digest('hex');
      const sig2 = crypto
        .createHmac('sha256', 'secret-b')
        .update(body)
        .digest('hex');
      expect(sig1).not.toBe(sig2);
    });

    it('produces identical signatures for same secret and payload', () => {
      const body = JSON.stringify({ applicantId: 'app-123' });
      const sig1 = crypto
        .createHmac('sha256', 'shared')
        .update(body)
        .digest('hex');
      const sig2 = crypto
        .createHmac('sha256', 'shared')
        .update(body)
        .digest('hex');
      expect(sig1).toBe(sig2);
    });

    it('HMAC-SHA256 output is 64-char hex', () => {
      const sig = crypto
        .createHmac('sha256', 'key')
        .update('data')
        .digest('hex');
      expect(sig).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('startKyc', () => {
    const mockBaseUrl = 'https://mockss-test.up.railway.app';
    let originalFetch: typeof fetch;

    function mockFetchSequence(responses: Array<{ ok: boolean; body: any }>) {
      const queue = [...responses];
      (global as any).fetch = jest.fn(async () => {
        const next = queue.shift();
        if (!next) throw new Error('Unexpected extra fetch call');
        return {
          ok: next.ok,
          json: async () => next.body,
          statusText: next.ok ? 'OK' : 'Bad Request',
        };
      });
    }

    beforeEach(() => {
      originalFetch = global.fetch;
      process.env.SUMSUB_BASE_URL = mockBaseUrl;
      process.env.SUMSUB_LEVEL_NAME = 'trientes-kyc-level';
      process.env.SUMSUB_TTL_SECS = '600';
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it('issues token, resolves applicantId, upserts record, returns webSdkUrl', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-1',
        email: 'test@example.com',
        phone: null,
      });
      mockPrisma.kycRecord.upsert.mockResolvedValue({});
      mockFetchSequence([
        { ok: true, body: { token: '_act-sbx-abc123', userId: 'user-1' } },
        {
          ok: true,
          body: {
            id: 'applicant-uuid-1',
            createdAt: '2026-06-09T00:00:00Z',
            externalUserId: 'user-1',
            info: {},
            review: { reviewStatus: 'init' },
          },
        },
      ]);

      const result = await service.startKyc('user-1');

      expect(result.status).toBe('PENDING');
      expect(result.applicantId).toBe('applicant-uuid-1');
      expect(result.sumsubApplicantId).toBe('applicant-uuid-1');
      expect(result.sdkBaseUrl).toBe(mockBaseUrl);
      expect(result.webSdkUrl).toBe(
        `${mockBaseUrl}/idensic/sdk/checkup?accessToken=${encodeURIComponent('_act-sbx-abc123')}`,
      );
      expect(result.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('upserts kycRecord with PENDING status and resolved applicantId', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-2',
        email: 'second@example.com',
        phone: null,
      });
      mockPrisma.kycRecord.upsert.mockResolvedValue({});
      mockFetchSequence([
        { ok: true, body: { token: 'tok2', userId: 'user-2' } },
        { ok: true, body: { id: 'applicant-2', externalUserId: 'user-2' } },
      ]);

      await service.startKyc('user-2');
      expect(mockPrisma.kycRecord.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 'user-2' },
          create: expect.objectContaining({
            status: 'PENDING',
            sumsubApplicantId: 'applicant-2',
          }),
          update: expect.objectContaining({
            status: 'PENDING',
            sumsubApplicantId: 'applicant-2',
          }),
        }),
      );
    });

    it('throws NotFoundException when user is not found', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await expect(service.startKyc('nonexistent-user')).rejects.toThrow(
        NotFoundException,
      );
      expect(mockPrisma.kycRecord.upsert).not.toHaveBeenCalled();
    });

    it('throws BadRequestException when token issuance fails', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-3',
        email: 'x@y.z',
        phone: null,
      });
      mockFetchSequence([
        { ok: false, body: { description: 'rate limit' } },
      ]);

      await expect(service.startKyc('user-3')).rejects.toThrow(
        BadRequestException,
      );
      expect(mockPrisma.kycRecord.upsert).not.toHaveBeenCalled();
    });

    it('uses configured levelName when issuing token', async () => {
      process.env.SUMSUB_LEVEL_NAME = 'enhanced-kyc-level';
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'user-4',
        email: 'a@b.c',
        phone: null,
      });
      mockPrisma.kycRecord.upsert.mockResolvedValue({});
      const fetchMock = jest.fn().mockImplementation((async (
        _url: string,
        init?: RequestInit,
      ) => {
        if (init?.method === 'POST') {
          const body = JSON.parse(init.body as string);
          expect(body.levelName).toBe('enhanced-kyc-level');
          return {
            ok: true,
            json: async () => ({ token: 't', userId: 'user-4' }),
          };
        }
        return {
          ok: true,
          json: async () => ({ id: 'app-4', externalUserId: 'user-4' }),
        };
      }) as any);
      (global as any).fetch = fetchMock;

      await service.startKyc('user-4');
      expect(fetchMock).toHaveBeenCalled();
    });
  });
});
