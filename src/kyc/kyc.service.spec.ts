import { Test, TestingModule } from '@nestjs/testing';
import { KycService } from './kyc.service';
import { BlockchainService } from '../blockchain/blockchain.service';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import * as crypto from 'crypto';

const mockPrisma = {
  kycRecord: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
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

describe('KycService', () => {
  let service: KycService;

  beforeEach(async () => {
    jest.clearAllMocks();
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
      ],
    }).compile();
    service = module.get<KycService>(KycService);
  });

  describe('getKycStatus', () => {
    it('returns UNVERIFIED when no KYC record exists', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      const result = await service.getKycStatus('user-1');
      expect(result.status).toBe('UNVERIFIED');
    });

    it('returns existing status when record exists', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ id: 'k1', status: 'VERIFIED', verifiedAt: new Date(), rejectionReason: null });
      const result = await service.getKycStatus('user-1');
      expect(result.status).toBe('VERIFIED');
    });

    it('returns PENDING status', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ id: 'k2', status: 'PENDING', verifiedAt: null, rejectionReason: null });
      const result = await service.getKycStatus('user-2');
      expect(result.status).toBe('PENDING');
    });

    it('returns rejection reason when REJECTED', async () => {
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ id: 'k3', status: 'REJECTED', verifiedAt: null, rejectionReason: 'Document expired' });
      const result = await service.getKycStatus('user-3');
      expect(result.status).toBe('REJECTED');
      expect(result.rejectionReason).toBe('Document expired');
    });
  });

  describe('handleWebhook', () => {
    it('throws BadRequestException for invalid HMAC signature', async () => {
      const body = Buffer.from(JSON.stringify({ type: 'applicantReviewed', applicantId: 'app-1' }));
      await expect(service.handleWebhook(body, 'wrong-signature')).rejects.toThrow(BadRequestException);
    });

    it('updates status to VERIFIED on GREEN review', async () => {
      const secretKey = 'test_secret';
      const payload = { type: 'applicantReviewed', applicantId: 'sumsub-1', reviewResult: { reviewAnswer: 'GREEN' } };
      const body = Buffer.from(JSON.stringify(payload));
      const sig = crypto.createHmac('sha256', secretKey).update(body).digest('hex');

      mockPrisma.kycRecord.findFirst.mockResolvedValue({ id: 'k1', sumsubApplicantId: 'sumsub-1' });
      mockPrisma.kycRecord.update.mockResolvedValue({ id: 'k1', status: 'VERIFIED' });

      const result = await service.handleWebhook(body, sig);
      expect(result).toHaveProperty('received', true);
      expect(mockPrisma.kycRecord.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ status: 'VERIFIED' }) })
      );
    });

    it('updates status to REJECTED on RED review', async () => {
      const secretKey = 'test_secret';
      const payload = { type: 'applicantReviewed', applicantId: 'sumsub-2', reviewResult: { reviewAnswer: 'RED', rejectLabels: ['DOC_EXPIRED'] } };
      const body = Buffer.from(JSON.stringify(payload));
      const sig = crypto.createHmac('sha256', secretKey).update(body).digest('hex');

      mockPrisma.kycRecord.findFirst.mockResolvedValue({ id: 'k2', sumsubApplicantId: 'sumsub-2' });
      mockPrisma.kycRecord.update.mockResolvedValue({ id: 'k2', status: 'REJECTED' });

      const result = await service.handleWebhook(body, sig);
      expect(result).toHaveProperty('received', true);
      expect(mockPrisma.kycRecord.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ status: 'REJECTED' }) })
      );
    });

    it('skips processing if applicantId not found in DB', async () => {
      const secretKey = 'test_secret';
      const payload = { type: 'applicantReviewed', applicantId: 'unknown', reviewResult: { reviewAnswer: 'GREEN' } };
      const body = Buffer.from(JSON.stringify(payload));
      const sig = crypto.createHmac('sha256', secretKey).update(body).digest('hex');

      mockPrisma.kycRecord.findFirst.mockResolvedValue(null);
      const result = await service.handleWebhook(body, sig);
      expect(result).toHaveProperty('received', true);
      expect(mockPrisma.kycRecord.update).not.toHaveBeenCalled();
    });
  });

  describe('HMAC signature logic', () => {
    it('produces different signatures for different secrets', () => {
      const body = JSON.stringify({ type: 'test' });
      const sig1 = crypto.createHmac('sha256', 'secret-a').update(body).digest('hex');
      const sig2 = crypto.createHmac('sha256', 'secret-b').update(body).digest('hex');
      expect(sig1).not.toBe(sig2);
    });

    it('produces identical signatures for same secret and payload', () => {
      const body = JSON.stringify({ applicantId: 'app-123' });
      const sig1 = crypto.createHmac('sha256', 'shared').update(body).digest('hex');
      const sig2 = crypto.createHmac('sha256', 'shared').update(body).digest('hex');
      expect(sig1).toBe(sig2);
    });

    it('HMAC-SHA256 output is 64-char hex', () => {
      const sig = crypto.createHmac('sha256', 'key').update('data').digest('hex');
      expect(sig).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('startKyc', () => {
    it('creates applicant and returns PENDING status when user is found', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ id: 'user-1', email: 'test@example.com', phone: null });
      mockPrisma.kycRecord.upsert.mockResolvedValue({ userId: 'user-1', sumsubApplicantId: 'mock_applicant_user-1', status: 'PENDING' });

      const result = await service.startKyc('user-1');
      expect(result.status).toBe('PENDING');
      expect(result.sumsubApplicantId).toMatch(/^mock_applicant_/);
      expect(result.sdkToken).toMatch(/^mock_sdk_token_/);
    });

    it('upserts kycRecord with PENDING status', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ id: 'user-2', email: 'second@example.com', phone: null });
      mockPrisma.kycRecord.upsert.mockResolvedValue({ userId: 'user-2', sumsubApplicantId: 'mock_applicant_user-2', status: 'PENDING' });

      await service.startKyc('user-2');
      expect(mockPrisma.kycRecord.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: 'user-2' },
          create: expect.objectContaining({ status: 'PENDING' }),
          update: expect.objectContaining({ status: 'PENDING' }),
        })
      );
    });

    it('throws NotFoundException when user is not found', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await expect(service.startKyc('nonexistent-user')).rejects.toThrow(NotFoundException);
      expect(mockPrisma.kycRecord.upsert).not.toHaveBeenCalled();
    });

    it('uses phone as identifier when email is null', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ id: 'user-3', email: null, phone: '+1234567890' });
      mockPrisma.kycRecord.upsert.mockResolvedValue({ userId: 'user-3', sumsubApplicantId: 'mock_applicant_user-3', status: 'PENDING' });

      const result = await service.startKyc('user-3');
      expect(result.status).toBe('PENDING');
    });
  });

});
