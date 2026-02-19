/**
 * E2E test: KYC webhook GREEN → blockchain attestation (mocked) → GET /kyc/on-chain/:userId
 *
 * This test verifies the integration between KycService and BlockchainService.
 * The actual blockchain calls are mocked — real on-chain tests require testnet connectivity.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import * as crypto from 'crypto';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { BlockchainService } from '../src/blockchain/blockchain.service';

describe('Blockchain KYC flow (E2E)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let blockchainService: jest.Mocked<BlockchainService>;
  let authToken: string;
  let userId: string;

  const mockAttestVerification = jest.fn().mockResolvedValue({ txHash: '0xdeadbeef' });
  const mockGetOnChain = jest.fn().mockResolvedValue({
    kycStatus: 2,
    kycTimestamp: 1734567890,
    kybStatus: 0,
    isActive: true,
  });

  const TEST_EMAIL = 'blockchain-test-' + Date.now() + '@taler.uno';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(BlockchainService)
      .useValue({
        attestVerification: mockAttestVerification,
        attestKyb: jest.fn().mockResolvedValue(null),
        revokeVerification: jest.fn().mockResolvedValue(null),
        getOnChainVerification: mockGetOnChain,
        isConnected: true,
        onModuleInit: jest.fn(),
        onModuleDestroy: jest.fn(),
        hashTalerId: (id: string) =>
          crypto.createHash('sha256').update(id).digest(),
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new (require('@nestjs/common').ValidationPipe)({ whitelist: true }));
    await app.init();

    prisma = app.get(PrismaService);
    blockchainService = app.get(BlockchainService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('Step 1: Register user', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: TEST_EMAIL, password: 'Test1234!' });

    expect(res.status).toBe(201);
    authToken = res.body.accessToken;
    // Decode userId from JWT
    const payload = JSON.parse(
      Buffer.from(authToken.split('.')[1], 'base64').toString(),
    );
    userId = payload.sub;
    expect(userId).toBeDefined();
  });

  it('Step 2: Start KYC', async () => {
    const res = await request(app.getHttpServer())
      .post('/kyc/start')
      .set('Authorization', 'Bearer ' + authToken);

    expect(res.status).toBe(201);
    expect(res.body.sumsubApplicantId).toContain('mock_applicant_');
    expect(res.body.status).toBe('PENDING');
  });

  it('Step 3: Sumsub webhook GREEN → triggers blockchain attestation', async () => {
    // Get applicant ID from DB
    const kyc = await prisma.kycRecord.findUnique({ where: { userId } });
    expect(kyc).toBeDefined();

    const applicantId = kyc!.sumsubApplicantId;
    const webhookBody = JSON.stringify({
      applicantId,
      type: 'applicantReviewed',
      reviewResult: { reviewAnswer: 'GREEN' },
    });

    // Calculate Sumsub HMAC signature
    const secretKey = process.env.SUMSUB_SECRET_KEY || '';
    const sig = crypto.createHmac('sha256', secretKey).update(webhookBody).digest('hex');

    const res = await request(app.getHttpServer())
      .post('/kyc/webhook')
      .set('x-app-token', sig)
      .set('Content-Type', 'application/json')
      .send(webhookBody);

    expect([200, 201]).toContain(res.status);
    expect(res.body.received).toBe(true);

    // Give async blockchain call time to execute
    await new Promise((r) => setTimeout(r, 100));
  });

  it('Step 4: KYC status is VERIFIED in DB', async () => {
    const res = await request(app.getHttpServer())
      .get('/kyc/status')
      .set('Authorization', 'Bearer ' + authToken);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('VERIFIED');
  });

  it('Step 5: GET /kyc/on-chain/:userId returns mocked on-chain record', async () => {
    const res = await request(app.getHttpServer())
      .get('/kyc/on-chain/' + userId);

    expect(res.status).toBe(200);
    expect(res.body.talerId).toBe(userId);
    expect(res.body.onChain.kycStatus).toBe(2);
    expect(res.body.onChain.isActive).toBe(true);
    expect(res.body.statusLabel).toBe('Verified');
    expect(mockGetOnChain).toHaveBeenCalledWith(userId);
  });

  it('Step 6: blockchainService.attestVerification was called with userId and status=2', async () => {
    expect(mockAttestVerification).toHaveBeenCalledWith(userId, 2);
  });
});
