import { Test, TestingModule } from "@nestjs/testing";
import { VoiceService } from "./voice.service";
import { PrismaService } from "../prisma/prisma.service";
import { FileStorageService } from "../common/file-storage.service";
import { GatingService } from "../billing/services/gating.service";
import { MeteringService } from "../billing/services/metering.service";
import { LedgerService } from "../billing/services/ledger.service";
import { PricingService } from "../billing/services/pricing.service";

const mockPrisma = {
  callLog: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    findMany: jest.fn(),
  },
  profile: {
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  publicRoom: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    create: jest.fn(),
  },
  meetingSummary: {
    create: jest.fn(),
    update: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
  },
  conversationParticipant: {
    findMany: jest.fn(),
  },
  aiSession: {
    findUnique: jest.fn(),
  },
};

const mockFileStorage = {
  getObject: jest.fn(),
  uploadFile: jest.fn(),
};

const mockGating = {
  startSession: jest.fn(),
  endSession: jest.fn(),
};

const mockMetering = {
  reportUsage: jest.fn(),
};

const mockLedger = {
  debit: jest.fn(),
  refund: jest.fn(),
};

const mockPricing = {
  calculatePlanckCost: jest.fn(),
};

describe("VoiceService", () => {
  let service: VoiceService;

  beforeEach(async () => {
    jest.clearAllMocks();
    // Ensure the env vars the service reads are present for deterministic tests.
    process.env.LIVEKIT_API_KEY = "test-api-key";
    process.env.LIVEKIT_API_SECRET = "test-api-secret-must-be-long-enough-for-hmac-signing";
    process.env.LIVEKIT_WS_URL = "wss://test.example.com/livekit";

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: FileStorageService, useValue: mockFileStorage },
        { provide: GatingService, useValue: mockGating },
        { provide: MeteringService, useValue: mockMetering },
        { provide: LedgerService, useValue: mockLedger },
        { provide: PricingService, useValue: mockPricing },
      ],
    }).compile();

    service = module.get<VoiceService>(VoiceService);
  });

  describe("generateGroupCallToken", () => {
    it("returns LiveKit token + ws url for given groupCallId/userId", async () => {
      const result = await service.generateGroupCallToken("gc-123", "user-456");
      expect(result.token).toBeTruthy();
      expect(result.token.split(".").length).toBe(3); // JWT has 3 dot-separated segments
      expect(result.livekitWsUrl).toBe(process.env.LIVEKIT_WS_URL);
      // Decode JWT payload, room field should be "group-gc-123"
      const payload = JSON.parse(
        Buffer.from(result.token.split(".")[1], "base64").toString(),
      );
      expect(payload.video.room).toBe("group-gc-123");
      expect(payload.sub).toBe("user-456");
      expect(payload.video.canPublish).toBe(true);
      expect(payload.video.canSubscribe).toBe(true);
    });
  });
});
