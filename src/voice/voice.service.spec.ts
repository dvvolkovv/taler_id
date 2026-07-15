// Set LIVEKIT_WS_URL BEFORE importing VoiceService — the module captures it
// into a const at import time (LK_WS_URL), so mutating process.env later has
// no effect on token generation.
process.env.LIVEKIT_WS_URL = "wss://test.example.com/livekit";

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
    // Note: LIVEKIT_API_KEY / LIVEKIT_API_SECRET / LIVEKIT_WS_URL are bound
    // to module-level consts at import time — mutating process.env in
    // beforeEach has no effect on the service. LIVEKIT_WS_URL is set at
    // top-of-file before import; the API key/secret use the module-level
    // dev fallbacks ("lkdevkey" / "lkSecret2024TalerID").

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
      expect(result.livekitWsUrl).toBe("wss://test.example.com/livekit");
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

  describe("transcribeExistingRecording — ownership check", () => {
    // Sentinel thrown by fileStorage.getObject: reaching it proves the
    // ownership check passed (download happens right after the check).
    const SENTINEL = "SENTINEL_DOWNLOAD_REACHED";
    const OWNER_ID = "c79530ed-5ba8-44e3-b7d4-4a591c7c1db6";

    const meeting = (over: Record<string, unknown> = {}) => ({
      id: "m-1",
      roomName: "personal-c79530ed-36fc367a",
      recordingUrl: "https://x/messenger/files/download?key=recordings%2Fa.ogg",
      participantIds: ["guest-1a941683", "guest-50507c35"],
      durationSec: 60,
      ...over,
    });

    beforeEach(() => {
      mockPrisma.meetingSummary.update.mockResolvedValue({});
      mockFileStorage.getObject.mockRejectedValue(new Error(SENTINEL));
    });

    it("allows the personal-room owner even when participantIds contains only guests", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());
      await expect(
        service.transcribeExistingRecording(OWNER_ID, "m-1"),
      ).rejects.toThrow(SENTINEL);
    });

    it("allows a listed participant", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({ participantIds: ["user-abc"], roomName: "tmp-room" }),
      );
      await expect(
        service.transcribeExistingRecording("user-abc", "m-1"),
      ).rejects.toThrow(SENTINEL);
    });

    it("rejects a stranger (not participant, not room owner) with 403", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({ roomName: "personal-51ed7d1a-38e454fb" }),
      );
      await expect(
        service.transcribeExistingRecording(OWNER_ID, "m-1"),
      ).rejects.toThrow("Not a participant of this meeting");
    });
  });
});
