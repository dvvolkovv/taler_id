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
import { RoomChatBufferService } from './room-chat-buffer.service';

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
    updateMany: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
  },
  billingTransaction: {
    findMany: jest.fn(),
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

const mockChatBuffer = {
  append: jest.fn(),
  remove: jest.fn(),
  hitRateLimit: jest.fn(),
  read: jest.fn(),
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
        { provide: RoomChatBufferService, useValue: mockChatBuffer },
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
    // Acceptance is the marker now: the call returns `processing` and the work
    // runs detached. (It used to be proven by a sentinel thrown from the
    // download, which sat right after the check — the download has since moved
    // into the background half, where nothing the caller sees can reach it.)
    const OWNER_ID = "c79530ed-5ba8-44e3-b7d4-4a591c7c1db6";

    const meeting = (over: Record<string, unknown> = {}) => ({
      id: "m-1",
      roomName: "personal-c79530ed-36fc367a",
      recordingUrl: "https://x/messenger/files/download?key=recordings%2Fa.ogg",
      participantIds: ["guest-1a941683", "guest-50507c35"],
      durationSec: 60,
      status: "done",
      ...over,
    });

    beforeEach(() => {
      mockPrisma.meetingSummary.update.mockResolvedValue({});
      mockGating.startSession.mockResolvedValue({ id: "s-1" });
      mockGating.endSession.mockResolvedValue(undefined);
      mockPricing.calculatePlanckCost.mockResolvedValue(1n);
      mockLedger.debit.mockResolvedValue({ id: "tx-1" });
      mockLedger.refund.mockResolvedValue(undefined);
      // The detached half is not under test here; let its download fail so it
      // settles at once instead of reaching for anything real.
      mockFileStorage.getObject.mockRejectedValue(new Error("no download in tests"));
    });

    it("allows the personal-room owner even when participantIds contains only guests", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());
      await expect(
        service.transcribeExistingRecording(OWNER_ID, "m-1"),
      ).resolves.toMatchObject({ status: "processing" });
    });

    it("allows a listed participant", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({ participantIds: ["user-abc"], roomName: "tmp-room" }),
      );
      await expect(
        service.transcribeExistingRecording("user-abc", "m-1"),
      ).resolves.toMatchObject({ status: "processing" });
    });

    // What LiveKit actually stores for an app participant since
    // 4cb6870 (device-unique identity): `<userId>#<deviceHash>`. The recorder
    // hands those identities to /voice/meetings/save verbatim, so every real
    // call recorded from the phone lands with hashed ids in participantIds —
    // while the caller asking for a protocol is identified by a bare userId.
    // The meeting still shows up in the cabinet (that listing matches on
    // CallLog.participantIds, which are bare), so it reads as "I see my own
    // recording but cannot transcribe it".
    it("allows a participant whose id is stored as a device-scoped LiveKit identity", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({
          roomName: "call-b55fe6f9-f053-4010-ad3e-bc34cc4efc98",
          participantIds: [
            "fc7d449b-84ac-4048-b3c5-7e6d49a091e7#1d5589ab",
            "51a2323d-7080-4ba5-a084-688815053699#89455dbf",
          ],
        }),
      );
      await expect(
        service.transcribeExistingRecording(
          "fc7d449b-84ac-4048-b3c5-7e6d49a091e7",
          "m-1",
        ),
      ).resolves.toMatchObject({ status: "processing" });
    });

    // The suffix must not become a way in: matching has to be on the whole
    // userId, not a prefix of it.
    it("rejects a stranger whose id merely prefixes a participant identity", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({
          roomName: "tmp-room",
          participantIds: ["fc7d449b-84ac-4048-b3c5-7e6d49a091e7#1d5589ab"],
        }),
      );
      await expect(
        service.transcribeExistingRecording("fc7d449b", "m-1"),
      ).rejects.toThrow("Not a participant of this meeting");
    });

    it("rejects a stranger (not participant, not room owner) with 403", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({ roomName: "personal-51ed7d1a-38e454fb" }),
      );
      await expect(
        service.transcribeExistingRecording(OWNER_ID, "m-1"),
      ).rejects.toThrow("Not a participant of this meeting");
    });

    it("closes meetings abandoned mid-transcription and gives the money back", async () => {
      mockPrisma.meetingSummary.findMany.mockResolvedValue([{ id: "m-old" }]);
      mockPrisma.billingTransaction.findMany.mockResolvedValue([
        { id: "tx-orphan" },
      ]);
      mockPrisma.meetingSummary.updateMany.mockResolvedValue({ count: 1 });

      await service.sweepAbandonedTranscriptions();

      // Refund first, then close — a meeting marked failed with the pre-debit
      // still taken is the exact state four March meetings were left in.
      expect(mockLedger.refund).toHaveBeenCalledWith(
        "tx-orphan",
        expect.stringContaining("m-old"),
      );
      const [closed] = mockPrisma.meetingSummary.updateMany.mock
        .calls[0] as any[];
      expect(closed.data).toEqual({ status: "failed" });
      // Status is re-checked on the way out: the other node may have finished it
      // while we were refunding.
      expect(closed.where).toMatchObject({ id: "m-old", status: "processing" });
    });

    it("leaves a run that only just started alone", async () => {
      mockPrisma.meetingSummary.findMany.mockResolvedValue([]);

      await service.sweepAbandonedTranscriptions();

      const [query] = mockPrisma.meetingSummary.findMany.mock.calls[0] as any[];
      expect(query.where.status).toBe("processing");
      // An age bound is the whole point: without it the sweep would kill
      // whatever the other app node is transcribing right now.
      const cutoff: Date = query.where.transcriptionStartedAt.lt;
      const minutesBack = (Date.now() - cutoff.getTime()) / 60_000;
      expect(minutesBack).toBeGreaterThanOrEqual(30);
      // Rows predating the column carry no timestamp and must not be guessed at.
      expect(query.where.transcriptionStartedAt.not).toBeNull();
      expect(mockLedger.refund).not.toHaveBeenCalled();
    });

    it("survives a refund that loses the race to the other node", async () => {
      mockPrisma.meetingSummary.findMany.mockResolvedValue([{ id: "m-old" }]);
      mockPrisma.billingTransaction.findMany.mockResolvedValue([
        { id: "tx-orphan" },
      ]);
      mockPrisma.meetingSummary.updateMany.mockResolvedValue({ count: 1 });
      mockLedger.refund.mockRejectedValue(
        new Error("transaction tx-orphan already reversed"),
      );

      await expect(
        service.sweepAbandonedTranscriptions(),
      ).resolves.toBeUndefined();
      // The meeting still gets closed — losing the refund race means someone
      // else already paid it back, not that the row should stay stuck.
      expect(mockPrisma.meetingSummary.updateMany).toHaveBeenCalled();
    });

    it("starts even if the sweep fails", async () => {
      mockPrisma.meetingSummary.findMany.mockRejectedValue(
        new Error("db is having a moment"),
      );

      await expect(service.onModuleInit()).resolves.toBeUndefined();
    });

    it("stamps the start of the attempt so the sweep can date it", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());

      await service.transcribeExistingRecording(OWNER_ID, "m-1");

      const stamped = mockPrisma.meetingSummary.update.mock.calls
        .map(([arg]: any) => arg.data)
        .find((d: any) => d.status === "processing");
      expect(stamped.transcriptionStartedAt).toBeInstanceOf(Date);
    });

    it("refuses to start a second pass, and a second charge, while one runs", async () => {
      mockPrisma.meetingSummary.findUnique.mockResolvedValue(
        meeting({ status: "processing" }),
      );
      await expect(
        service.transcribeExistingRecording(OWNER_ID, "m-1"),
      ).resolves.toMatchObject({ status: "processing", alreadyRunning: true });
      expect(mockLedger.debit).not.toHaveBeenCalled();
    });
  });
});
