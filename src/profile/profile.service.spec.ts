import { Test, TestingModule } from "@nestjs/testing";
import { ProfileService } from "./profile.service";
import { PrismaService } from "../prisma/prisma.service";
import { S3Service } from "./s3.service";
import { NotFoundException, BadRequestException } from "@nestjs/common";

const mockPrisma = {
  profile: {
    findUnique: jest.fn(),
    update: jest.fn(),
    deleteMany: jest.fn(),
  },
  user: {
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  kycRecord: {
    findUnique: jest.fn(),
    deleteMany: jest.fn(),
  },
  document: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    delete: jest.fn(),
    deleteMany: jest.fn(),
  },
  session: {
    findMany: jest.fn(),
    deleteMany: jest.fn(),
  },
  totpSecret: {
    deleteMany: jest.fn(),
  },
  $transaction: jest.fn(),
};

const mockS3 = {
  uploadEncrypted: jest.fn(),
  getPresignedUrl: jest.fn(),
  deleteFile: jest.fn(),
};

const PROFILE = {
  id: "profile-1",
  userId: "user-1",
  firstName: "John",
  lastName: "Doe",
  walletAddress: null,
  documents: [],
};

const USER = {
  email: "john@example.com",
  phone: "+1234567890",
  createdAt: new Date("2024-01-01"),
};

describe("ProfileService", () => {
  let service: ProfileService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProfileService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: S3Service, useValue: mockS3 },
      ],
    }).compile();
    service = module.get<ProfileService>(ProfileService);
  });

  // -----------------------------------------------------------------------
  describe("getProfile", () => {
    it("returns profile with kycStatus UNVERIFIED when no KYC record", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      mockPrisma.user.findUnique.mockResolvedValue(USER);

      const result = await service.getProfile("user-1");
      expect(result.kycStatus).toBe("UNVERIFIED");
      expect(result.email).toBe("john@example.com");
    });

    it("returns profile with kycStatus from KYC record", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: "VERIFIED" });
      mockPrisma.user.findUnique.mockResolvedValue(USER);

      const result = await service.getProfile("user-1");
      expect(result.kycStatus).toBe("VERIFIED");
    });

    it("throws NotFoundException when profile does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);

      await expect(service.getProfile("unknown-user")).rejects.toThrow(NotFoundException);
    });

    it("includes documents in the response", async () => {
      const docs = [{ id: "doc-1", type: "PASSPORT" }];
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: docs });
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      mockPrisma.user.findUnique.mockResolvedValue(USER);

      const result = await service.getProfile("user-1");
      expect(result.documents).toHaveLength(1);
    });
  });

  // -----------------------------------------------------------------------
  describe("updateProfile", () => {
    it("updates and returns the profile", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.profile.update.mockResolvedValue({ ...PROFILE, firstName: "Jane" });

      const result = await service.updateProfile("user-1", { firstName: "Jane" });
      expect(result.firstName).toBe("Jane");
      expect(mockPrisma.profile.update).toHaveBeenCalledWith(
        expect.objectContaining({ where: { userId: "user-1" } })
      );
    });

    it("throws NotFoundException when profile does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);

      await expect(service.updateProfile("missing-user", { firstName: "Jane" })).rejects.toThrow(NotFoundException);
      expect(mockPrisma.profile.update).not.toHaveBeenCalled();
    });

    it("converts dateOfBirth string to Date object", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      let captured: any;
      mockPrisma.profile.update.mockImplementation(async (args: any) => { captured = args; return { ...PROFILE }; });

      await service.updateProfile("user-1", { dateOfBirth: "1990-05-15" });
      expect(captured.data.dateOfBirth).toBeInstanceOf(Date);
    });
  });

  // -----------------------------------------------------------------------
  describe("linkWallet", () => {
    it("saves a valid EVM wallet address", async () => {
      const addr = "0xAbCd1234567890abcdef1234567890abCDeF1234";
      mockPrisma.profile.update.mockResolvedValue({ ...PROFILE, walletAddress: addr });

      const result = await service.linkWallet("user-1", { walletAddress: addr });
      expect(result.walletAddress).toBe(addr);
    });

    it("accepts lowercase hex address", async () => {
      const addr = "0xabcdef1234567890abcdef1234567890abcdef12";
      mockPrisma.profile.update.mockResolvedValue({ ...PROFILE, walletAddress: addr });

      await expect(service.linkWallet("user-1", { walletAddress: addr })).resolves.toBeDefined();
    });

    it("throws BadRequestException for address without 0x prefix", async () => {
      await expect(
        service.linkWallet("user-1", { walletAddress: "abcdef1234567890abcdef1234567890abcdef12" })
      ).rejects.toThrow(BadRequestException);
    });

    it("throws BadRequestException for address that is too short", async () => {
      await expect(
        service.linkWallet("user-1", { walletAddress: "0x1234" })
      ).rejects.toThrow(BadRequestException);
    });

    it("throws BadRequestException for address that is too long", async () => {
      await expect(
        service.linkWallet("user-1", { walletAddress: "0x" + "a".repeat(41) })
      ).rejects.toThrow(BadRequestException);
    });

    it("throws BadRequestException for address with invalid hex chars", async () => {
      await expect(
        service.linkWallet("user-1", { walletAddress: "0x" + "g".repeat(40) })
      ).rejects.toThrow(BadRequestException);
    });

    it("does not call prisma when address is invalid", async () => {
      await expect(
        service.linkWallet("user-1", { walletAddress: "not-a-wallet" })
      ).rejects.toThrow(BadRequestException);
      expect(mockPrisma.profile.update).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  describe("unlinkWallet", () => {
    it("sets walletAddress to null", async () => {
      mockPrisma.profile.update.mockResolvedValue({ ...PROFILE, walletAddress: null });

      const result = await service.unlinkWallet("user-1");
      expect(result.walletAddress).toBeNull();
      expect(mockPrisma.profile.update).toHaveBeenCalledWith({
        where: { userId: "user-1" },
        data: { walletAddress: null },
      });
    });
  });

  // -----------------------------------------------------------------------
  describe("uploadDocument", () => {
    const validFile = {
      originalname: "passport.jpg",
      mimetype: "image/jpeg",
      size: 1 * 1024 * 1024,
      buffer: Buffer.from("fake-image-data"),
    } as Express.Multer.File;

    it("uploads a valid document and returns metadata", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockS3.uploadEncrypted.mockResolvedValue(undefined);
      mockPrisma.document.create.mockResolvedValue({
        id: "doc-1",
        type: "PASSPORT",
        uploadedAt: new Date(),
      });

      const result = await service.uploadDocument("user-1", validFile, "PASSPORT");
      expect(result.id).toBe("doc-1");
      expect(result.type).toBe("PASSPORT");
      expect(mockS3.uploadEncrypted).toHaveBeenCalledTimes(1);
    });

    it("throws BadRequestException for invalid document type", async () => {
      await expect(
        service.uploadDocument("user-1", validFile, "INVALID_TYPE")
      ).rejects.toThrow(BadRequestException);
      expect(mockS3.uploadEncrypted).not.toHaveBeenCalled();
    });

    it("throws BadRequestException when file exceeds 10MB", async () => {
      const bigFile = { ...validFile, size: 11 * 1024 * 1024 };
      await expect(
        service.uploadDocument("user-1", bigFile as Express.Multer.File, "PASSPORT")
      ).rejects.toThrow(BadRequestException);
    });

    it("accepts file exactly at 10MB limit", async () => {
      const exactFile = { ...validFile, size: 10 * 1024 * 1024 };
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockS3.uploadEncrypted.mockResolvedValue(undefined);
      mockPrisma.document.create.mockResolvedValue({ id: "doc-2", type: "PASSPORT", uploadedAt: new Date() });

      await expect(
        service.uploadDocument("user-1", exactFile as Express.Multer.File, "PASSPORT")
      ).resolves.toBeDefined();
    });

    it("throws BadRequestException for invalid MIME type", async () => {
      const invalidMime = { ...validFile, mimetype: "image/gif" };
      await expect(
        service.uploadDocument("user-1", invalidMime as Express.Multer.File, "PASSPORT")
      ).rejects.toThrow(BadRequestException);
    });

    it("accepts image/png MIME type", async () => {
      const pngFile = { ...validFile, originalname: "id.png", mimetype: "image/png" };
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockS3.uploadEncrypted.mockResolvedValue(undefined);
      mockPrisma.document.create.mockResolvedValue({ id: "doc-3", type: "NATIONAL_ID", uploadedAt: new Date() });

      await expect(
        service.uploadDocument("user-1", pngFile as Express.Multer.File, "NATIONAL_ID")
      ).resolves.toBeDefined();
    });

    it("accepts application/pdf MIME type", async () => {
      const pdfFile = { ...validFile, originalname: "diploma.pdf", mimetype: "application/pdf" };
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockS3.uploadEncrypted.mockResolvedValue(undefined);
      mockPrisma.document.create.mockResolvedValue({ id: "doc-4", type: "DIPLOMA", uploadedAt: new Date() });

      await expect(
        service.uploadDocument("user-1", pdfFile as Express.Multer.File, "DIPLOMA")
      ).resolves.toBeDefined();
    });

    it("throws NotFoundException when profile does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);

      await expect(
        service.uploadDocument("missing-user", validFile, "PASSPORT")
      ).rejects.toThrow(NotFoundException);
    });

    it("saves s3Key with documents/ prefix", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockS3.uploadEncrypted.mockResolvedValue(undefined);
      let captured: any;
      mockPrisma.document.create.mockImplementation(async (args: any) => { captured = args; return { id: "doc-1", type: "PASSPORT", uploadedAt: new Date() }; });

      await service.uploadDocument("user-1", validFile, "PASSPORT");
      expect(captured.data.s3Key).toMatch(/^documents\/user-1\//);
    });

    it("accepts all valid document types", async () => {
      const validTypes = ["PASSPORT", "NATIONAL_ID", "DRIVERS_LICENSE", "DIPLOMA", "CERTIFICATE"];
      for (const docType of validTypes) {
        jest.clearAllMocks();
        mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
        mockS3.uploadEncrypted.mockResolvedValue(undefined);
        mockPrisma.document.create.mockResolvedValue({ id: "doc-x", type: docType, uploadedAt: new Date() });

        await expect(service.uploadDocument("user-1", validFile, docType)).resolves.toBeDefined();
      }
    });
  });

  // -----------------------------------------------------------------------
  describe("getDocuments", () => {
    it("returns list of documents for the user", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findMany.mockResolvedValue([
        { id: "doc-1", type: "PASSPORT", originalName: "pass.jpg", mimeType: "image/jpeg", status: "PENDING", uploadedAt: new Date() },
      ]);

      const result = await service.getDocuments("user-1");
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe("PASSPORT");
    });

    it("throws NotFoundException when profile does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);

      await expect(service.getDocuments("missing-user")).rejects.toThrow(NotFoundException);
    });

    it("returns empty array when no documents exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findMany.mockResolvedValue([]);

      const result = await service.getDocuments("user-1");
      expect(result).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  describe("getDocumentDownloadUrl", () => {
    it("returns presigned URL for existing document", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findFirst.mockResolvedValue({ id: "doc-1", s3Key: "documents/user-1/file.jpg" });
      mockS3.getPresignedUrl.mockResolvedValue("https://s3.example.com/signed");

      const result = await service.getDocumentDownloadUrl("user-1", "doc-1");
      expect(result.url).toBe("https://s3.example.com/signed");
      expect(result.expiresIn).toBe(300);
    });

    it("throws NotFoundException when profile does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);

      await expect(service.getDocumentDownloadUrl("missing-user", "doc-1")).rejects.toThrow(NotFoundException);
    });

    it("throws NotFoundException when document does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findFirst.mockResolvedValue(null);

      await expect(service.getDocumentDownloadUrl("user-1", "no-such-doc")).rejects.toThrow(NotFoundException);
    });

    it("calls S3 getPresignedUrl with 300s expiry", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findFirst.mockResolvedValue({ id: "doc-1", s3Key: "documents/user-1/file.pdf" });
      mockS3.getPresignedUrl.mockResolvedValue("https://s3.example.com/signed");

      await service.getDocumentDownloadUrl("user-1", "doc-1");
      expect(mockS3.getPresignedUrl).toHaveBeenCalledWith("documents/user-1/file.pdf", 300);
    });
  });

  // -----------------------------------------------------------------------
  describe("deleteDocument", () => {
    it("deletes document from S3 and DB", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findFirst.mockResolvedValue({ id: "doc-1", s3Key: "documents/user-1/file.jpg" });
      mockS3.deleteFile.mockResolvedValue(undefined);
      mockPrisma.document.delete.mockResolvedValue({ id: "doc-1" });

      const result = await service.deleteDocument("user-1", "doc-1");
      expect(result.success).toBe(true);
      expect(mockS3.deleteFile).toHaveBeenCalledWith("documents/user-1/file.jpg");
      expect(mockPrisma.document.delete).toHaveBeenCalledWith({ where: { id: "doc-1" } });
    });

    it("throws NotFoundException when profile does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue(null);

      await expect(service.deleteDocument("missing-user", "doc-1")).rejects.toThrow(NotFoundException);
    });

    it("throws NotFoundException when document does not exist", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findFirst.mockResolvedValue(null);

      await expect(service.deleteDocument("user-1", "no-such-doc")).rejects.toThrow(NotFoundException);
      expect(mockS3.deleteFile).not.toHaveBeenCalled();
    });

    it("calls S3 deleteFile before DB delete", async () => {
      const callOrder: string[] = [];
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE });
      mockPrisma.document.findFirst.mockResolvedValue({ id: "doc-1", s3Key: "documents/user-1/file.jpg" });
      mockS3.deleteFile.mockImplementation(async () => { callOrder.push("s3"); });
      mockPrisma.document.delete.mockImplementation(async () => { callOrder.push("db"); return { id: "doc-1" }; });

      await service.deleteDocument("user-1", "doc-1");
      expect(callOrder).toEqual(["s3", "db"]);
    });
  });

  // -----------------------------------------------------------------------
  describe("exportData", () => {
    it("returns all user data including profile, kyc and sessions", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(USER);
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: [] });
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: "VERIFIED" });
      mockPrisma.session.findMany.mockResolvedValue([
        { deviceInfo: "Chrome", ipAddress: "127.0.0.1", createdAt: new Date(), lastSeenAt: new Date() },
      ]);

      const result = await service.exportData("user-1");
      expect(result).toHaveProperty("exportedAt");
      expect(result.user).toEqual(USER);
      expect(result.kycStatus).toBe("VERIFIED");
      expect(result.sessions).toHaveLength(1);
    });

    it("includes profile with documents", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(USER);
      const profileWithDocs = {
        ...PROFILE,
        documents: [{ id: "doc-1", type: "PASSPORT", uploadedAt: new Date() }],
      };
      mockPrisma.profile.findUnique.mockResolvedValue(profileWithDocs);
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      mockPrisma.session.findMany.mockResolvedValue([]);

      const result = await service.exportData("user-1");
      expect(result.profile.documents).toHaveLength(1);
    });

    it("returns kycStatus undefined when no KYC record", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(USER);
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: [] });
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      mockPrisma.session.findMany.mockResolvedValue([]);

      const result = await service.exportData("user-1");
      expect(result.kycStatus).toBeUndefined();
    });

    it("exportedAt is an ISO date string", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(USER);
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: [] });
      mockPrisma.kycRecord.findUnique.mockResolvedValue(null);
      mockPrisma.session.findMany.mockResolvedValue([]);

      const result = await service.exportData("user-1");
      expect(new Date(result.exportedAt).toISOString()).toBe(result.exportedAt);
    });
  });

  // -----------------------------------------------------------------------
  describe("deleteAccount", () => {
    it("calls S3 deleteFile for each document", async () => {
      const docs = [
        { id: "doc-1", s3Key: "documents/user-1/a.jpg" },
        { id: "doc-2", s3Key: "documents/user-1/b.pdf" },
      ];
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: docs });
      mockS3.deleteFile.mockResolvedValue(undefined);
      mockPrisma.$transaction = jest.fn().mockResolvedValue(undefined);

      await service.deleteAccount("user-1");
      expect(mockS3.deleteFile).toHaveBeenCalledTimes(2);
      expect(mockS3.deleteFile).toHaveBeenCalledWith("documents/user-1/a.jpg");
      expect(mockS3.deleteFile).toHaveBeenCalledWith("documents/user-1/b.pdf");
    });

    it("runs prisma transaction to wipe all records", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: [] });
      mockS3.deleteFile.mockResolvedValue(undefined);
      mockPrisma.$transaction = jest.fn().mockResolvedValue(undefined);

      await service.deleteAccount("user-1");
      expect(mockPrisma.$transaction).toHaveBeenCalledTimes(1);
    });

    it("returns success true", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: [] });
      mockS3.deleteFile.mockResolvedValue(undefined);
      mockPrisma.$transaction = jest.fn().mockResolvedValue(undefined);

      const result = await service.deleteAccount("user-1");
      expect(result.success).toBe(true);
    });

    it("does not call S3 when profile has no documents", async () => {
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: [] });
      mockPrisma.$transaction = jest.fn().mockResolvedValue(undefined);

      await expect(service.deleteAccount("user-1")).resolves.toBeDefined();
      expect(mockS3.deleteFile).not.toHaveBeenCalled();
    });

    it("swallows S3 errors during document cleanup", async () => {
      const docs = [{ id: "doc-1", s3Key: "documents/user-1/broken.jpg" }];
      mockPrisma.profile.findUnique.mockResolvedValue({ ...PROFILE, documents: docs });
      mockS3.deleteFile.mockRejectedValue(new Error("S3 unavailable"));
      mockPrisma.$transaction = jest.fn().mockResolvedValue(undefined);

      await expect(service.deleteAccount("user-1")).resolves.toBeDefined();
    });
  });
});
