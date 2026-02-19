import { Test, TestingModule } from "@nestjs/testing";
import { TenantService } from "./tenant.service";
import { PrismaService } from "../prisma/prisma.service";
import { ConfigService } from "@nestjs/config";
import {
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from "@nestjs/common";
import { TenantRole, KycStatus } from "@prisma/client";

const mockPrisma = {
  tenant: {
    create: jest.fn(),
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
  },
  tenantMember: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  user: {
    findFirst: jest.fn(),
    findUnique: jest.fn(),
  },
  pendingInvite: {
    create: jest.fn(),
    findUnique: jest.fn(),
    delete: jest.fn(),
  },
};

const mockConfig = {
  get: jest.fn((key: string) => {
    const cfg: Record<string, any> = {
      "sumsub.appToken": "test_token",
      "sumsub.secretKey": "test_secret",
      "sumsub.baseUrl": "https://api.sumsub.com",
    };
    return cfg[key];
  }),
};

const TENANT_ID = "tenant-1";
const OWNER_ID = "user-owner";
const ADMIN_ID = "user-admin";
const VIEWER_ID = "user-viewer";

const makeMember = (userId: string, role: TenantRole) => ({
  id: "member-" + userId,
  tenantId: TENANT_ID,
  userId,
  role,
});

const TENANT = {
  id: TENANT_ID,
  name: "Acme Corp",
  description: "Test tenant",
  kybStatus: KycStatus.UNVERIFIED,
  sumsubApplicantId: null,
  members: [],
};

describe("TenantService", () => {
  let service: TenantService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TenantService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: ConfigService, useValue: mockConfig },
      ],
    }).compile();
    service = module.get<TenantService>(TenantService);
  });

  // -----------------------------------------------------------------------
  describe("createTenant", () => {
    it("creates tenant and returns it with OWNER member", async () => {
      const tenantWithMember = { ...TENANT, members: [makeMember(OWNER_ID, TenantRole.OWNER)] };
      mockPrisma.tenant.create.mockResolvedValue(tenantWithMember);

      const result = await service.createTenant(OWNER_ID, { name: "Acme Corp" });
      expect(result.name).toBe("Acme Corp");
      expect(result.members[0].role).toBe(TenantRole.OWNER);
      expect(result.members[0].userId).toBe(OWNER_ID);
    });

    it("passes dto fields to prisma create", async () => {
      mockPrisma.tenant.create.mockResolvedValue({ ...TENANT, members: [] });

      await service.createTenant(OWNER_ID, {
        name: "New Tenant",
        description: "Desc",
        legalAddress: "123 Main St",
        website: "https://example.com",
        email: "contact@example.com",
        phone: "+1234567890",
      });

      expect(mockPrisma.tenant.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: "New Tenant",
            description: "Desc",
            contactEmail: "contact@example.com",
          }),
        })
      );
    });

    it("creates OWNER membership inline with tenant", async () => {
      mockPrisma.tenant.create.mockResolvedValue({ ...TENANT, members: [] });

      await service.createTenant(OWNER_ID, { name: "Test" });

      expect(mockPrisma.tenant.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            members: {
              create: { userId: OWNER_ID, role: TenantRole.OWNER },
            },
          }),
        })
      );
    });
  });

  // -----------------------------------------------------------------------
  describe("getMyTenants", () => {
    it("returns tenants with role for the user", async () => {
      mockPrisma.tenantMember.findMany.mockResolvedValue([
        { role: TenantRole.OWNER, tenant: { ...TENANT } },
        { role: TenantRole.ADMIN, tenant: { ...TENANT, id: "tenant-2", name: "Beta LLC" } },
      ]);

      const result = await service.getMyTenants(OWNER_ID);
      expect(result).toHaveLength(2);
      expect(result[0].role).toBe(TenantRole.OWNER);
      expect(result[1].role).toBe(TenantRole.ADMIN);
    });

    it("returns empty array when user has no memberships", async () => {
      mockPrisma.tenantMember.findMany.mockResolvedValue([]);

      const result = await service.getMyTenants("nobody");
      expect(result).toHaveLength(0);
    });

    it("spreads tenant fields into result", async () => {
      mockPrisma.tenantMember.findMany.mockResolvedValue([
        { role: TenantRole.VIEWER, tenant: { ...TENANT } },
      ]);

      const result = await service.getMyTenants(VIEWER_ID);
      expect(result[0].name).toBe("Acme Corp");
      expect(result[0].id).toBe(TENANT_ID);
    });
  });

  // -----------------------------------------------------------------------
  describe("getTenant", () => {
    it("returns tenant details for a member", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.tenant.findUnique.mockResolvedValue({ ...TENANT, members: [] });

      const result = await service.getTenant(TENANT_ID, OWNER_ID);
      expect(result.id).toBe(TENANT_ID);
    });

    it("throws ForbiddenException when user is not a member", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(null);

      await expect(service.getTenant(TENANT_ID, "outsider")).rejects.toThrow(ForbiddenException);
    });
  });

  // -----------------------------------------------------------------------
  describe("updateTenant", () => {
    it("allows OWNER to update tenant", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, name: "Updated Corp" });

      const result = await service.updateTenant(TENANT_ID, OWNER_ID, { name: "Updated Corp" });
      expect(result.name).toBe("Updated Corp");
    });

    it("allows ADMIN to update tenant", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(ADMIN_ID, TenantRole.ADMIN));
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, name: "Updated Corp" });

      await expect(service.updateTenant(TENANT_ID, ADMIN_ID, { name: "Updated Corp" })).resolves.toBeDefined();
    });

    it("throws ForbiddenException when user is VIEWER (not OWNER/ADMIN)", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(VIEWER_ID, TenantRole.VIEWER));

      await expect(service.updateTenant(TENANT_ID, VIEWER_ID, { name: "Hack" })).rejects.toThrow(ForbiddenException);
    });

    it("throws ForbiddenException when user is not a member at all", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(null);

      await expect(service.updateTenant(TENANT_ID, "outsider", { name: "Hack" })).rejects.toThrow(ForbiddenException);
    });
  });

  // -----------------------------------------------------------------------
  describe("startKyb", () => {
    it("returns mock applicantId in mock mode (test_token)", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.tenant.findUnique.mockResolvedValue({ ...TENANT });
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, kybStatus: KycStatus.PENDING });

      const result = await service.startKyb(TENANT_ID, OWNER_ID);
      expect(result.applicantId).toBe("mock_company_" + TENANT_ID);
      expect(result.sdkToken).toMatch(/^mock_kyb_sdk_token_/);
    });

    it("sets kybStatus to PENDING in the database", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.tenant.findUnique.mockResolvedValue({ ...TENANT });
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, kybStatus: KycStatus.PENDING });

      await service.startKyb(TENANT_ID, OWNER_ID);
      expect(mockPrisma.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ kybStatus: KycStatus.PENDING }),
        })
      );
    });

    it("throws ForbiddenException when user is not OWNER", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(ADMIN_ID, TenantRole.ADMIN));

      await expect(service.startKyb(TENANT_ID, ADMIN_ID)).rejects.toThrow(ForbiddenException);
    });

    it("throws ForbiddenException when user is not a member", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(null);

      await expect(service.startKyb(TENANT_ID, "outsider")).rejects.toThrow(ForbiddenException);
    });
  });

  // -----------------------------------------------------------------------
  describe("handleKybWebhook", () => {
    it("updates kybStatus to VERIFIED on GREEN review", async () => {
      mockPrisma.tenant.findFirst.mockResolvedValue({ ...TENANT });
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, kybStatus: KycStatus.VERIFIED });

      const result = await service.handleKybWebhook({
        applicantId: "app-1",
        type: "applicantReviewed",
        reviewResult: { reviewAnswer: "GREEN" },
      });

      expect(result.processed).toBe(true);
      expect(result.status).toBe(KycStatus.VERIFIED);
      expect(mockPrisma.tenant.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ kybStatus: KycStatus.VERIFIED }) })
      );
    });

    it("updates kybStatus to REJECTED on RED review", async () => {
      mockPrisma.tenant.findFirst.mockResolvedValue({ ...TENANT });
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, kybStatus: KycStatus.REJECTED });

      const result = await service.handleKybWebhook({
        applicantId: "app-2",
        type: "applicantReviewed",
        reviewResult: { reviewAnswer: "RED" },
      });

      expect(result.processed).toBe(true);
      expect(result.status).toBe(KycStatus.REJECTED);
    });

    it("returns processed:false when tenant not found", async () => {
      mockPrisma.tenant.findFirst.mockResolvedValue(null);

      const result = await service.handleKybWebhook({
        applicantId: "unknown-app",
        type: "applicantReviewed",
        reviewResult: { reviewAnswer: "GREEN" },
      });

      expect(result.processed).toBe(false);
      expect(mockPrisma.tenant.update).not.toHaveBeenCalled();
    });

    it("returns processed:false for non-applicantReviewed type", async () => {
      const result = await service.handleKybWebhook({
        applicantId: "app-1",
        type: "applicantPending",
        reviewResult: { reviewAnswer: "GREEN" },
      });

      expect(result.processed).toBe(false);
      expect(mockPrisma.tenant.findFirst).not.toHaveBeenCalled();
    });

    it("includes tenantId in processed result", async () => {
      mockPrisma.tenant.findFirst.mockResolvedValue({ ...TENANT });
      mockPrisma.tenant.update.mockResolvedValue({ ...TENANT, kybStatus: KycStatus.VERIFIED });

      const result = await service.handleKybWebhook({
        applicantId: "app-1",
        type: "applicantReviewed",
        reviewResult: { reviewAnswer: "GREEN" },
      });

      expect(result.tenantId).toBe(TENANT_ID);
    });
  });

  // -----------------------------------------------------------------------
  describe("inviteMember", () => {
    it("adds existing user directly as ADMIN", async () => {
      // assertRole call (OWNER checks), then existing member check
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole
        .mockResolvedValueOnce(null); // check existing member
      mockPrisma.user.findFirst.mockResolvedValue({ id: "new-user", email: "new@example.com" });
      mockPrisma.tenantMember.create.mockResolvedValue({
        ...makeMember("new-user", TenantRole.ADMIN),
        user: { id: "new-user", email: "new@example.com" },
      });

      const result = await service.inviteMember(TENANT_ID, OWNER_ID, {
        email: "new@example.com",
        role: "ADMIN",
      });

      expect(result.type).toBe("added");
      expect(mockPrisma.tenantMember.create).toHaveBeenCalledTimes(1);
    });

    it("throws ConflictException when existing user is already a member", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole
        .mockResolvedValueOnce(makeMember("existing-user", TenantRole.VIEWER)); // already member
      mockPrisma.user.findFirst.mockResolvedValue({ id: "existing-user", email: "member@example.com" });

      await expect(
        service.inviteMember(TENANT_ID, OWNER_ID, { email: "member@example.com", role: "VIEWER" })
      ).rejects.toThrow(ConflictException);
    });

    it("throws ForbiddenException when trying to invite as OWNER", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));

      await expect(
        service.inviteMember(TENANT_ID, OWNER_ID, { email: "someone@example.com", role: "OWNER" })
      ).rejects.toThrow(ForbiddenException);
    });

    it("creates pending invite for unknown email", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.user.findFirst.mockResolvedValue(null);
      mockPrisma.pendingInvite.create.mockResolvedValue({
        token: "invite-token-abc",
        email: "unknown@example.com",
        role: TenantRole.ADMIN,
        tenantId: TENANT_ID,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      const result = await service.inviteMember(TENANT_ID, OWNER_ID, {
        email: "unknown@example.com",
        role: "ADMIN",
      });

      expect(result.type).toBe("invited");
      expect(result.inviteToken).toBe("invite-token-abc");
    });

    it("throws ForbiddenException when requester is VIEWER (not OWNER/ADMIN)", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(VIEWER_ID, TenantRole.VIEWER));

      await expect(
        service.inviteMember(TENANT_ID, VIEWER_ID, { email: "x@example.com", role: "VIEWER" })
      ).rejects.toThrow(ForbiddenException);
    });

    it("ADMIN can invite new VIEWER", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(ADMIN_ID, TenantRole.ADMIN)) // assertRole
        .mockResolvedValueOnce(null); // not already a member
      mockPrisma.user.findFirst.mockResolvedValue({ id: "new-viewer", email: "viewer@example.com" });
      mockPrisma.tenantMember.create.mockResolvedValue({
        ...makeMember("new-viewer", TenantRole.VIEWER),
        user: { id: "new-viewer", email: "viewer@example.com" },
      });

      const result = await service.inviteMember(TENANT_ID, ADMIN_ID, {
        email: "viewer@example.com",
        role: "VIEWER",
      });

      expect(result.type).toBe("added");
    });
  });

  // -----------------------------------------------------------------------
  describe("acceptInvite", () => {
    const INVITE_TOKEN = "valid-invite-token";
    const INVITE = {
      token: INVITE_TOKEN,
      tenantId: TENANT_ID,
      email: "invitee@example.com",
      role: TenantRole.VIEWER,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
    };

    it("creates member and deletes invite on valid accept", async () => {
      mockPrisma.pendingInvite.findUnique.mockResolvedValue(INVITE);
      mockPrisma.user.findUnique.mockResolvedValue({ id: "invitee-id", email: "invitee@example.com" });
      mockPrisma.tenantMember.create.mockResolvedValue(makeMember("invitee-id", TenantRole.VIEWER));
      mockPrisma.pendingInvite.delete.mockResolvedValue(INVITE);

      const result = await service.acceptInvite(INVITE_TOKEN, "invitee-id");
      expect(result).toHaveProperty("role", TenantRole.VIEWER);
      expect(mockPrisma.pendingInvite.delete).toHaveBeenCalledWith({ where: { token: INVITE_TOKEN } });
    });

    it("throws NotFoundException when invite token not found", async () => {
      mockPrisma.pendingInvite.findUnique.mockResolvedValue(null);

      await expect(service.acceptInvite("bad-token", "user-1")).rejects.toThrow(NotFoundException);
    });

    it("throws BadRequestException when invite is expired", async () => {
      mockPrisma.pendingInvite.findUnique.mockResolvedValue({
        ...INVITE,
        expiresAt: new Date(Date.now() - 1000), // already expired
      });

      await expect(service.acceptInvite(INVITE_TOKEN, "invitee-id")).rejects.toThrow(BadRequestException);
    });

    it("throws ForbiddenException when user email does not match invite email", async () => {
      mockPrisma.pendingInvite.findUnique.mockResolvedValue(INVITE);
      mockPrisma.user.findUnique.mockResolvedValue({ id: "wrong-user", email: "wrong@example.com" });

      await expect(service.acceptInvite(INVITE_TOKEN, "wrong-user")).rejects.toThrow(ForbiddenException);
    });
  });

  // -----------------------------------------------------------------------
  describe("changeRole", () => {
    it("OWNER can change VIEWER role to ADMIN", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole
        .mockResolvedValueOnce(makeMember(VIEWER_ID, TenantRole.VIEWER)); // target
      mockPrisma.tenantMember.update.mockResolvedValue(makeMember(VIEWER_ID, TenantRole.ADMIN));

      const result = await service.changeRole(TENANT_ID, OWNER_ID, VIEWER_ID, { role: "ADMIN" });
      expect(result.role).toBe(TenantRole.ADMIN);
    });

    it("ADMIN cannot change OWNER role", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(ADMIN_ID, TenantRole.ADMIN)) // assertRole (ADMIN passes)
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)); // target is owner

      await expect(
        service.changeRole(TENANT_ID, ADMIN_ID, OWNER_ID, { role: "VIEWER" })
      ).rejects.toThrow(ForbiddenException);
    });

    it("ADMIN cannot assign OWNER role", async () => {
      // ADMIN tries to promote a VIEWER to OWNER - forbidden
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(ADMIN_ID, TenantRole.ADMIN)) // assertRole
        .mockResolvedValueOnce(makeMember(VIEWER_ID, TenantRole.VIEWER)); // target is viewer

      await expect(
        service.changeRole(TENANT_ID, ADMIN_ID, VIEWER_ID, { role: "OWNER" })
      ).rejects.toThrow(ForbiddenException);
    });

    it("throws NotFoundException when target member not found", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole
        .mockResolvedValueOnce(null); // target not found

      await expect(
        service.changeRole(TENANT_ID, OWNER_ID, "ghost-user", { role: "ADMIN" })
      ).rejects.toThrow(NotFoundException);
    });

    it("OWNER can change ADMIN to VIEWER", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER))
        .mockResolvedValueOnce(makeMember(ADMIN_ID, TenantRole.ADMIN));
      mockPrisma.tenantMember.update.mockResolvedValue(makeMember(ADMIN_ID, TenantRole.VIEWER));

      const result = await service.changeRole(TENANT_ID, OWNER_ID, ADMIN_ID, { role: "VIEWER" });
      expect(result.role).toBe(TenantRole.VIEWER);
    });

    it("throws ForbiddenException when requester is not a member", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValueOnce(null);

      await expect(
        service.changeRole(TENANT_ID, "outsider", VIEWER_ID, { role: "ADMIN" })
      ).rejects.toThrow(ForbiddenException);
    });
  });

  // -----------------------------------------------------------------------
  describe("removeMember", () => {
    it("removes a VIEWER member successfully", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole
        .mockResolvedValueOnce(makeMember(VIEWER_ID, TenantRole.VIEWER)); // target
      mockPrisma.tenantMember.delete.mockResolvedValue(makeMember(VIEWER_ID, TenantRole.VIEWER));

      const result = await service.removeMember(TENANT_ID, OWNER_ID, VIEWER_ID);
      expect(result.success).toBe(true);
      expect(mockPrisma.tenantMember.delete).toHaveBeenCalledTimes(1);
    });

    it("throws ForbiddenException when trying to remove OWNER", async () => {
      // Use a different target userId so both findFirst calls can be mocked independently
      const TARGET_OWNER_ID = "user-owner-2";
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole for requester
        .mockResolvedValueOnce(makeMember(TARGET_OWNER_ID, TenantRole.OWNER)); // target is also owner

      await expect(service.removeMember(TENANT_ID, OWNER_ID, TARGET_OWNER_ID)).rejects.toThrow(ForbiddenException);
    });

    it("throws NotFoundException when target member not found", async () => {
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER)) // assertRole
        .mockResolvedValueOnce(null); // target not found

      await expect(service.removeMember(TENANT_ID, OWNER_ID, "ghost-user")).rejects.toThrow(NotFoundException);
    });

    it("throws ForbiddenException when requester is VIEWER", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValueOnce(makeMember(VIEWER_ID, TenantRole.VIEWER));

      await expect(service.removeMember(TENANT_ID, VIEWER_ID, "someone")).rejects.toThrow(ForbiddenException);
    });

    it("calls tenantMember.delete with the member id", async () => {
      const targetMember = makeMember(VIEWER_ID, TenantRole.VIEWER);
      mockPrisma.tenantMember.findFirst
        .mockResolvedValueOnce(makeMember(OWNER_ID, TenantRole.OWNER))
        .mockResolvedValueOnce(targetMember);
      mockPrisma.tenantMember.delete.mockResolvedValue(targetMember);

      await service.removeMember(TENANT_ID, OWNER_ID, VIEWER_ID);
      expect(mockPrisma.tenantMember.delete).toHaveBeenCalledWith({ where: { id: targetMember.id } });
    });
  });

  // -----------------------------------------------------------------------
  describe("getKybStatus", () => {
    it("returns kybStatus and applicantId for a member", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.tenant.findUnique.mockResolvedValue({
        kybStatus: KycStatus.VERIFIED,
        sumsubApplicantId: "app-xyz",
      });

      const result = await service.getKybStatus(TENANT_ID, OWNER_ID);
      expect(result.status).toBe(KycStatus.VERIFIED);
      expect(result.applicantId).toBe("app-xyz");
    });

    it("throws ForbiddenException when user is not a member", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(null);

      await expect(service.getKybStatus(TENANT_ID, "outsider")).rejects.toThrow(ForbiddenException);
    });

    it("throws NotFoundException when tenant does not exist", async () => {
      mockPrisma.tenantMember.findFirst.mockResolvedValue(makeMember(OWNER_ID, TenantRole.OWNER));
      mockPrisma.tenant.findUnique.mockResolvedValue(null);

      await expect(service.getKybStatus(TENANT_ID, OWNER_ID)).rejects.toThrow(NotFoundException);
    });
  });
});
