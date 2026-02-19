import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { S3Service } from "./s3.service";
import { UpdateProfileDto, LinkWalletDto } from "./dto/update-profile.dto";
import { v4 as uuidv4 } from "uuid";
import * as path from "path";

@Injectable()
export class ProfileService {
  constructor(
    private prisma: PrismaService,
    private s3: S3Service,
  ) {}

  async getProfile(userId: string) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
      include: { documents: true },
    });
    if (!profile) throw new NotFoundException("Profile not found");

    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, phone: true, emailVerified: true, createdAt: true },
    });

    return {
      ...profile,
      email: user?.email,
      phone: user?.phone,
      emailVerified: user?.emailVerified ?? false,
      kycStatus: kyc?.status || "UNVERIFIED",
      createdAt: user?.createdAt,
    };
  }

  async updateProfile(userId: string, dto: UpdateProfileDto) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    // Update phone on User model if provided
    if (dto.phone !== undefined) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { phone: dto.phone || null },
      });
    }

    return this.prisma.profile.update({
      where: { userId },
      data: {
        firstName: dto.firstName,
        lastName: dto.lastName,
        middleName: dto.middleName,
        dateOfBirth: dto.dateOfBirth ? new Date(dto.dateOfBirth) : undefined,
        country: dto.country,
        postalCode: dto.postalCode,
        preferredCurrency: dto.preferredCurrency,
        language: dto.language,
      },
    });
  }

  async updatePhone(userId: string, phone: string | undefined) {
    if (phone) {
      const existing = await this.prisma.user.findFirst({
        where: { phone, NOT: { id: userId } },
      });
      if (existing) throw new ConflictException('Phone number already in use');
    }
    await this.prisma.user.update({
      where: { id: userId },
      data: { phone: phone || null },
    });
    return { success: true };
  }

  async linkWallet(userId: string, dto: LinkWalletDto) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(dto.walletAddress)) {
      throw new BadRequestException("Invalid wallet address. Must be a valid EVM address (0x...)");
    }

    return this.prisma.profile.update({
      where: { userId },
      data: { walletAddress: dto.walletAddress },
    });
  }

  async unlinkWallet(userId: string) {
    return this.prisma.profile.update({
      where: { userId },
      data: { walletAddress: null },
    });
  }

  async uploadDocument(userId: string, file: Express.Multer.File, type: string) {
    const validTypes = ["PASSPORT", "NATIONAL_ID", "DRIVERS_LICENSE", "DIPLOMA", "CERTIFICATE"];
    if (!validTypes.includes(type)) {
      throw new BadRequestException("Invalid document type. Valid types: " + validTypes.join(", "));
    }

    if (file.size > 10 * 1024 * 1024) {
      throw new BadRequestException("File size must not exceed 10MB");
    }

    const allowedMimes = ["image/jpeg", "image/png", "application/pdf"];
    if (!allowedMimes.includes(file.mimetype)) {
      throw new BadRequestException("Only JPEG, PNG and PDF files are allowed");
    }

    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    const ext = path.extname(file.originalname) || ".bin";
    const s3Key = "documents/" + userId + "/" + uuidv4() + ext;

    await this.s3.uploadEncrypted(s3Key, file.buffer, file.mimetype);

    const document = await this.prisma.document.create({
      data: {
        profileId: profile.id,
        type: type as any,
        s3Key,
        originalName: file.originalname,
        mimeType: file.mimetype,
      },
    });

    return { id: document.id, type: document.type, uploadedAt: document.uploadedAt };
  }

  async getDocuments(userId: string) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    return this.prisma.document.findMany({
      where: { profileId: profile.id },
      select: { id: true, type: true, originalName: true, mimeType: true, status: true, uploadedAt: true },
    });
  }

  async getDocumentDownloadUrl(userId: string, documentId: string) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    const document = await this.prisma.document.findFirst({
      where: { id: documentId, profileId: profile.id },
    });
    if (!document) throw new NotFoundException("Document not found");

    const url = await this.s3.getPresignedUrl(document.s3Key, 300);
    return { url, expiresIn: 300 };
  }

  async deleteDocument(userId: string, documentId: string) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    const document = await this.prisma.document.findFirst({
      where: { id: documentId, profileId: profile.id },
    });
    if (!document) throw new NotFoundException("Document not found");

    await this.s3.deleteFile(document.s3Key);
    await this.prisma.document.delete({ where: { id: documentId } });

    return { success: true };
  }

  async exportData(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, phone: true, emailVerified: true, createdAt: true },
    });
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
      include: { documents: { select: { id: true, type: true, uploadedAt: true } } },
    });
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      select: { deviceInfo: true, ipAddress: true, createdAt: true, lastSeenAt: true },
    });

    return {
      exportedAt: new Date().toISOString(),
      user,
      profile: { ...profile, documents: profile?.documents },
      kycStatus: kyc?.status,
      sessions,
    };
  }

  async deleteAccount(userId: string) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
      include: { documents: true },
    });

    if (profile?.documents) {
      for (const doc of profile.documents) {
        await this.s3.deleteFile(doc.s3Key).catch(() => {});
      }
    }

    await this.prisma.$transaction([
      this.prisma.document.deleteMany({ where: { profileId: profile?.id } }),
      this.prisma.kycRecord.deleteMany({ where: { userId } }),
      this.prisma.session.deleteMany({ where: { userId } }),
      this.prisma.totpSecret.deleteMany({ where: { userId } }),
      this.prisma.profile.deleteMany({ where: { userId } }),
      this.prisma.user.update({ where: { id: userId }, data: { deletedAt: new Date(), email: null, phone: null, passwordHash: null } }),
    ]);

    return { success: true };
  }
}
