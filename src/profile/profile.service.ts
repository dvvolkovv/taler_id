import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { UpdateProfileDto, LinkWalletDto } from "./dto/update-profile.dto";

@Injectable()
export class ProfileService {
  constructor(private prisma: PrismaService) {}

  async getProfile(userId: string) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
    });
    if (!profile) throw new NotFoundException("Profile not found");

    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, phone: true, emailVerified: true, createdAt: true, username: true },
    });

    return {
      ...profile,
      email: user?.email,
      phone: user?.phone,
      emailVerified: user?.emailVerified ?? false,
      kycStatus: kyc?.status || "UNVERIFIED",
      createdAt: user?.createdAt,
      username: user?.username ?? null,
    };
  }

  async updateProfile(userId: string, dto: UpdateProfileDto) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    if (dto.phone !== undefined) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { phone: dto.phone || null },
      });
    }

    if (dto.fcmToken !== undefined) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { fcmToken: dto.fcmToken },
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
      if (existing) throw new ConflictException("Phone number already in use");
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

  async exportData(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, phone: true, emailVerified: true, createdAt: true, username: true },
    });
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
    });
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      select: { deviceInfo: true, ipAddress: true, createdAt: true, lastSeenAt: true },
    });

    return {
      exportedAt: new Date().toISOString(),
      user,
      profile,
      kycStatus: kyc?.status,
      sessions,
    };
  }

  async deleteAccount(userId: string) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
    });

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

  async uploadAvatar(userId: string, filename: string) {
    const avatarUrl = 'https://id.taler.tirol/uploads/avatars/' + filename;
    await this.prisma.profile.upsert({
      where: { userId },
      update: { avatarUrl },
      create: { userId, avatarUrl },
    });
    return { avatarUrl };
  }

    async updateUsername(userId: string, username: string) {
    const existing = await this.prisma.user.findFirst({
      where: { username, NOT: { id: userId } },
    });
    if (existing) throw new ConflictException('Username already taken');
    await this.prisma.user.update({ where: { id: userId }, data: { username } });
    return { success: true, username };
  }

  async getPublicProfile(userId: string) {
    const [profile, user] = await Promise.all([
      this.prisma.profile.findUnique({
        where: { userId },
        select: { firstName: true, lastName: true, avatarUrl: true },
      }),
      this.prisma.user.findUnique({
        where: { id: userId },
        select: { username: true },
      }),
    ]);
    return { ...profile, username: user?.username ?? null, userId };
  }
}
