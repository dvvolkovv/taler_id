import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';
import { UpdateProfileDto, LinkWalletDto } from './dto/update-profile.dto';

@Injectable()
export class ProfileService {
  constructor(
    private prisma: PrismaService,
    private fileStorage: FileStorageService,
  ) {}

  async getProfile(userId: string) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
    });
    if (!profile) throw new NotFoundException('Profile not found');

    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        email: true,
        phone: true,
        emailVerified: true,
        createdAt: true,
        username: true,
      },
    });

    return {
      ...profile,
      id: userId,
      email: user?.email,
      phone: user?.phone,
      emailVerified: user?.emailVerified ?? false,
      kycStatus: kyc?.status || 'UNVERIFIED',
      createdAt: user?.createdAt,
      username: user?.username ?? null,
      status: profile.status ?? null,
    };
  }

  async updateProfile(userId: string, dto: UpdateProfileDto) {
    if (dto.phone !== undefined) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { phone: dto.phone || null },
      });
    }

    if (dto.fcmToken !== undefined) {
      // Clear this FCM token from any other user (device switched accounts)
      if (dto.fcmToken) {
        await this.prisma.user.updateMany({
          where: { fcmToken: dto.fcmToken, NOT: { id: userId } },
          data: { fcmToken: null },
        });
      }
      await this.prisma.user.update({
        where: { id: userId },
        data: { fcmToken: dto.fcmToken },
      });
    }

    if (dto.voipToken !== undefined) {
      // Clear this VoIP token from any other user (device switched accounts)
      if (dto.voipToken) {
        await this.prisma.user.updateMany({
          where: { voipToken: dto.voipToken, NOT: { id: userId } },
          data: { voipToken: null },
        });
      }
      await this.prisma.user.update({
        where: { id: userId },
        data: { voipToken: dto.voipToken },
      });
    }

    return this.prisma.profile.upsert({
      where: { userId },
      update: {
        firstName: dto.firstName,
        lastName: dto.lastName,
        middleName: dto.middleName,
        dateOfBirth: dto.dateOfBirth ? new Date(dto.dateOfBirth) : undefined,
        country: dto.country,
        postalCode: dto.postalCode,
        preferredCurrency: dto.preferredCurrency,
        language: dto.language,
        status: dto.status,
        aiTwinEnabled: dto.aiTwinEnabled,
        aiTwinTimeoutSeconds: dto.aiTwinTimeoutSeconds,
        aiTwinPrompt: dto.aiTwinPrompt,
        aiTwinVoiceId: dto.aiTwinVoiceId,
      },
      create: {
        userId,
        firstName: dto.firstName,
        lastName: dto.lastName,
        middleName: dto.middleName,
        dateOfBirth: dto.dateOfBirth ? new Date(dto.dateOfBirth) : undefined,
        country: dto.country,
        postalCode: dto.postalCode,
        preferredCurrency: dto.preferredCurrency,
        language: dto.language,
        status: dto.status,
        aiTwinEnabled: dto.aiTwinEnabled,
        aiTwinTimeoutSeconds: dto.aiTwinTimeoutSeconds,
        aiTwinPrompt: dto.aiTwinPrompt,
        aiTwinVoiceId: dto.aiTwinVoiceId,
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
      throw new BadRequestException(
        'Invalid wallet address. Must be a valid EVM address (0x...)',
      );
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
      select: {
        email: true,
        phone: true,
        emailVerified: true,
        createdAt: true,
        username: true,
      },
    });
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
    });
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      select: {
        deviceInfo: true,
        ipAddress: true,
        createdAt: true,
        lastSeenAt: true,
      },
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
      this.prisma.user.update({
        where: { id: userId },
        data: {
          deletedAt: new Date(),
          email: null,
          phone: null,
          passwordHash: null,
        },
      }),
    ]);

    return { success: true };
  }

  async uploadAvatar(userId: string, filename: string) {
    const baseUrl = process.env.BASE_URL || 'https://id.taler.tirol';
    const avatarUrl = `${baseUrl}/uploads/avatars/${filename}`;
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
    await this.prisma.user.update({
      where: { id: userId },
      data: { username },
    });
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

  // ── Video Backgrounds ──────────────────────────────────────────────

  async getBackgrounds(userId: string) {
    return this.prisma.userBackground.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async uploadBackground(userId: string, file: Express.Multer.File) {
    // Max 10 backgrounds per user
    const count = await this.prisma.userBackground.count({ where: { userId } });
    if (count >= 10) {
      throw new BadRequestException('Maximum 10 backgrounds allowed');
    }

    const { v4: uuidv4 } = require('uuid');
    const { extname } = require('path');
    const ext = extname(file.originalname) || '.jpg';
    const s3Key = `backgrounds/${userId}/${uuidv4()}${ext}`;

    await this.fileStorage.upload(s3Key, file.buffer, file.mimetype);
    const fileUrl = this.fileStorage.getPublicUrl(s3Key);

    // Generate thumbnail
    let thumbnailUrl: string | null = null;
    try {
      const sharp = require('sharp');
      const thumbBuffer = await sharp(file.buffer)
        .resize(200, 200, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();
      const thumbKey = `backgrounds/${userId}/thumb_${uuidv4()}.webp`;
      await this.fileStorage.upload(thumbKey, thumbBuffer, 'image/webp');
      thumbnailUrl = this.fileStorage.getPublicUrl(thumbKey);
    } catch (e) {
      // Thumbnail generation failed — continue without it
    }

    return this.prisma.userBackground.create({
      data: {
        userId,
        s3Key,
        fileUrl,
        thumbnailUrl,
        fileName: file.originalname,
        fileSize: file.size,
        mimeType: file.mimetype,
      },
    });
  }

  async deleteBackground(userId: string, id: string) {
    const bg = await this.prisma.userBackground.findFirst({
      where: { id, userId },
    });
    if (!bg) throw new NotFoundException('Background not found');

    // Delete from S3
    try {
      await this.fileStorage.delete(bg.s3Key);
    } catch (e) {
      // S3 deletion failed — continue anyway
    }

    await this.prisma.userBackground.delete({ where: { id } });
    return { deleted: true };
  }
}
