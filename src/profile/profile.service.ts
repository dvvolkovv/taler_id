import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';
import { PartnerLinkRevokerService } from '../partner-core/partner-link-revoker.service';
import { resolveUserIdOrUsername } from '../common/utils/user-id.util';
import { UpdateProfileDto, LinkWalletDto } from './dto/update-profile.dto';

/**
 * `deleteAccount(userId, { onlyIfManagedBy })` refused: a fresh `FOR UPDATE`
 * read of the User row found it no longer managed by that partner (a password
 * got set in between — e.g. forgot-password — a different partner now owns
 * it, or it's already gone). No row was touched.
 */
export class AccountNotManagedError extends Error {}

@Injectable()
export class ProfileService {
  private readonly logger = new Logger(ProfileService.name);

  constructor(
    private prisma: PrismaService,
    private fileStorage: FileStorageService,
    private partnerLinks: PartnerLinkRevokerService,
  ) {}

  async getProfile(userIdOrUsername: string) {
    // Accept either a userId (UUID) or a username — share links of the form
    // https://id.taler.tirol/u/<username> pass the username here.
    const userId = await resolveUserIdOrUsername(this.prisma, userIdOrUsername);
    if (!userId) throw new NotFoundException('Profile not found');

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
      availableBots: {
        analyst: true,
        outbound: true,
        informer: profile.informerAccess === true,
      },
    };
  }

  async updateProfile(userId: string, dto: UpdateProfileDto, sessionId?: string) {
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
      // Multi-device: also store the token on THIS device's session so wake-pushes
      // reach all of the user's logged-in devices (see MessengerService.getFcmTokens).
      // try/catch: no-op if the Session.fcmToken column isn't present yet.
      if (sessionId) {
        try {
          await this.prisma.session.update({
            where: { id: sessionId },
            data: { fcmToken: dto.fcmToken || null },
          });
        } catch {
          /* column missing (un-migrated env) or session gone — ignore */
        }
      }
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
      if (sessionId) {
        try {
          await this.prisma.session.update({
            where: { id: sessionId },
            data: { voipToken: dto.voipToken || null },
          });
        } catch {
          /* column missing (un-migrated env) or session gone — ignore */
        }
      }
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
        assistantName: dto.assistantName,
        lastSeenPrivacy: dto.lastSeenPrivacy,
        newDeviceApproval: dto.newDeviceApproval,
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
        assistantName: dto.assistantName,
        lastSeenPrivacy: dto.lastSeenPrivacy,
        newDeviceApproval: dto.newDeviceApproval,
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

  /**
   * @param opts.onlyIfManagedBy Partner-API guard (Task: deleteUser). The
   * partner decided "managed" from an earlier, unlocked read; a person can
   * set their first TalerID password (forgot-password) in the gap between
   * that read and this call, which hands the account back to them. When set,
   * the deletion runs inside one transaction that re-reads the User row
   * `FOR UPDATE` and aborts with `AccountNotManagedError` (no row touched) if
   * it no longer matches `createdByPartnerId === onlyIfManagedBy &&
   * passwordHash IS NULL && deletedAt IS NULL` — same shape as the `FOR
   * UPDATE` re-check in PartnerUsersService.provisionOnce. Omitted: behaves
   * exactly as before (the caller's own `DELETE /profile`, admin).
   */
  async deleteAccount(userId: string, opts?: { onlyIfManagedBy: string }) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
    });

    if (opts?.onlyIfManagedBy) {
      const partnerId = opts.onlyIfManagedBy;
      await this.prisma.$transaction(async (tx) => {
        const [fresh] = await tx.$queryRaw<
          {
            passwordHash: string | null;
            createdByPartnerId: string | null;
            deletedAt: Date | null;
          }[]
        >`SELECT "passwordHash", "createdByPartnerId", "deletedAt" FROM "User" WHERE id = ${userId} FOR UPDATE`;
        if (
          !fresh ||
          fresh.createdByPartnerId !== partnerId ||
          fresh.passwordHash !== null ||
          fresh.deletedAt !== null
        ) {
          throw new AccountNotManagedError();
        }
        for (const op of this.deletionStatements(tx, userId, profile)) {
          await op;
        }
      });
    } else {
      // Prisma drops `undefined` filters, so `profileId: profile?.id` would match
      // every row and wipe the whole Document table for a user without a Profile.
      await this.prisma.$transaction(
        this.deletionStatements(this.prisma, userId, profile),
      );
    }

    // Партнёры (nadi) теряют доступ сразу, а не когда истекут выданные токены:
    // человек удалил аккаунт — его чатов не должен видеть никто. Сбой отзыва
    // не отменяет удаления: новых токенов партнёр уже не получит (аккаунт
    // удалён), выданные доживут не дольше 15 минут, а недоделанный отзыв
    // добьёт следующий DELETE связки партнёром.
    try {
      await this.partnerLinks.revokeAllForUser(userId);
    } catch (e) {
      this.logger.error(`partner links not fully revoked for ${userId}: ${(e as Error).message}`);
    }

    return { success: true };
  }

  /** Same six statements either way — only whether they run via `this.prisma` (array transaction) or `tx` (interactive transaction, guarded path) differs. */
  private deletionStatements(
    db: PrismaService | Prisma.TransactionClient,
    userId: string,
    profile: { id: string } | null,
  ) {
    return [
      ...(profile
        ? [db.document.deleteMany({ where: { profileId: profile.id } })]
        : []),
      db.kycRecord.deleteMany({ where: { userId } }),
      db.session.deleteMany({ where: { userId } }),
      db.totpSecret.deleteMany({ where: { userId } }),
      db.profile.deleteMany({ where: { userId } }),
      db.user.update({
        where: { id: userId },
        data: {
          deletedAt: new Date(),
          email: null,
          phone: null,
          passwordHash: null,
        },
      }),
    ];
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

  async getPublicProfile(userIdOrUsername: string) {
    // Accept either a userId (UUID) or a username — share links of the form
    // https://id.taler.tirol/u/<username> pass the username here.
    const userId = await resolveUserIdOrUsername(this.prisma, userIdOrUsername);
    if (!userId) throw new NotFoundException('Profile not found');

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
    return { ...profile, username: user?.username ?? null, userId, id: userId };
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
