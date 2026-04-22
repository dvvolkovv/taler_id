import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { FcmService } from '../common/fcm.service';
import { RegisterDeviceKeyDto } from './dto/register-device-key.dto';
import { DeviceKeyResponseDto } from './dto/device-key-response.dto';
import { RevokeDeviceKeyDto } from './dto/revoke-device-key.dto';

const SUPPORTED_ALG = 'X25519';

@Injectable()
export class DeviceKeysService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly fcm: FcmService,
  ) {}

  async register(
    userId: string,
    dto: RegisterDeviceKeyDto,
  ): Promise<DeviceKeyResponseDto> {
    if (dto.algorithm !== SUPPORTED_ALG) {
      throw new BadRequestException(
        `Unsupported algorithm: ${dto.algorithm} (only ${SUPPORTED_ALG})`,
      );
    }
    if (dto.validUntilEpochMs <= Date.now()) {
      throw new BadRequestException('validUntilEpochMs is in the past');
    }

    const userPk = this.extractUserPk(dto.certificate);

    const record = await this.prisma.deviceKey.create({
      data: {
        userId,
        devicePk: dto.devicePk.toLowerCase(),
        userPk,
        algorithm: SUPPORTED_ALG,
        validUntil: new Date(dto.validUntilEpochMs),
        certificate: dto.certificate,
        signature: dto.signature.toLowerCase(),
      },
    });

    // Fan-out push to this user's contacts (fire-and-forget).
    this.fcm.sendKeyUpdate(userId).catch(() => {
      /* FCM failures should not break registration */
    });

    return this.toResponseDto(record);
  }

  async listForContact(
    _callerId: string,
    contactUserId: string,
  ): Promise<DeviceKeyResponseDto[]> {
    const user = await this.prisma.user.findUnique({
      where: { id: contactUserId },
    });
    if (!user) {
      throw new NotFoundException(`User ${contactUserId} not found`);
    }
    const rows = await this.prisma.deviceKey.findMany({
      where: {
        userId: contactUserId,
        revokedAt: null,
        validUntil: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.toResponseDto(r));
  }

  async revoke(
    callerId: string,
    keyId: string,
    _dto: RevokeDeviceKeyDto,
  ): Promise<DeviceKeyResponseDto> {
    const existing = await this.prisma.deviceKey.findUnique({
      where: { id: keyId },
    });
    if (!existing || existing.userId !== callerId) {
      throw new NotFoundException('Device key not found');
    }
    const updated = await this.prisma.deviceKey.update({
      where: { id: keyId },
      data: { revokedAt: new Date() },
    });
    this.fcm.sendKeyUpdate(callerId).catch(() => {
      /* swallow */
    });
    return this.toResponseDto(updated);
  }

  /**
   * Extract the `userPk` field from a cert JSON string.
   *
   * Returns lowercase hex if present and string-typed, otherwise `null`.
   * Malformed JSON returns `null` (Phase 1b backward compat — the legacy
   * cert has no userPk and the backend stored it as-is without parsing).
   */
  private extractUserPk(certificateJson: string): string | null {
    try {
      const parsed = JSON.parse(certificateJson);
      const v = parsed?.userPk;
      if (typeof v !== 'string') return null;
      return v.toLowerCase();
    } catch {
      return null;
    }
  }

  private toResponseDto(row: any): DeviceKeyResponseDto {
    return {
      id: row.id,
      userId: row.userId,
      devicePk: row.devicePk,
      userPk: row.userPk ?? null,
      algorithm: row.algorithm,
      validUntil: (row.validUntil as Date).toISOString(),
      certificate: row.certificate,
      signature: row.signature,
      revokedAt: row.revokedAt ? (row.revokedAt as Date).toISOString() : null,
      createdAt: (row.createdAt as Date).toISOString(),
    };
  }
}
