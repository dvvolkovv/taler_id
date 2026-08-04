import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class TrustedDeviceService {
  constructor(private readonly prisma: PrismaService) {}

  async list(userId: string, currentDeviceId?: string) {
    const devices = await this.prisma.trustedDevice.findMany({
      where: { userId, revokedAt: null },
      orderBy: { lastSeenAt: 'desc' },
      select: {
        id: true,
        deviceId: true,
        deviceInfo: true,
        label: true,
        lastIp: true,
        lastLocation: true,
        firstSeenAt: true,
        lastSeenAt: true,
      },
    });
    return devices.map((d) => ({
      ...d,
      isCurrent: Boolean(currentDeviceId) && d.deviceId === currentDeviceId,
    }));
  }

  /**
   * Отзыв должен что-то значить: помимо снятия доверия гасим живые сессии
   * этого устройства. Иначе выданный ему 30-дневный refresh продолжал бы
   * работать, и «отозвал» на экране означало бы ровно ничего.
   */
  async revoke(userId: string, id: string, ip: string, userAgent: string) {
    const device = await this.prisma.trustedDevice.findFirst({
      where: { id, userId },
    });
    if (!device) throw new NotFoundException('Device not found');

    await this.prisma.trustedDevice.update({
      where: { id },
      data: { revokedAt: new Date() },
    });
    await this.prisma.session.updateMany({
      where: { userId, deviceId: device.deviceId, isRevoked: false },
      data: { isRevoked: true },
    });
    await this.prisma.auditLog.create({
      data: {
        userId,
        action: 'TRUSTED_DEVICE_REVOKED',
        ipAddress: ip,
        userAgent: userAgent?.substring(0, 200),
        meta: { deviceId: device.deviceId },
      },
    });

    return { success: true };
  }
}
