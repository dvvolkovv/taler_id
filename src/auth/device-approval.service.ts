import {
  Injectable,
  Logger,
  HttpException,
  HttpStatus,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { FcmService } from '../common/fcm.service';
import { EmailService } from '../email/email.service';
import {
  APPROVAL_TTL_SECONDS,
  APPROVAL_CLAIMED_TTL_SECONDS,
  MAX_PENDING_PER_HOUR,
  MAX_EMAIL_SENDS,
  MAX_CODE_ATTEMPTS,
  EMAIL_RESEND_COOLDOWN_SECONDS,
  ApprovalRecord,
  approvalKey,
  approvalIdKey,
  claimedKey,
  codeKey,
  codeAttemptsKey,
  emailSendsKey,
  emailCooldownKey,
  rateKey,
} from './device-approval.constants';

export interface CreatePendingInput {
  userId: string;
  deviceId: string;
  deviceInfo: string;
  ip: string;
  location?: string | null;
  email?: string | null;
}

@Injectable()
export class DeviceApprovalService {
  private readonly logger = new Logger(DeviceApprovalService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly fcm: FcmService,
    private readonly email: EmailService,
  ) {}

  /**
   * Заводит ожидание и будит доверенные устройства.
   *
   * Возвращает `approvalToken` — секрет, который уходит ТОЛЬКО в тело ответа
   * новому устройству. В пуш едет `approvalId`: превью уведомления на
   * заблокированном экране не должно давать никакого доступа к аккаунту.
   */
  async createPending(input: CreatePendingInput): Promise<{
    approvalToken: string;
    approverCount: number;
    emailAvailable: boolean;
    expiresIn: number;
  }> {
    const attempts = await this.redis.incr(rateKey(input.userId));
    await this.redis.expire(rateKey(input.userId), 3600);
    if (attempts > MAX_PENDING_PER_HOUR) {
      throw new HttpException(
        'Too many sign-in attempts from new devices. Try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const approvalToken = uuidv4();
    const approvalId = uuidv4();

    const record: ApprovalRecord = {
      approvalId,
      userId: input.userId,
      deviceId: input.deviceId,
      deviceInfo: input.deviceInfo?.substring(0, 200) ?? '',
      ip: input.ip,
      location: input.location ?? null,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    await this.redis.setEx(
      approvalKey(approvalToken),
      APPROVAL_TTL_SECONDS,
      JSON.stringify(record),
    );
    await this.redis.setEx(
      approvalIdKey(approvalId),
      APPROVAL_TTL_SECONDS,
      approvalToken,
    );

    const approvers = await this.prisma.session.findMany({
      where: {
        userId: input.userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
        fcmToken: { not: null },
        NOT: { deviceId: input.deviceId },
      },
      select: { id: true, fcmToken: true, deviceId: true },
    });

    for (const session of approvers) {
      if (!session.fcmToken) continue;
      try {
        await this.fcm.sendDeviceApprovalRequest(session.fcmToken, {
          approvalId,
          deviceInfo: record.deviceInfo,
          ip: record.ip,
          location: record.location,
        });
      } catch (e) {
        // Недоставленный пуш не должен ронять вход: на этот случай есть код
        // на почту, и человек всё равно доберётся до своего аккаунта.
        this.logger.warn(
          `approval push failed for session ${session.id}: ${(e as Error).message}`,
        );
      }
    }

    await this.prisma.auditLog.create({
      data: {
        userId: input.userId,
        action: 'DEVICE_APPROVAL_REQUESTED',
        ipAddress: input.ip,
        userAgent: record.deviceInfo,
        meta: { approvalId, approvers: approvers.length },
      },
    });

    return {
      approvalToken,
      approverCount: approvers.length,
      emailAvailable: Boolean(input.email),
      expiresIn: APPROVAL_TTL_SECONDS,
    };
  }

  private async load(approvalId: string): Promise<{
    token: string;
    record: ApprovalRecord;
  }> {
    const token = await this.redis.get(approvalIdKey(approvalId));
    if (!token) throw new NotFoundException('Approval request not found');
    const raw = await this.redis.get(approvalKey(token));
    if (!raw) throw new NotFoundException('Approval request not found');
    return { token, record: JSON.parse(raw) as ApprovalRecord };
  }

  private async save(token: string, record: ApprovalRecord) {
    // TTL держим исходный: одобрение не должно продлевать окно ожидания.
    await this.redis.setEx(
      approvalKey(token),
      APPROVAL_TTL_SECONDS,
      JSON.stringify(record),
    );
  }

  /** Вызывается с уже доверенного устройства пользователя. */
  async approve(userId: string, approvalId: string) {
    const { token, record } = await this.load(approvalId);
    // Чужое ожидание отвечает тем же «не найдено», что и несуществующее:
    // иначе по коду ответа можно перебирать чужие approvalId.
    if (record.userId !== userId)
      throw new NotFoundException('Approval request not found');
    if (record.status === 'rejected')
      throw new BadRequestException('This request was already rejected');

    record.status = 'approved';
    await this.save(token, record);

    // Доверие выдаём здесь, а не при заборе токенов: если ответ на заборе
    // потеряется в сети, повторный вход пройдёт уже как со знакомого
    // устройства — сценарий самозалечивается.
    await this.prisma.trustedDevice.upsert({
      where: {
        userId_deviceId: { userId, deviceId: record.deviceId },
      },
      create: {
        userId,
        deviceId: record.deviceId,
        deviceInfo: record.deviceInfo,
        lastIp: record.ip,
        lastLocation: record.location,
      },
      update: {
        revokedAt: null,
        lastSeenAt: new Date(),
        lastIp: record.ip,
        lastLocation: record.location,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        userId,
        action: 'DEVICE_APPROVED',
        ipAddress: record.ip,
        userAgent: record.deviceInfo,
        meta: { approvalId, deviceId: record.deviceId },
      },
    });

    return { success: true };
  }

  async reject(userId: string, approvalId: string) {
    const { token, record } = await this.load(approvalId);
    if (record.userId !== userId)
      throw new NotFoundException('Approval request not found');

    record.status = 'rejected';
    await this.save(token, record);

    await this.prisma.auditLog.create({
      data: {
        userId,
        action: 'DEVICE_REJECTED',
        ipAddress: record.ip,
        userAgent: record.deviceInfo,
        meta: { approvalId, deviceId: record.deviceId },
      },
    });

    return { success: true };
  }

  /**
   * Опрашивается новым устройством, пока оно ждёт ответа.
   *
   * Забор одобренной записи атомарный (`GETDEL`): два опроса, прилетевших
   * одновременно, не должны выдать две сессии на один вход. Проигравший
   * получает `claimed`, а не `expired` — иначе человеку, который только что
   * вошёл, показали бы ошибку.
   */
  async claim(approvalToken: string): Promise<{
    status: 'pending' | 'approved' | 'rejected' | 'expired' | 'claimed';
    record?: ApprovalRecord;
  }> {
    const raw = await this.redis.get(approvalKey(approvalToken));

    if (!raw) {
      const claimed = await this.redis.get(claimedKey(approvalToken));
      return { status: claimed ? 'claimed' : 'expired' };
    }

    const record = JSON.parse(raw) as ApprovalRecord;

    if (record.status === 'pending') return { status: 'pending' };

    if (record.status === 'rejected') {
      await this.redis.del(approvalKey(approvalToken));
      await this.redis.del(approvalIdKey(record.approvalId));
      return { status: 'rejected' };
    }

    const taken = await this.redis
      .getClient()
      .getdel(approvalKey(approvalToken));
    if (!taken) return { status: 'claimed' };

    await this.redis.del(approvalIdKey(record.approvalId));
    await this.redis.setEx(
      claimedKey(approvalToken),
      APPROVAL_CLAIMED_TTL_SECONDS,
      '1',
    );

    return { status: 'approved', record };
  }

  /** Чтение записи без изменения статуса. */
  async peek(approvalToken: string): Promise<ApprovalRecord> {
    const raw = await this.redis.get(approvalKey(approvalToken));
    if (!raw) throw new NotFoundException('Approval request not found');
    return JSON.parse(raw) as ApprovalRecord;
  }

  /**
   * Запасной канал для того, у кого одно устройство или до остальных не
   * доходят пуши. Без него фича превращается в способ потерять доступ
   * к собственному аккаунту.
   */
  async sendEmailCode(approvalToken: string, email: string) {
    const record = await this.peek(approvalToken);
    if (record.status !== 'pending')
      throw new BadRequestException('This request is already resolved');

    if (await this.redis.get(emailCooldownKey(approvalToken))) {
      throw new BadRequestException(
        `Please wait ${EMAIL_RESEND_COOLDOWN_SECONDS} seconds before requesting another code`,
      );
    }

    const sends = await this.redis.incr(emailSendsKey(approvalToken));
    await this.redis.expire(emailSendsKey(approvalToken), APPROVAL_TTL_SECONDS);
    if (sends > MAX_EMAIL_SENDS)
      throw new BadRequestException('Too many codes requested — sign in again');

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redis.setEx(codeKey(approvalToken), APPROVAL_TTL_SECONDS, code);
    await this.redis.setEx(
      emailCooldownKey(approvalToken),
      EMAIL_RESEND_COOLDOWN_SECONDS,
      '1',
    );
    await this.email.sendOtp(email, code, 'New device sign-in');

    return { sent: true };
  }

  async verifyEmailCode(approvalToken: string, code: string) {
    const record = await this.peek(approvalToken);

    const stored = await this.redis.get(codeKey(approvalToken));
    if (!stored || stored !== code) {
      // Шесть цифр — миллион вариантов, но подбирать их можно быстро.
      // Сжигаем ожидание после горстки промахов: каждая новая попытка
      // тогда стоит заново введённого пароля.
      const attempts = await this.redis.incr(codeAttemptsKey(approvalToken));
      await this.redis.expire(
        codeAttemptsKey(approvalToken),
        APPROVAL_TTL_SECONDS,
      );
      if (attempts >= MAX_CODE_ATTEMPTS) {
        await this.redis.del(approvalKey(approvalToken));
        await this.redis.del(approvalIdKey(record.approvalId));
        await this.redis.del(codeKey(approvalToken));
        throw new BadRequestException('Too many invalid codes — sign in again');
      }
      throw new BadRequestException('Invalid or expired code');
    }

    await this.redis.del(codeKey(approvalToken));
    await this.redis.del(codeAttemptsKey(approvalToken));

    record.status = 'approved';
    await this.save(approvalToken, record);
    await this.prisma.trustedDevice.upsert({
      where: {
        userId_deviceId: {
          userId: record.userId,
          deviceId: record.deviceId,
        },
      },
      create: {
        userId: record.userId,
        deviceId: record.deviceId,
        deviceInfo: record.deviceInfo,
        lastIp: record.ip,
        lastLocation: record.location,
      },
      update: {
        revokedAt: null,
        lastSeenAt: new Date(),
        lastIp: record.ip,
        lastLocation: record.location,
      },
    });
    await this.prisma.auditLog.create({
      data: {
        userId: record.userId,
        action: 'DEVICE_APPROVED',
        ipAddress: record.ip,
        userAgent: record.deviceInfo,
        meta: { via: 'email', deviceId: record.deviceId },
      },
    });

    return { success: true };
  }
}
