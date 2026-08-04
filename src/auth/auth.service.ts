import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { ACCESS_TOKEN_TYPE } from '../common/utils/access-token.util';
import * as bcrypt from 'bcrypt';
import { generateSecret, generateURI, verify as otpVerify } from 'otplib';
import * as QRCode from 'qrcode';
import { v4 as uuidv4 } from 'uuid';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as fs from 'fs';
import { EmailService } from '../email/email.service';
import { SYSTEM_USER_EMAIL } from '../system-channel/system-channel.constants';
import { SystemChannelService } from '../system-channel/system-channel.service';
import { DeviceApprovalService } from './device-approval.service';
import { NEW_DEVICE_APPROVAL_DEFAULT } from './device-approval.constants';

/**
 * How long a spent refresh token is remembered so that replaying it is
 * recognised as theft rather than reported as a plain "invalid token".
 */
const REFRESH_REPLAY_WINDOW_SECONDS = 24 * 60 * 60;

const TWO_FA_CHALLENGE_TTL_SECONDS = 300;
/** Wrong codes tolerated per challenge before it is discarded. */
const MAX_2FA_ATTEMPTS = 5;

@Injectable()
export class AuthService {
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redis: RedisService,
    private emailService: EmailService,
    private readonly systemChannel: SystemChannelService,
    private readonly deviceApproval: DeviceApprovalService,
  ) {
    const privatePath =
      this.configService.get<string>('jwt.privateKeyPath') ?? '';
    const publicPath =
      this.configService.get<string>('jwt.publicKeyPath') ?? '';
    this.privateKey = fs.readFileSync(privatePath, 'utf8');
    this.publicKey = fs.readFileSync(publicPath, 'utf8');
  }

  async register(
    dto: RegisterDto,
    ip: string,
    userAgent: string,
    deviceId?: string,
  ) {
    if (!dto.email && !dto.phone) {
      throw new BadRequestException('Email or phone is required');
    }

    const email = dto.email?.trim().toLowerCase();

    // Check duplicates
    if (email) {
      const existing = await this.prisma.user.findUnique({
        where: { email },
      });
      if (existing) throw new ConflictException('Email already registered');
    }
    if (dto.phone) {
      const existing = await this.prisma.user.findUnique({
        where: { phone: dto.phone },
      });
      if (existing) throw new ConflictException('Phone already registered');
    }

    const bcryptRounds =
      this.configService.get<number>('security.bcryptRounds') ?? 12;
    const passwordHash = await bcrypt.hash(dto.password, bcryptRounds);

    const user = await this.prisma.user.create({
      data: {
        email,
        phone: dto.phone,
        passwordHash,
        username: dto.username,
        profile: {
          create: { firstName: dto.firstName, lastName: dto.lastName },
        },
        kycRecord: { create: {} },
      },
    });

    try {
      await this.systemChannel.subscribeUser(user.id);
    } catch (e) {
      // подписка не должна ронять регистрацию
      this.logger.warn(
        `system-channel subscribe failed for ${user.id}: ${(e as Error).message}`,
      );
    }

    await this.auditLog(
      user.id,
      'REGISTER_' + (dto.email ? 'EMAIL' : 'PHONE'),
      ip,
      userAgent,
    );

    const session = await this.createSession(user.id, ip, userAgent, deviceId);
    // Первое устройство аккаунта доверяем сразу: gateDecision всё равно
    // пропустил бы его, но пусть запись существует с самого начала.
    await this.deviceApproval.touch(user.id, deviceId, userAgent, ip);
    return this.generateTokens(user, session.id);
  }

  async login(
    dto: LoginDto,
    ip: string,
    userAgent: string,
    deviceId?: string,
  ) {
    const email = dto.email?.trim().toLowerCase();

    // Build OR conditions without undefined
    const orConditions: any[] = [];
    if (email) orConditions.push({ email });
    if (dto.phone) orConditions.push({ phone: dto.phone });

    const user = await this.prisma.user.findFirst({
      where: {
        OR: orConditions,
        deletedAt: null,
      },
      include: { totpSecret: true },
    });

    // Must match the key incrementFailedAttempts() writes below. For an unknown
    // account that key is `ip:<ip>`, so checking a literal `unknown` bucket
    // meant misses were counted but never enforced.
    const lockoutSubject = user?.id || `ip:${ip}`;
    const lockout = await this.redis.get(`lockout:${lockoutSubject}`);
    if (lockout) {
      throw new ForbiddenException(
        'Account locked due to too many failed attempts. Try again later.',
      );
    }

    if (!user || !user.passwordHash) {
      await this.incrementFailedAttempts(lockoutSubject, ip);
      await this.auditLog(null, 'LOGIN_FAILED', ip, userAgent, {
        reason: 'user_not_found',
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isValid) {
      await this.incrementFailedAttempts(user.id, ip);
      await this.auditLog(user.id, 'LOGIN_FAILED', ip, userAgent, {
        reason: 'wrong_password',
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Clear failed attempts on success
    await this.redis.del(`failed:${user.id}`);

    // Check if 2FA is enabled
    if (user.totpSecret?.verified) {
      const challengeToken = uuidv4();
      await this.redis.setEx(
        `2fa_challenge:${challengeToken}`,
        TWO_FA_CHALLENGE_TTL_SECONDS,
        user.id,
      );
      return { next: '2fa', challengeToken };
    }

    return this.completeLogin(user, ip, userAgent, deviceId);
  }

  /**
   * Общий хвост успешной аутентификации — единственное место, где решается,
   * выдать сессию сразу или отправить вход ждать подтверждения. И `login()`,
   * и `verify2fa()` проходят через него: пройденный TOTP не должен быть
   * лазейкой мимо шлюза.
   */
  private async completeLogin(
    user: any,
    ip: string,
    userAgent: string,
    deviceId: string | undefined,
  ) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId: user.id },
      select: { newDeviceApproval: true },
    });
    const enabled = profile?.newDeviceApproval ?? NEW_DEVICE_APPROVAL_DEFAULT;

    const decision = await this.deviceApproval.gateDecision(
      user.id,
      deviceId,
      enabled,
    );

    if (decision === 'approve') {
      const pending = await this.deviceApproval.createPending({
        userId: user.id,
        deviceId: deviceId!,
        deviceInfo: userAgent,
        ip,
        email: user.email,
      });
      return { next: 'device_approval', ...pending };
    }

    await this.deviceApproval.touch(user.id, deviceId, userAgent, ip);
    await this.auditLog(user.id, 'LOGIN_SUCCESS', ip, userAgent);
    const session = await this.createSession(user.id, ip, userAgent, deviceId);
    return this.generateTokens(user, session.id);
  }

  /**
   * Забор токенов новым устройством после одобрения. Сессия заводится с ip и
   * user-agent, записанными в момент попытки входа, а не текущего опроса:
   * иначе в списке сессий появилось бы устройство с чужими приметами.
   */
  async claimDeviceApproval(
    approvalToken: string,
    ip: string,
    userAgent: string,
  ) {
    const outcome = await this.deviceApproval.claim(approvalToken);

    if (outcome.status !== 'approved') return { status: outcome.status };

    const record = outcome.record!;
    const user = await this.prisma.user.findUnique({
      where: { id: record.userId },
    });
    if (!user) throw new UnauthorizedException('User not found');

    await this.auditLog(user.id, 'LOGIN_SUCCESS', ip, userAgent, {
      via: 'device_approval',
    });
    const session = await this.createSession(
      user.id,
      record.ip,
      record.deviceInfo,
      record.deviceId,
    );
    const tokens = await this.generateTokens(user, session.id);
    return { status: 'approved', ...tokens };
  }

  async sendDeviceApprovalEmail(approvalToken: string) {
    const record = await this.deviceApproval.peek(approvalToken);
    const user = await this.prisma.user.findUnique({
      where: { id: record.userId },
      select: { email: true },
    });
    if (!user?.email)
      throw new BadRequestException('No email address on this account');
    return this.deviceApproval.sendEmailCode(approvalToken, user.email);
  }

  async verify2fa(
    challengeToken: string,
    code: string,
    ip: string,
    userAgent: string,
    deviceId?: string,
  ) {
    const userId = await this.redis.get(`2fa_challenge:${challengeToken}`);
    if (!userId)
      throw new UnauthorizedException('Invalid or expired challenge token');

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { totpSecret: true },
    });
    if (!user || !user.totpSecret)
      throw new UnauthorizedException('User not found');

    const result = await otpVerify({
      token: code,
      secret: user.totpSecret.secret,
    });
    if (!result.valid) {
      // A challenge used to survive its full 5 minutes no matter how many codes
      // were tried against it, and nothing counted the failures — six digits is
      // a million values, and the TOTP window accepts neighbouring codes too.
      // Burn the challenge after a handful of misses so guessing costs a fresh
      // password authentication each time.
      const attemptsKey = `2fa_attempts:${challengeToken}`;
      const attempts = await this.redis.incr(attemptsKey);
      await this.redis.expire(attemptsKey, TWO_FA_CHALLENGE_TTL_SECONDS);

      if (attempts >= MAX_2FA_ATTEMPTS) {
        await this.redis.del(`2fa_challenge:${challengeToken}`);
        await this.redis.del(attemptsKey);
        await this.auditLog(userId, '2FA_CHALLENGE_BURNED', ip, userAgent, {
          attempts,
        });
        throw new UnauthorizedException(
          'Too many invalid codes — sign in again',
        );
      }

      await this.auditLog(userId, '2FA_FAILED', ip, userAgent, { attempts });
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.redis.del(`2fa_attempts:${challengeToken}`);
    await this.redis.del(`2fa_challenge:${challengeToken}`);
    return this.completeLogin(user, ip, userAgent, deviceId);
  }

  async setupTotp(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    const secret = generateSecret();
    const identifier = user?.email || user?.phone || userId;
    const otpAuthUri = generateURI({
      issuer: 'Taler ID',
      label: identifier,
      secret,
    });
    const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUri);

    // Save unverified secret
    await this.prisma.totpSecret.upsert({
      where: { userId },
      create: { userId, secret, verified: false },
      update: { secret, verified: false },
    });

    return { secret, qrCode: qrCodeDataUrl, otpAuthUri };
  }

  async verifyTotp(
    userId: string,
    code: string,
    ip: string,
    userAgent: string,
  ) {
    const totpRecord = await this.prisma.totpSecret.findUnique({
      where: { userId },
    });
    if (!totpRecord) throw new BadRequestException('TOTP not set up');

    const result = await otpVerify({ token: code, secret: totpRecord.secret });
    if (!result.valid) throw new UnauthorizedException('Invalid TOTP code');

    await this.prisma.totpSecret.update({
      where: { userId },
      data: { verified: true },
    });
    await this.auditLog(userId, '2FA_ENABLED', ip, userAgent);
    return { success: true };
  }

  async disableTotp(
    userId: string,
    password: string,
    ip: string,
    userAgent: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user?.passwordHash) throw new UnauthorizedException('User not found');
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) throw new UnauthorizedException('Invalid password');

    await this.prisma.totpSecret.deleteMany({ where: { userId } });
    await this.auditLog(userId, '2FA_DISABLED', ip, userAgent);
    return { success: true };
  }

  async refreshTokens(refreshToken: string, ip: string, userAgent: string) {
    // Claim the token atomically. GET followed by DEL left a window in which
    // two concurrent requests both saw the token and both got a fresh pair.
    const sessionId = await this.redis
      .getClient()
      .getdel(`refresh:${refreshToken}`);

    if (!sessionId) {
      // A token that was already spent being presented again is the signature
      // of a stolen refresh token: the honest client has long since rotated to
      // the next one, so whoever holds this one copied it. Failing the single
      // request would leave the thief free to keep trying — revoke the session
      // instead, which invalidates their tokens and the victim's alike.
      const replayed = await this.redis.get(`refresh:used:${refreshToken}`);
      if (replayed) {
        await this.prisma.session.updateMany({
          where: { id: replayed, isRevoked: false },
          data: { isRevoked: true },
        });
        const revokedSession = await this.prisma.session.findUnique({
          where: { id: replayed },
          select: { userId: true },
        });
        if (revokedSession) {
          await this.auditLog(
            revokedSession.userId,
            'REFRESH_REUSE_DETECTED',
            ip,
            userAgent,
            { sessionId: replayed },
          );
        }
        throw new UnauthorizedException(
          'Refresh token reuse detected — session revoked',
        );
      }
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Remember the spent token briefly so the replay above can be recognised.
    await this.redis.setEx(
      `refresh:used:${refreshToken}`,
      REFRESH_REPLAY_WINDOW_SECONDS,
      sessionId,
    );

    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: { include: { kycRecord: true } } },
    });
    if (!session || session.isRevoked)
      throw new UnauthorizedException('Session revoked');
    // getSessions() filters on expiresAt, so an expired session disappears from
    // the user's session list — but this path never checked it, and each
    // refresh minted another 30-day token without moving Session.expiresAt.
    // A session the user can no longer see could therefore be refreshed
    // forever.
    if (session.expiresAt <= new Date())
      throw new UnauthorizedException('Session expired');

    // Generate new token pair
    const newTokens = await this.generateTokens(session.user, session.id);

    // Update session lastSeenAt
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { lastSeenAt: new Date() },
    });

    return newTokens;
  }

  async logout(
    userId: string,
    sessionId: string,
    ip: string,
    userAgent: string,
    fcmToken?: string,
    voipToken?: string,
  ) {
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });
    // Clear push tokens so this device stops receiving pushes for this user
    const clearData: any = {};
    if (fcmToken !== undefined) {
      // Only clear if the stored token matches the one being logged out
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { fcmToken: true, voipToken: true },
      });
      if (user?.fcmToken === fcmToken) clearData.fcmToken = null;
      if (voipToken !== undefined && user?.voipToken === voipToken)
        clearData.voipToken = null;
    } else {
      clearData.fcmToken = null;
      clearData.voipToken = null;
    }
    if (Object.keys(clearData).length > 0) {
      await this.prisma.user.update({ where: { id: userId }, data: clearData });
    }
    await this.auditLog(userId, 'LOGOUT', ip, userAgent);
    return { success: true };
  }

  async getSessions(userId: string, currentSessionId?: string) {
    const sessions = await this.prisma.session.findMany({
      where: { userId, isRevoked: false, expiresAt: { gt: new Date() } },
      select: {
        id: true,
        deviceInfo: true,
        ipAddress: true,
        location: true,
        createdAt: true,
        lastSeenAt: true,
      },
      orderBy: { lastSeenAt: 'desc' },
    });
    return sessions.map((s) => ({
      ...s,
      isCurrent: s.id === currentSessionId,
    }));
  }

  async revokeSession(
    userId: string,
    sessionId: string,
    ip: string,
    userAgent: string,
  ) {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });
    if (!session || session.userId !== userId) {
      throw new ForbiddenException('Cannot revoke this session');
    }
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });
    await this.auditLog(userId, 'SESSION_REVOKED', ip, userAgent, {
      revokedSessionId: sessionId,
    });
    return { success: true };
  }

  async revokeAllSessions(
    userId: string,
    currentSessionId: string,
    ip: string,
    userAgent: string,
  ) {
    await this.prisma.session.updateMany({
      where: { userId, id: { not: currentSessionId } },
      data: { isRevoked: true },
    });
    await this.auditLog(userId, 'ALL_SESSIONS_REVOKED', ip, userAgent);
    return { success: true };
  }

  private async createSession(
    userId: string,
    ip: string,
    userAgent: string,
    deviceId?: string,
  ) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    return this.prisma.session.create({
      data: {
        userId,
        ipAddress: ip,
        deviceInfo: userAgent?.substring(0, 200),
        deviceId: deviceId || null,
        expiresAt,
      },
    });
  }

  private async generateTokens(user: any, sessionId: string) {
    const kyc = await this.prisma.kycRecord.findUnique({
      where: { userId: user.id },
    });

    const payload = {
      sub: user.id,
      email: user.email,
      phone: user.phone,
      kyc_status: kyc?.status || 'UNVERIFIED',
      session_id: sessionId,
      // Marks this as an API access token. The OIDC provider signs its tokens
      // with the same key pair, so verifiers need more than a valid signature.
      typ: ACCESS_TOKEN_TYPE,
    };

    const accessToken = this.jwtService.sign(payload, {
      algorithm: 'RS256',
      privateKey: this.privateKey,
      expiresIn: '2h',
    });

    const refreshToken = uuidv4();
    const refreshTtl = 30 * 24 * 60 * 60; // 30 days in seconds
    await this.redis.setEx(`refresh:${refreshToken}`, refreshTtl, sessionId);

    return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: 7200 };
  }

  private async incrementFailedAttempts(key: string, ip: string) {
    const failedKey = `failed:${key}`;
    const maxAttempts =
      this.configService.get<number>('security.bruteForceMaxAttempts') ?? 5;
    const lockoutMinutes =
      this.configService.get<number>('security.bruteForceLockouttMinutes') ??
      15;

    const attempts = await this.redis.incr(failedKey);
    await this.redis.expire(failedKey, lockoutMinutes * 60);

    if (attempts >= maxAttempts) {
      const lockoutKey = `lockout:${key}`;
      await this.redis.setEx(lockoutKey, lockoutMinutes * 60, '1');
      await this.redis.del(failedKey);
    }
  }

  async sendEmailVerification(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user?.email)
      throw new BadRequestException('No email address on this account');
    if ((user as any).emailVerified)
      return { sent: false, alreadyVerified: true };

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redis.setEx(`email_verify:${userId}`, 600, code);
    await this.emailService.sendOtp(user.email, code, 'Email verification');
    return { sent: true };
  }

  async verifyEmail(userId: string, code: string) {
    const stored = await this.redis.get(`email_verify:${userId}`);
    if (!stored || stored !== code)
      throw new BadRequestException('Invalid or expired code');

    await this.prisma.user.update({
      where: { id: userId },
      data: { emailVerified: true } as any,
    });
    await this.redis.del(`email_verify:${userId}`);
    await this.auditLog(userId, 'EMAIL_VERIFIED', '', '');
    return { verified: true };
  }

  async auditLog(
    userId: string | null,
    action: string,
    ip: string,
    userAgent: string,
    meta?: any,
  ) {
    await this.prisma.auditLog.create({
      data: {
        userId,
        action,
        ipAddress: ip,
        userAgent: userAgent?.substring(0, 200),
        meta: meta || {},
      },
    });
  }

  // ── Password Reset ──

  async forgotPassword(email: string) {
    const normalized = email?.trim().toLowerCase();
    if (!normalized) return { sent: true };

    // Silent no-op for system account: mirrors the user-not-found path to
    // prevent enumeration while blocking the reset flow for this account.
    if (normalized === SYSTEM_USER_EMAIL) return { sent: true };

    const user = await this.prisma.user.findUnique({
      where: { email: normalized },
    });
    // Always return success to prevent email enumeration
    if (!user) return { sent: true };

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redis.setEx(`pwd_reset:${normalized}`, 600, code);
    await this.emailService.sendOtp(normalized, code, 'Password reset');
    await this.auditLog(user.id, 'PASSWORD_RESET_REQUESTED', '', '');
    return { sent: true };
  }

  async verifyForgotCode(email: string, code: string) {
    const normalized = email?.trim().toLowerCase() ?? '';
    const stored = await this.redis.get(`pwd_reset:${normalized}`);
    if (!stored || stored !== code) {
      throw new BadRequestException('Invalid or expired code');
    }

    await this.redis.del(`pwd_reset:${normalized}`);

    // Create a short-lived reset token (10 min)
    const resetToken = this.jwtService.sign(
      { email: normalized, purpose: 'password_reset' },
      { privateKey: this.privateKey, algorithm: 'RS256', expiresIn: '10m' },
    );

    return { valid: true, resetToken };
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ip: string,
    userAgent: string,
    // Kept optional so older callers still compile; when absent every session
    // is revoked, including the caller's.
    currentSessionId?: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user?.passwordHash) throw new UnauthorizedException('User not found');

    const isValid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isValid) {
      await this.auditLog(userId, 'PASSWORD_CHANGE_FAILED', ip, userAgent, {
        reason: 'wrong_current_password',
      });
      throw new UnauthorizedException('Invalid current password');
    }

    if (currentPassword === newPassword) {
      throw new BadRequestException('New password must differ from current');
    }

    const bcryptRounds =
      this.configService.get<number>('security.bcryptRounds') ?? 12;
    const passwordHash = await bcrypt.hash(newPassword, bcryptRounds);

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    // Changing the password is how a user reacts to a suspected compromise, so
    // it has to end the intruder's access. Sessions were left untouched before,
    // which meant a stolen refresh token stayed valid for its full 30 days.
    // The caller's own session survives — they just proved they know the
    // current password. Access tokens already issued live out their 2h TTL.
    await this.prisma.session.updateMany({
      where: {
        userId,
        isRevoked: false,
        ...(currentSessionId ? { id: { not: currentSessionId } } : {}),
      },
      data: { isRevoked: true },
    });

    await this.auditLog(userId, 'PASSWORD_CHANGED', ip, userAgent, {
      otherSessionsRevoked: true,
    });
    return { changed: true };
  }

  async resetPassword(resetToken: string, newPassword: string) {
    let payload: any;
    try {
      payload = this.jwtService.verify(resetToken, {
        publicKey: this.publicKey,
        algorithms: ['RS256'],
      });
    } catch {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (payload.purpose !== 'password_reset') {
      throw new BadRequestException('Invalid token purpose');
    }

    const email = String(payload.email ?? '').trim().toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new BadRequestException('User not found');

    const bcryptRounds =
      this.configService.get<number>('security.bcryptRounds') ?? 12;
    const passwordHash = await bcrypt.hash(newPassword, bcryptRounds);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordHash },
    });

    // A reset is the recovery path for an account the user may have lost
    // control of, so every existing session goes — there is no "current"
    // session to spare here, the user is not signed in.
    await this.prisma.session.updateMany({
      where: { userId: user.id, isRevoked: false },
      data: { isRevoked: true },
    });

    await this.auditLog(user.id, 'PASSWORD_RESET', '', '', {
      allSessionsRevoked: true,
    });
    return { reset: true };
  }
}
