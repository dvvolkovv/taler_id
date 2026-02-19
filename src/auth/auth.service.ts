import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import * as bcrypt from 'bcrypt';
import { generateSecret, generateURI, verify as otpVerify } from 'otplib';
import * as QRCode from 'qrcode';
import { v4 as uuidv4 } from 'uuid';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as fs from 'fs';

@Injectable()
export class AuthService {
  private readonly privateKey: string;
  private readonly publicKey: string;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redis: RedisService,
  ) {
    const privatePath = this.configService.get<string>('jwt.privateKeyPath') ?? '';
    const publicPath = this.configService.get<string>('jwt.publicKeyPath') ?? '';
    this.privateKey = fs.readFileSync(privatePath, 'utf8');
    this.publicKey = fs.readFileSync(publicPath, 'utf8');
  }

  async register(dto: RegisterDto, ip: string, userAgent: string) {
    if (!dto.email && !dto.phone) {
      throw new BadRequestException('Email or phone is required');
    }

    // Check duplicates
    if (dto.email) {
      const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
      if (existing) throw new ConflictException('Email already registered');
    }
    if (dto.phone) {
      const existing = await this.prisma.user.findUnique({ where: { phone: dto.phone } });
      if (existing) throw new ConflictException('Phone already registered');
    }

    const bcryptRounds = this.configService.get<number>('security.bcryptRounds') ?? 12;
    const passwordHash = await bcrypt.hash(dto.password, bcryptRounds);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        phone: dto.phone,
        passwordHash,
        profile: { create: { firstName: dto.firstName, lastName: dto.lastName } },
        kycRecord: { create: {} },
      },
    });

    await this.auditLog(user.id, 'REGISTER_' + (dto.email ? 'EMAIL' : 'PHONE'), ip, userAgent);

    const session = await this.createSession(user.id, ip, userAgent);
    return this.generateTokens(user, session.id);
  }

  async login(dto: LoginDto, ip: string, userAgent: string) {
    // Build OR conditions without undefined
    const orConditions: any[] = [];
    if (dto.email) orConditions.push({ email: dto.email });
    if (dto.phone) orConditions.push({ phone: dto.phone });

    const user = await this.prisma.user.findFirst({
      where: {
        OR: orConditions,
        deletedAt: null,
      },
      include: { totpSecret: true },
    });

    // Check lockout
    const lockoutKey = `lockout:${user?.id || 'unknown'}`;
    const lockout = await this.redis.get(lockoutKey);
    if (lockout) {
      throw new ForbiddenException('Account locked due to too many failed attempts. Try again later.');
    }

    if (!user || !user.passwordHash) {
      await this.incrementFailedAttempts(user?.id || `ip:${ip}`, ip);
      await this.auditLog(null, 'LOGIN_FAILED', ip, userAgent, { reason: 'user_not_found' });
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isValid) {
      await this.incrementFailedAttempts(user.id, ip);
      await this.auditLog(user.id, 'LOGIN_FAILED', ip, userAgent, { reason: 'wrong_password' });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Clear failed attempts on success
    await this.redis.del(`failed:${user.id}`);

    // Check if 2FA is enabled
    if (user.totpSecret?.verified) {
      const challengeToken = uuidv4();
      await this.redis.setEx(`2fa_challenge:${challengeToken}`, 300, user.id); // 5 min TTL
      return { next: '2fa', challengeToken };
    }

    await this.auditLog(user.id, 'LOGIN_SUCCESS', ip, userAgent);
    const session = await this.createSession(user.id, ip, userAgent);
    return this.generateTokens(user, session.id);
  }

  async verify2fa(challengeToken: string, code: string, ip: string, userAgent: string) {
    const userId = await this.redis.get(`2fa_challenge:${challengeToken}`);
    if (!userId) throw new UnauthorizedException('Invalid or expired challenge token');

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { totpSecret: true },
    });
    if (!user || !user.totpSecret) throw new UnauthorizedException('User not found');

    const result = await otpVerify({ token: code, secret: user.totpSecret.secret });
    if (!result.valid) {
      await this.auditLog(userId, '2FA_FAILED', ip, userAgent);
      throw new UnauthorizedException('Invalid 2FA code');
    }

    await this.redis.del(`2fa_challenge:${challengeToken}`);
    await this.auditLog(userId, 'LOGIN_SUCCESS', ip, userAgent);
    const session = await this.createSession(userId, ip, userAgent);
    return this.generateTokens(user, session.id);
  }

  async setupTotp(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    const secret = generateSecret();
    const identifier = user?.email || user?.phone || userId;
    const otpAuthUri = generateURI({ issuer: 'Taler ID', label: identifier, secret });
    const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUri);

    // Save unverified secret
    await this.prisma.totpSecret.upsert({
      where: { userId },
      create: { userId, secret, verified: false },
      update: { secret, verified: false },
    });

    return { secret, qrCode: qrCodeDataUrl, otpAuthUri };
  }

  async verifyTotp(userId: string, code: string, ip: string, userAgent: string) {
    const totpRecord = await this.prisma.totpSecret.findUnique({ where: { userId } });
    if (!totpRecord) throw new BadRequestException('TOTP not set up');

    const result = await otpVerify({ token: code, secret: totpRecord.secret });
    if (!result.valid) throw new UnauthorizedException('Invalid TOTP code');

    await this.prisma.totpSecret.update({ where: { userId }, data: { verified: true } });
    await this.auditLog(userId, '2FA_ENABLED', ip, userAgent);
    return { success: true };
  }

  async disableTotp(userId: string, password: string, ip: string, userAgent: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user?.passwordHash) throw new UnauthorizedException('User not found');
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) throw new UnauthorizedException('Invalid password');

    await this.prisma.totpSecret.deleteMany({ where: { userId } });
    await this.auditLog(userId, '2FA_DISABLED', ip, userAgent);
    return { success: true };
  }

  async refreshTokens(refreshToken: string, ip: string, userAgent: string) {
    // Verify the refresh token is in Redis
    const sessionId = await this.redis.get(`refresh:${refreshToken}`);
    if (!sessionId) throw new UnauthorizedException('Invalid or expired refresh token');

    // Invalidate old refresh token (rotation)
    await this.redis.del(`refresh:${refreshToken}`);

    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: { include: { kycRecord: true } } },
    });
    if (!session || session.isRevoked) throw new UnauthorizedException('Session revoked');

    // Generate new token pair
    const newTokens = await this.generateTokens(session.user, session.id);

    // Update session lastSeenAt
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { lastSeenAt: new Date() },
    });

    return newTokens;
  }

  async logout(userId: string, sessionId: string, ip: string, userAgent: string) {
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });
    await this.auditLog(userId, 'LOGOUT', ip, userAgent);
    return { success: true };
  }

  async getSessions(userId: string) {
    return this.prisma.session.findMany({
      where: { userId, isRevoked: false, expiresAt: { gt: new Date() } },
      select: { id: true, deviceInfo: true, ipAddress: true, location: true, createdAt: true, lastSeenAt: true },
      orderBy: { lastSeenAt: 'desc' },
    });
  }

  async revokeSession(userId: string, sessionId: string, ip: string, userAgent: string) {
    const session = await this.prisma.session.findUnique({ where: { id: sessionId } });
    if (!session || session.userId !== userId) {
      throw new ForbiddenException('Cannot revoke this session');
    }
    await this.prisma.session.update({ where: { id: sessionId }, data: { isRevoked: true } });
    await this.auditLog(userId, 'SESSION_REVOKED', ip, userAgent, { revokedSessionId: sessionId });
    return { success: true };
  }

  async revokeAllSessions(userId: string, currentSessionId: string, ip: string, userAgent: string) {
    await this.prisma.session.updateMany({
      where: { userId, id: { not: currentSessionId } },
      data: { isRevoked: true },
    });
    await this.auditLog(userId, 'ALL_SESSIONS_REVOKED', ip, userAgent);
    return { success: true };
  }

  private async createSession(userId: string, ip: string, userAgent: string) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    return this.prisma.session.create({
      data: {
        userId,
        ipAddress: ip,
        deviceInfo: userAgent?.substring(0, 200),
        expiresAt,
      },
    });
  }

  private async generateTokens(user: any, sessionId: string) {
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId: user.id } });

    const payload = {
      sub: user.id,
      email: user.email,
      phone: user.phone,
      kyc_status: kyc?.status || 'UNVERIFIED',
      session_id: sessionId,
    };

    const accessToken = this.jwtService.sign(payload, {
      algorithm: 'RS256',
      privateKey: this.privateKey,
      expiresIn: '15m',
    });

    const refreshToken = uuidv4();
    const refreshTtl = 30 * 24 * 60 * 60; // 30 days in seconds
    await this.redis.setEx(`refresh:${refreshToken}`, refreshTtl, sessionId);

    return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: 900 };
  }

  private async incrementFailedAttempts(key: string, ip: string) {
    const failedKey = `failed:${key}`;
    const maxAttempts = this.configService.get<number>('security.bruteForceMaxAttempts') ?? 5;
    const lockoutMinutes = this.configService.get<number>('security.bruteForceLockouttMinutes') ?? 15;

    const attempts = await this.redis.incr(failedKey);
    await this.redis.expire(failedKey, lockoutMinutes * 60);

    if (attempts >= maxAttempts) {
      const lockoutKey = `lockout:${key}`;
      await this.redis.setEx(lockoutKey, lockoutMinutes * 60, '1');
      await this.redis.del(failedKey);
    }
  }

  async auditLog(userId: string | null, action: string, ip: string, userAgent: string, meta?: any) {
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
}
