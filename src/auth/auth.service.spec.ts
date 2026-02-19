import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import {
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';

// Mock all ESM/native modules that can't be loaded in Jest
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockReturnValue('mock-key-content'),
}));

jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'MOCKSECRET12345678'),
  generateURI: jest.fn(() => 'otpauth://totp/Taler%20ID:test@example.com?secret=MOCKSECRET&issuer=Taler%20ID'),
  generate: jest.fn(() => '123456'),
  verify: jest.fn(() => true),
}));

jest.mock('qrcode', () => ({
  toDataURL: jest.fn(() => Promise.resolve('data:image/png;base64,mockQR')),
}));

const mockPrisma = {
  user: { findFirst: jest.fn(), findUnique: jest.fn(), create: jest.fn() },
  session: { create: jest.fn(), findMany: jest.fn(), findUnique: jest.fn(), update: jest.fn(), updateMany: jest.fn() },
  kycRecord: { findUnique: jest.fn(), create: jest.fn(), update: jest.fn() },
  totpSecret: { findUnique: jest.fn(), upsert: jest.fn(), update: jest.fn(), deleteMany: jest.fn() },
  auditLog: { create: jest.fn() },
};

const mockRedis = {
  get: jest.fn(), set: jest.fn(), setEx: jest.fn(), del: jest.fn(), incr: jest.fn(), expire: jest.fn(),
};

const mockJwt = {
  sign: jest.fn().mockReturnValue('mock.jwt.token'),
  verifyAsync: jest.fn(),
};

const mockConfig = {
  get: jest.fn((key: string) => {
    const config: Record<string, any> = {
      'jwt.privateKeyPath': '/fake/private.pem',
      'jwt.publicKeyPath': '/fake/public.pem',
      'jwt.accessExpiresIn': 900,
      'jwt.refreshExpiresIn': 2592000,
      'security.bcryptRounds': 10,
      'security.bruteForceMaxAttempts': 5,
      'security.bruteForceLockouttMinutes': 15,
    };
    return config[key];
  }),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: RedisService, useValue: mockRedis },
        { provide: JwtService, useValue: mockJwt },
        { provide: ConfigService, useValue: mockConfig },
      ],
    }).compile();
    service = module.get<AuthService>(AuthService);
  });

  describe('register', () => {
    it('creates user and returns tokens', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      mockPrisma.user.create.mockResolvedValue({ id: 'u1', email: 'test@example.com', phone: null });
      mockPrisma.session.create.mockResolvedValue({ id: 'session-1' });
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: 'UNVERIFIED' });
      mockRedis.setEx.mockResolvedValue('OK');
      mockPrisma.auditLog.create.mockResolvedValue({});

      const result = await service.register({ email: 'test@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest');
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result.tokenType).toBe('Bearer');
      expect(result.expiresIn).toBe(900);
    });

    it('hashes password before storing', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      let captured: any;
      mockPrisma.user.create.mockImplementation(async ({ data }) => { captured = data; return { id: 'u1', email: data.email, phone: null }; });
      mockPrisma.session.create.mockResolvedValue({ id: 'session-1' });
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: 'UNVERIFIED' });
      mockRedis.setEx.mockResolvedValue('OK');
      mockPrisma.auditLog.create.mockResolvedValue({});

      await service.register({ email: 'hash@example.com', password: 'PlainTextX' }, '127.0.0.1', 'Jest');
      expect(captured.passwordHash).not.toBe('PlainTextX');
      const valid = await bcrypt.compare('PlainTextX', captured.passwordHash);
      expect(valid).toBe(true);
    });

    it('throws ConflictException on duplicate email', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ id: 'existing', email: 'test@example.com' });
      await expect(service.register({ email: 'test@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest'))
        .rejects.toThrow(ConflictException);
    });

    it('stores refresh token in Redis with TTL', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      mockPrisma.user.create.mockResolvedValue({ id: 'u2', email: 'r@example.com', phone: null });
      mockPrisma.session.create.mockResolvedValue({ id: 'session-2' });
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: 'UNVERIFIED' });
      mockRedis.setEx.mockResolvedValue('OK');
      mockPrisma.auditLog.create.mockResolvedValue({});

      await service.register({ email: 'r@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest');
      expect(mockRedis.setEx).toHaveBeenCalledTimes(1);
      const [key, ttl] = mockRedis.setEx.mock.calls[0];
      expect(key).toMatch(/^refresh:/);
      expect(ttl).toBeGreaterThan(0);
    });
  });

  describe('login', () => {
    it('returns tokens for valid credentials', async () => {
      const hash = await bcrypt.hash('Password1x', 10);
      mockPrisma.user.findFirst.mockResolvedValue({ id: 'u1', email: 'test@example.com', phone: null, passwordHash: hash, totpSecret: null });
      mockRedis.get.mockResolvedValue(null);
      mockPrisma.session.create.mockResolvedValue({ id: 'session-1' });
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: 'UNVERIFIED' });
      mockRedis.setEx.mockResolvedValue('OK');
      mockRedis.del.mockResolvedValue(1);
      mockPrisma.auditLog.create.mockResolvedValue({});

      const result = await service.login({ email: 'test@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest');
      expect(result).toHaveProperty('accessToken');
      expect(result.tokenType).toBe('Bearer');
    });

    it('throws UnauthorizedException for wrong password', async () => {
      const hash = await bcrypt.hash('correctPassword', 10);
      mockPrisma.user.findFirst.mockResolvedValue({ id: 'u1', email: 'test@example.com', phone: null, passwordHash: hash, totpSecret: null });
      mockRedis.get.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(1);
      mockRedis.expire.mockResolvedValue(1);
      mockPrisma.auditLog.create.mockResolvedValue({});

      await expect(service.login({ email: 'test@example.com', password: 'wrongPassword' }, '127.0.0.1', 'Jest'))
        .rejects.toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException for non-existent user', async () => {
      mockPrisma.user.findFirst.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(1);
      mockRedis.expire.mockResolvedValue(1);
      mockPrisma.auditLog.create.mockResolvedValue({});

      await expect(service.login({ email: 'nobody@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest'))
        .rejects.toThrow(UnauthorizedException);
    });

    it('throws ForbiddenException when account is locked', async () => {
      const hash = await bcrypt.hash('Password1x', 10);
      mockPrisma.user.findFirst.mockResolvedValue({ id: 'u-locked', email: 'locked@example.com', phone: null, passwordHash: hash, totpSecret: null });
      mockRedis.get.mockResolvedValue('1');

      await expect(service.login({ email: 'locked@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest'))
        .rejects.toThrow(ForbiddenException);
    });

    it('returns 2fa challenge when TOTP is enabled', async () => {
      const hash = await bcrypt.hash('Password1x', 10);
      mockPrisma.user.findFirst.mockResolvedValue({ id: 'u-totp', email: 'totp@example.com', phone: null, passwordHash: hash, totpSecret: { secret: 'TOTP_SECRET', verified: true } });
      mockRedis.get.mockResolvedValue(null);
      mockRedis.setEx.mockResolvedValue('OK');
      mockRedis.del.mockResolvedValue(1);
      mockPrisma.auditLog.create.mockResolvedValue({});

      const result = await service.login({ email: 'totp@example.com', password: 'Password1x' }, '127.0.0.1', 'Jest');
      expect(result).toHaveProperty('next', '2fa');
      expect(result).toHaveProperty('challengeToken');
    });

    it('increments failed attempts on wrong password', async () => {
      const hash = await bcrypt.hash('correct', 10);
      mockPrisma.user.findFirst.mockResolvedValue({ id: 'u1', email: 'fail@example.com', phone: null, passwordHash: hash, totpSecret: null });
      mockRedis.get.mockResolvedValue(null);
      mockRedis.incr.mockResolvedValue(1);
      mockRedis.expire.mockResolvedValue(1);
      mockPrisma.auditLog.create.mockResolvedValue({});

      await expect(service.login({ email: 'fail@example.com', password: 'wrong' }, '127.0.0.1', 'Jest'))
        .rejects.toThrow(UnauthorizedException);
      expect(mockRedis.incr).toHaveBeenCalledWith(expect.stringContaining('failed:'));
    });
  });

  describe('refreshTokens', () => {
    it('returns new token pair for valid refresh token', async () => {
      mockRedis.get.mockResolvedValue('session-uuid-1');
      mockRedis.del.mockResolvedValue(1);
      mockPrisma.session.findUnique.mockResolvedValue({
        id: 'session-uuid-1', userId: 'u1', isRevoked: false,
        expiresAt: new Date(Date.now() + 86400000),
        user: { id: 'u1', email: 'test@example.com', phone: null, kycRecord: { status: 'UNVERIFIED' } },
      });
      mockPrisma.session.update.mockResolvedValue({});
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: 'UNVERIFIED' });
      mockRedis.setEx.mockResolvedValue('OK');
      mockPrisma.auditLog.create.mockResolvedValue({});

      const result = await service.refreshTokens('valid-refresh', '127.0.0.1', 'Jest');
      expect(result).toHaveProperty('accessToken');
      expect(result.tokenType).toBe('Bearer');
    });

    it('throws UnauthorizedException for invalid refresh token', async () => {
      mockRedis.get.mockResolvedValue(null);
      await expect(service.refreshTokens('invalid', '127.0.0.1', 'Jest')).rejects.toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException for revoked session', async () => {
      mockRedis.get.mockResolvedValue('session-revoked');
      mockRedis.del.mockResolvedValue(1);
      mockPrisma.session.findUnique.mockResolvedValue({ id: 'session-revoked', userId: 'u1', isRevoked: true, user: { id: 'u1', email: 'test@example.com', phone: null } });
      await expect(service.refreshTokens('some-token', '127.0.0.1', 'Jest')).rejects.toThrow(UnauthorizedException);
    });

    it('deletes old refresh token from Redis (rotation)', async () => {
      mockRedis.get.mockResolvedValue('session-uuid-1');
      mockRedis.del.mockResolvedValue(1);
      mockPrisma.session.findUnique.mockResolvedValue({
        id: 'session-uuid-1', userId: 'u1', isRevoked: false,
        user: { id: 'u1', email: 'test@example.com', phone: null },
      });
      mockPrisma.session.update.mockResolvedValue({});
      mockPrisma.kycRecord.findUnique.mockResolvedValue({ status: 'UNVERIFIED' });
      mockRedis.setEx.mockResolvedValue('OK');
      mockPrisma.auditLog.create.mockResolvedValue({});

      await service.refreshTokens('old-token', '127.0.0.1', 'Jest');
      expect(mockRedis.del).toHaveBeenCalledWith('refresh:old-token');
    });
  });

  describe('getSessions', () => {
    it('returns active sessions for user', async () => {
      mockPrisma.session.findMany.mockResolvedValue([
        { id: 's1', deviceInfo: 'Chrome', ipAddress: '127.0.0.1', createdAt: new Date(), lastSeenAt: new Date() },
        { id: 's2', deviceInfo: 'Safari', ipAddress: '10.0.0.1', createdAt: new Date(), lastSeenAt: new Date() },
      ]);
      const result = await service.getSessions('user-1');
      expect(result).toHaveLength(2);
    });
  });

  describe('logout', () => {
    it('revokes session and returns success', async () => {
      mockPrisma.session.update.mockResolvedValue({ id: 'session-1', isRevoked: true });
      mockPrisma.auditLog.create.mockResolvedValue({});

      const result = await service.logout('u1', 'session-1', '127.0.0.1', 'Jest');
      expect(result.success).toBe(true);
      expect(mockPrisma.session.update).toHaveBeenCalledWith({ where: { id: 'session-1' }, data: { isRevoked: true } });
    });
  });

  describe("verify2FA", () => {
    it("throws UnauthorizedException for invalid challenge token", async () => {
      mockRedis.get.mockResolvedValue(null);
      await expect(service.verify2fa("bad-token", "123456", "127.0.0.1", "UA")).rejects.toThrow(UnauthorizedException);
    });

    it("throws UnauthorizedException when user has no TOTP", async () => {
      mockRedis.get.mockResolvedValue("user-1");
      mockPrisma.user.findUnique.mockResolvedValue({ id: "user-1", totpSecret: null });
      await expect(service.verify2fa("tok", "123456", "127.0.0.1", "UA")).rejects.toThrow(UnauthorizedException);
    });

    it("throws UnauthorizedException for invalid TOTP code", async () => {
      const otplib = require("otplib");
      otplib.verify.mockReturnValueOnce(false);
      mockRedis.get.mockResolvedValue("user-1");
      mockPrisma.user.findUnique.mockResolvedValue({
        id: "user-1",
        email: "t@t.com",
        totpSecret: { secret: "JBSWY3DPEHPK3PXP" },
      });
      mockPrisma.auditLog.create.mockResolvedValue({});
      await expect(service.verify2fa("tok", "000000", "127.0.0.1", "UA")).rejects.toThrow(UnauthorizedException);
    });
  });

  describe("setupTotp", () => {
    it("returns secret, qrCode, otpAuthUri", async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ id: "u1", email: "a@b.com" });
      mockPrisma.totpSecret.upsert.mockResolvedValue({});
      const result = await service.setupTotp("u1");
      expect(result).toHaveProperty("secret");
      expect(result).toHaveProperty("qrCode");
      expect(result).toHaveProperty("otpAuthUri");
    });
  });

  describe("verifyTotp", () => {
    it("throws BadRequestException when TOTP not set up", async () => {
      mockPrisma.totpSecret.findUnique.mockResolvedValue(null);
      await expect(service.verifyTotp("u1", "123456", "127.0.0.1", "UA")).rejects.toThrow(BadRequestException);
    });

    it("throws UnauthorizedException for invalid code", async () => {
      const otplib = require("otplib");
      otplib.verify.mockReturnValueOnce(false);
      mockPrisma.totpSecret.findUnique.mockResolvedValue({ secret: "JBSWY3DPEHPK3PXP", verified: false });
      mockPrisma.auditLog.create.mockResolvedValue({});
      await expect(service.verifyTotp("u1", "000000", "127.0.0.1", "UA")).rejects.toThrow(UnauthorizedException);
    });
  });

  describe("disableTotp", () => {
    it("throws UnauthorizedException when password is wrong", async () => {
      const bcryptLib = require("bcrypt");
      const hash = await bcryptLib.hash("correct", 10);
      mockPrisma.user.findUnique.mockResolvedValue({ id: "u1", passwordHash: hash });
      mockPrisma.auditLog.create.mockResolvedValue({});
      await expect(service.disableTotp("u1", "wrong", "127.0.0.1", "UA")).rejects.toThrow(UnauthorizedException);
    });
  });

  describe("revokeSession", () => {
    it("throws ForbiddenException for session belonging to another user", async () => {
      mockPrisma.session.findUnique.mockResolvedValue({ id: "s1", userId: "other-user" });
      await expect(service.revokeSession("u1", "s1", "127.0.0.1", "UA")).rejects.toThrow(ForbiddenException);
    });

    it("revokes own session successfully", async () => {
      mockPrisma.session.findUnique.mockResolvedValue({ id: "s1", userId: "u1" });
      mockPrisma.session.update.mockResolvedValue({ id: "s1", isRevoked: true });
      const result = await service.revokeSession("u1", "s1", "127.0.0.1", "UA");
      expect(result.success).toBe(true);
      expect(mockPrisma.session.update).toHaveBeenCalledWith(
        expect.objectContaining({ data: { isRevoked: true } })
      );
    });
  });

  describe("revokeAllSessions", () => {
    it("revokes all sessions except current", async () => {
      mockPrisma.session.updateMany.mockResolvedValue({ count: 3 });
      const result = await service.revokeAllSessions("u1", "current-session", "127.0.0.1", "UA");
      expect(result.success).toBe(true);
      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ id: { not: "current-session" } }),
        })
      );
    });
  });

});
