import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Req,
  UseGuards,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto, Login2faDto, RefreshDto } from './dto/login.dto';
import {
  ApprovalTokenDto,
  ApprovalCodeDto,
} from './dto/device-approval.dto';
import { DeviceApprovalService } from './device-approval.service';
import { TrustedDeviceService } from './trusted-device.service';
import {
  ForgotPasswordDto,
  VerifyForgotCodeDto,
  ResetPasswordDto,
} from './dto/forgot-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly deviceApproval: DeviceApprovalService,
    private readonly trustedDevices: TrustedDeviceService,
  ) {}

  /**
   * Непрозрачный идентификатор устройства. Старые клиенты — десктоп, веб,
   * мобилки до 1.1.24 — его не шлют, и для них вход работает как раньше.
   */
  private deviceId(req: Request): string | undefined {
    const raw = req.headers['x-device-id'];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (!value) return undefined;
    const trimmed = String(value).trim();
    // Клиент шлёт uuid v4; всё, что на него не похоже, игнорируем, а не пишем
    // в базу — иначе кто угодно набьёт таблицу мусором произвольной длины.
    return /^[0-9a-fA-F-]{16,64}$/.test(trimmed) ? trimmed : undefined;
  }

  @Post('register')
  async register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.authService.register(
      dto,
      req.ip ?? req.socket?.remoteAddress ?? '',
      req.headers['user-agent'] ?? '',
      this.deviceId(req),
    );
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.authService.login(
      dto,
      req.ip ?? req.socket?.remoteAddress ?? '',
      req.headers['user-agent'] ?? '',
      this.deviceId(req),
    );
  }

  @Post('login/2fa')
  @HttpCode(HttpStatus.OK)
  async verify2fa(@Body() dto: Login2faDto, @Req() req: Request) {
    return this.authService.verify2fa(
      dto.challengeToken,
      dto.code,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
      this.deviceId(req),
    );
  }

  // ── Подтверждение входа с нового устройства ──

  /** Опрос новым устройством, пока оно ждёт ответа. */
  @Post('login/device-approval/status')
  @HttpCode(HttpStatus.OK)
  async approvalStatus(@Body() dto: ApprovalTokenDto, @Req() req: Request) {
    return this.authService.claimDeviceApproval(
      dto.approvalToken,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  /** Запасной канал: прислать код на адрес аккаунта. */
  @Post('login/device-approval/email')
  @HttpCode(HttpStatus.OK)
  async approvalEmail(@Body() dto: ApprovalTokenDto) {
    return this.authService.sendDeviceApprovalEmail(dto.approvalToken);
  }

  @Post('login/device-approval/verify')
  @HttpCode(HttpStatus.OK)
  async approvalVerify(@Body() dto: ApprovalCodeDto, @Req() req: Request) {
    await this.deviceApproval.verifyEmailCode(dto.approvalToken, dto.code);
    return this.authService.claimDeviceApproval(
      dto.approvalToken,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  /** Вызывается с уже доверенного устройства пользователя. */
  @Post('devices/approvals/:approvalId/approve')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async approveDevice(
    @CurrentUser() user: any,
    @Param('approvalId') approvalId: string,
  ) {
    return this.deviceApproval.approve(user.sub, approvalId);
  }

  @Post('devices/approvals/:approvalId/reject')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async rejectDevice(
    @CurrentUser() user: any,
    @Param('approvalId') approvalId: string,
  ) {
    return this.deviceApproval.reject(user.sub, approvalId);
  }

  /** Ожидания подтверждения — на случай, когда пуш не дошёл. */
  @Get('devices/approvals/pending')
  @UseGuards(JwtAuthGuard)
  async pendingApprovals(@CurrentUser() user: any) {
    return this.deviceApproval.listPending(user.sub);
  }

  @Get('devices')
  @UseGuards(JwtAuthGuard)
  async listDevices(@CurrentUser() user: any, @Req() req: Request) {
    return this.trustedDevices.list(user.sub, this.deviceId(req));
  }

  @Delete('devices/:id')
  @UseGuards(JwtAuthGuard)
  async revokeDevice(
    @CurrentUser() user: any,
    @Param('id') id: string,
    @Req() req: Request,
  ) {
    return this.trustedDevices.revoke(
      user.sub,
      id,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() dto: RefreshDto, @Req() req: Request) {
    return this.authService.refreshTokens(
      dto.refreshToken,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: any,
    @Req() req: Request,
    @Body() body?: { fcmToken?: string; voipToken?: string },
  ) {
    return this.authService.logout(
      user.sub,
      user.session_id,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
      body?.fcmToken,
      body?.voipToken,
    );
  }

  @Get('2fa/totp/setup')
  @UseGuards(JwtAuthGuard)
  async setupTotp(@CurrentUser() user: any) {
    return this.authService.setupTotp(user.sub);
  }

  @Post('2fa/totp/verify')
  @UseGuards(JwtAuthGuard)
  async verifyTotpSetup(
    @Body() body: { code: string },
    @CurrentUser() user: any,
    @Req() req: Request,
  ) {
    return this.authService.verifyTotp(
      user.sub,
      body.code,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  @Delete('2fa/totp')
  @UseGuards(JwtAuthGuard)
  async disableTotp(
    @Body() body: { password: string },
    @CurrentUser() user: any,
    @Req() req: Request,
  ) {
    return this.authService.disableTotp(
      user.sub,
      body.password,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getSessions(@CurrentUser() user: any) {
    return this.authService.getSessions(user.sub, user.session_id);
  }

  @Delete('sessions/:id')
  @UseGuards(JwtAuthGuard)
  async revokeSession(
    @Param('id') sessionId: string,
    @CurrentUser() user: any,
    @Req() req: Request,
  ) {
    return this.authService.revokeSession(
      user.sub,
      sessionId,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  @Delete('sessions')
  @UseGuards(JwtAuthGuard)
  async revokeAllSessions(@CurrentUser() user: any, @Req() req: Request) {
    return this.authService.revokeAllSessions(
      user.sub,
      user.session_id,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  @Post('email/verify/send')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async sendEmailVerification(@CurrentUser() user: any) {
    return this.authService.sendEmailVerification(user.sub);
  }

  @Post('email/verify/confirm')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() body: { code: string }, @CurrentUser() user: any) {
    return this.authService.verifyEmail(user.sub, body.code);
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto.email);
  }

  @Post('forgot-password/verify')
  @HttpCode(HttpStatus.OK)
  async verifyForgotCode(@Body() dto: VerifyForgotCodeDto) {
    return this.authService.verifyForgotCode(dto.email, dto.code);
  }

  @Post('forgot-password/reset')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto.resetToken, dto.newPassword);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @Body() dto: ChangePasswordDto,
    @CurrentUser() user: any,
    @Req() req: Request,
  ) {
    return this.authService.changePassword(
      user.sub,
      dto.currentPassword,
      dto.newPassword,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
      user.session_id,
    );
  }
}
