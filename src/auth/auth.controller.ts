import {
  Controller, Post, Get, Delete, Body, Req, UseGuards, Param, HttpCode, HttpStatus
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto, Login2faDto, RefreshDto } from './dto/login.dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.authService.register(dto, req.ip ?? req.socket?.remoteAddress ?? '', req.headers['user-agent'] ?? '');
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.authService.login(dto, req.ip ?? req.socket?.remoteAddress ?? '', req.headers['user-agent'] ?? '');
  }

  @Post('login/2fa')
  @HttpCode(HttpStatus.OK)
  async verify2fa(@Body() dto: Login2faDto, @Req() req: Request) {
    return this.authService.verify2fa(dto.challengeToken, dto.code, req.ip ?? '', req.headers['user-agent'] ?? '');
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() dto: RefreshDto, @Req() req: Request) {
    return this.authService.refreshTokens(dto.refreshToken, req.ip ?? '', req.headers['user-agent'] ?? '');
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@CurrentUser() user: any, @Req() req: Request) {
    return this.authService.logout(user.sub, user.session_id, req.ip ?? '', req.headers['user-agent'] ?? '');
  }

  @Get('2fa/totp/setup')
  @UseGuards(JwtAuthGuard)
  async setupTotp(@CurrentUser() user: any) {
    return this.authService.setupTotp(user.sub);
  }

  @Post('2fa/totp/verify')
  @UseGuards(JwtAuthGuard)
  async verifyTotpSetup(@Body() body: { code: string }, @CurrentUser() user: any, @Req() req: Request) {
    return this.authService.verifyTotp(user.sub, body.code, req.ip ?? '', req.headers['user-agent'] ?? '');
  }

  @Delete('2fa/totp')
  @UseGuards(JwtAuthGuard)
  async disableTotp(@Body() body: { password: string }, @CurrentUser() user: any, @Req() req: Request) {
    return this.authService.disableTotp(user.sub, body.password, req.ip ?? '', req.headers['user-agent'] ?? '');
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getSessions(@CurrentUser() user: any) {
    return this.authService.getSessions(user.sub, user.session_id);
  }

  @Delete('sessions/:id')
  @UseGuards(JwtAuthGuard)
  async revokeSession(@Param('id') sessionId: string, @CurrentUser() user: any, @Req() req: Request) {
    return this.authService.revokeSession(user.sub, sessionId, req.ip ?? '', req.headers['user-agent'] ?? '');
  }

  @Delete('sessions')
  @UseGuards(JwtAuthGuard)
  async revokeAllSessions(@CurrentUser() user: any, @Req() req: Request) {
    return this.authService.revokeAllSessions(user.sub, user.session_id, req.ip ?? '', req.headers['user-agent'] ?? '');
  }
}
