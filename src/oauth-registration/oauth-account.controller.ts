import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from '../auth/auth.service';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { PrismaService } from '../prisma/prisma.service';
import { OidcBearerGuard } from './oidc-bearer.guard';

/**
 * Account-scoped endpoints for the Developer Portal SPA.
 *
 * The portal authenticates via OAuth PKCE (opaque access token), so we use
 * OidcBearerGuard — same as the rest of /oauth/* routes. The portal needs to
 * (a) know whether the logged-in user is email-verified, (b) trigger an
 * email-verify code, and (c) submit the code — without bouncing through the
 * mobile-app's JWT auth.
 */
@Controller('oauth/account')
@UseGuards(OidcBearerGuard)
export class OAuthAccountController {
  constructor(
    private readonly auth: AuthService,
    private readonly prisma: PrismaService,
  ) {}

  @Get()
  async getAccount(@CurrentUser() user: any) {
    const row = await this.prisma.user.findUnique({
      where: { id: user.sub },
      select: { email: true, emailVerified: true } as any,
    });
    return {
      email: row?.email ?? null,
      emailVerified: Boolean((row as any)?.emailVerified),
    };
  }

  @Post('email-verify/send')
  @Throttle({ short: { limit: 3, ttl: 60_000 } })
  @HttpCode(HttpStatus.OK)
  sendEmailVerify(@CurrentUser() user: any) {
    return this.auth.sendEmailVerification(user.sub);
  }

  @Post('email-verify/confirm')
  @HttpCode(HttpStatus.OK)
  confirmEmailVerify(@CurrentUser() user: any, @Body() body: { code: string }) {
    return this.auth.verifyEmail(user.sub, body?.code ?? '');
  }
}
