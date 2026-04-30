import { Controller, Post, Get, Req, UseGuards, Logger } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Request } from 'express';
import { KycService } from './kyc.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';

interface RawBodyRequest extends Request {
  rawBody?: Buffer;
}

@Controller('kyc')
export class KycController {
  private readonly logger = new Logger(KycController.name);

  constructor(private readonly kycService: KycService) {}

  @Post('start')
  @UseGuards(JwtAuthGuard)
  startKyc(@CurrentUser() user: any) {
    return this.kycService.startKyc(user.sub);
  }

  @Get('status')
  @UseGuards(JwtAuthGuard)
  getStatus(@CurrentUser() user: any) {
    return this.kycService.getKycStatus(user.sub);
  }

  @Get('applicant-data')
  @UseGuards(JwtAuthGuard)
  getApplicantData(@CurrentUser() user: any) {
    return this.kycService.getApplicantData(user.sub);
  }

  @SkipThrottle()
  @Post('webhook')
  async webhook(@Req() req: RawBodyRequest) {
    // Debug: log all x- headers from Sumsub
    const xHeaders = Object.entries(req.headers)
      .filter(([k]) => k.startsWith('x-'))
      .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {});
    this.logger.log(`Sumsub webhook headers: ${JSON.stringify(xHeaders)}`);
    this.logger.log(
      `rawBody exists: ${!!req.rawBody}, body type: ${typeof req.body}`,
    );

    const signature = (req.headers['x-payload-digest'] ||
      req.headers['x-app-access-sig']) as string;
    const body = req.rawBody || Buffer.from(JSON.stringify(req.body));
    return this.kycService.handleWebhook(body, signature);
  }
}
