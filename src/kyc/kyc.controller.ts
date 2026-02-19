import { Controller, Post, Get, Req, UseGuards } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import { Request } from "express";
import { KycService } from "./kyc.service";
import { JwtAuthGuard } from "../common/guards/jwt-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";

interface RawBodyRequest extends Request {
  rawBody?: Buffer;
}

@Controller("kyc")
export class KycController {
  constructor(private readonly kycService: KycService) {}

  @Post("start")
  @UseGuards(JwtAuthGuard)
  startKyc(@CurrentUser() user: any) {
    return this.kycService.startKyc(user.sub);
  }

  @Get("status")
  @UseGuards(JwtAuthGuard)
  getStatus(@CurrentUser() user: any) {
    return this.kycService.getKycStatus(user.sub);
  }

  @SkipThrottle()
  @Post("webhook")
  async webhook(@Req() req: RawBodyRequest) {
    const signature = req.headers["x-app-token"] as string;
    const body = req.rawBody || Buffer.from(JSON.stringify(req.body));
    return this.kycService.handleWebhook(body, signature);
  }
}
