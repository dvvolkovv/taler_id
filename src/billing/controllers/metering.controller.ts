import { Body, Controller, Post, UseFilters, UseGuards } from '@nestjs/common';
import { MeteringService } from '../services/metering.service';
import { MeteringSecretGuard } from '../guards/metering-secret.guard';
import { ReportUsageDto, HeartbeatDto } from '../dto/report.dto';
import { BillingExceptionFilter } from '../filters/billing-exception.filter';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';

@Controller('metering')
@UseFilters(BillingExceptionFilter)
export class MeteringController {
  constructor(private readonly metering: MeteringService) {}

  // Agents (ai-twin-agent, outbound-call-agent) call this with shared-secret header.
  @Post('report')
  @UseGuards(MeteringSecretGuard)
  async report(@Body() body: ReportUsageDto) {
    await this.metering.reportUsage(body.sessionId, body.units, body.reporter);
    return { ok: true };
  }

  // Mobile clients call this for liveness — JWT-authenticated.
  @Post('heartbeat')
  @UseGuards(JwtAuthGuard)
  async heartbeat(@Body() body: HeartbeatDto) {
    await this.metering.heartbeat(body.sessionId);
    return { ok: true };
  }
}
