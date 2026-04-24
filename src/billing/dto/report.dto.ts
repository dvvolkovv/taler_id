import { IsIn, IsNumber, IsString, IsUUID, Max, Min } from 'class-validator';

// Realistic upper bound: 24 hours in minutes. Prevents buggy agents from
// reporting absurd values that could drain a wallet in one call.
const MAX_UNITS_PER_REPORT = 24 * 60;

export class ReportUsageDto {
  @IsUUID('4')
  sessionId!: string;

  @IsNumber()
  @Min(0)
  @Max(MAX_UNITS_PER_REPORT)
  units!: number;

  @IsIn(['ai-twin-agent', 'outbound-call-agent', 'client'])
  reporter!: string;
}

export class HeartbeatDto {
  @IsUUID('4')
  sessionId!: string;
}
