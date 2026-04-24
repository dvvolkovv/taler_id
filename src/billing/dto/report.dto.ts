import { IsNumber, IsString, Min } from 'class-validator';

export class ReportUsageDto {
  @IsString()
  sessionId!: string;

  @IsNumber()
  @Min(0)
  units!: number;

  @IsString()
  reporter!: string;
}

export class HeartbeatDto {
  @IsString()
  sessionId!: string;
}
