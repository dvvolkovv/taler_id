import { IsOptional, IsString, MaxLength } from 'class-validator';

export class RevokeDeviceKeyDto {
  @IsOptional()
  @IsString()
  @MaxLength(500)
  reason?: string;
}
