import { IsString, Matches, IsInt, IsPositive } from 'class-validator';

export class RegisterDeviceKeyDto {
  @IsString()
  @Matches(/^[0-9a-f]{64}$/i, { message: 'devicePk must be 64 hex chars' })
  devicePk: string;

  @IsString()
  algorithm: string; // must equal "X25519" — enforced by service

  @IsInt()
  @IsPositive()
  validUntilEpochMs: number;

  @IsString()
  @Matches(/^[0-9a-f]{128}$/i, { message: 'signature must be 128 hex chars (Ed25519)' })
  signature: string;

  @IsString()
  certificate: string; // the full canonical JSON that was signed
}
