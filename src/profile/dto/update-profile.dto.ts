import { IsString, IsOptional, IsDateString, IsIn, Matches, IsBoolean, IsInt, Min, Max, MaxLength } from 'class-validator';

export class UpdateProfileDto {
  @IsString()
  @IsOptional()
  firstName?: string;

  @IsString()
  @IsOptional()
  lastName?: string;

  @IsString()
  @IsOptional()
  middleName?: string;

  @IsDateString()
  @IsOptional()
  dateOfBirth?: string;

  @IsString()
  @IsOptional()
  country?: string;

  @IsString()
  @IsOptional()
  postalCode?: string;

  @IsString()
  @IsOptional()
  preferredCurrency?: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsIn(['en', 'ru', 'de'])
  @IsOptional()
  language?: string;

  @IsString()
  @IsOptional()
  fcmToken?: string;

  @IsString()
  @IsOptional()
  voipToken?: string;

  @IsString()
  @IsOptional()
  status?: string;

  @IsBoolean()
  @IsOptional()
  aiTwinEnabled?: boolean;

  @IsInt()
  @Min(15)
  @Max(60)
  @IsOptional()
  aiTwinTimeoutSeconds?: number;

  @IsString()
  @MaxLength(2000)
  @IsOptional()
  aiTwinPrompt?: string;

  @IsString()
  @MaxLength(100)
  @IsOptional()
  aiTwinVoiceId?: string;
}

export class LinkWalletDto {
  // Substrate SS58 address (e.g. 5HueCGU8rMtraL...) — 47-48 base58 chars
  @IsString()
  @Matches(/^[1-9A-HJ-NP-Za-km-z]{46,50}$/, { message: 'Invalid Substrate address (SS58 format required, e.g. 5HueCGU...)' })
  walletAddress: string;
}
