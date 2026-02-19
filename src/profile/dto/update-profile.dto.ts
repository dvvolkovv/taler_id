import { IsString, IsOptional, IsDateString, IsIn } from 'class-validator';

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

  @IsIn(['en', 'ru', 'de'])
  @IsOptional()
  language?: string;
}

export class LinkWalletDto {
  @IsString()
  walletAddress: string;
}
