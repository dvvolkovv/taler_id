import {
  IsString,
  IsOptional,
  IsEmail,
  IsUrl,
  MaxLength,
} from 'class-validator';
import { Transform } from 'class-transformer';

const normalizeEmail = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim().toLowerCase() : value;

export class CreateTenantDto {
  @IsString()
  @MaxLength(200)
  name: string;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  description?: string;

  @IsOptional()
  @IsString()
  legalAddress?: string;

  @IsOptional()
  @IsUrl()
  website?: string;

  @IsOptional()
  @IsEmail()
  @Transform(normalizeEmail)
  email?: string;

  @IsOptional()
  @IsString()
  phone?: string;
}

export class UpdateTenantDto {
  @IsOptional()
  @IsString()
  @MaxLength(200)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  description?: string;

  @IsOptional()
  @IsString()
  legalAddress?: string;

  @IsOptional()
  @IsUrl()
  website?: string;

  @IsOptional()
  @IsEmail()
  @Transform(normalizeEmail)
  email?: string;

  @IsOptional()
  @IsString()
  phone?: string;
}

export class InviteMemberDto {
  @IsEmail()
  @Transform(normalizeEmail)
  email: string;

  @IsString()
  role: string;
}

export class ChangeRoleDto {
  @IsString()
  role: string;
}
