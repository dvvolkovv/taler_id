import { IsString, IsEmail, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';

const normalizeEmail = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim().toLowerCase() : value;

export class ForgotPasswordDto {
  @IsEmail()
  @Transform(normalizeEmail)
  email: string;
}

export class VerifyForgotCodeDto {
  @IsEmail()
  @Transform(normalizeEmail)
  email: string;

  @IsString()
  code: string;
}

export class ResetPasswordDto {
  @IsString()
  resetToken: string;

  @IsString()
  @MinLength(8)
  newPassword: string;
}
