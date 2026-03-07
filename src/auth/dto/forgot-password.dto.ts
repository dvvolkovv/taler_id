import { IsString, IsEmail, MinLength } from 'class-validator';

export class ForgotPasswordDto {
  @IsEmail()
  email: string;
}

export class VerifyForgotCodeDto {
  @IsEmail()
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
