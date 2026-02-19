import { IsString, IsOptional } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsOptional()
  email?: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsString()
  password: string;
}

export class Login2faDto {
  @IsString()
  challengeToken: string;

  @IsString()
  code: string;
}

export class RefreshDto {
  @IsString()
  refreshToken: string;
}
