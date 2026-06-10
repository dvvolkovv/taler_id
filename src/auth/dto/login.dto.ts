import { IsString, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
  @IsString()
  @IsOptional()
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
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
