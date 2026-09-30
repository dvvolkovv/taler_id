import { IsString, Matches } from 'class-validator';

export class VerifyLinkCodeDto {
  @IsString()
  @Matches(/^\d{6}$/, { message: 'invalid_code' })
  code!: string;
}
