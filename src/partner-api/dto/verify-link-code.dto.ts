import { IsString, Matches } from 'class-validator';

export class VerifyLinkCodeDto {
  @IsString({ message: 'invalid_code' })
  @Matches(/^\d{6}$/, { message: 'invalid_code' })
  code!: string;
}
