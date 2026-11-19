import {
  ArrayMaxSize,
  IsArray,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  MaxLength,
} from 'class-validator';

export class OAuthApproveDto {
  @IsString()
  @IsNotEmpty()
  client_id!: string;

  @IsString()
  @IsNotEmpty()
  @IsUrl({ require_tld: false, protocols: ['http', 'https'], require_protocol: true })
  redirect_uri!: string;

  @IsString()
  @IsNotEmpty()
  scope!: string;

  @IsString()
  @IsIn(['code'])
  response_type!: 'code';

  @IsString()
  @IsIn(['S256'])
  code_challenge_method!: 'S256';

  @IsString()
  @IsNotEmpty()
  code_challenge!: string;

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  nonce?: string;

  /** 'person' или id компании (scope companies). */
  @IsOptional()
  @IsString()
  @MaxLength(100)
  act_as?: string;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(100)
  @IsString({ each: true })
  @MaxLength(100, { each: true })
  company_ids?: string[];
}
