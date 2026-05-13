import { IsIn, IsNotEmpty, IsOptional, IsString, IsUrl } from 'class-validator';

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
}
