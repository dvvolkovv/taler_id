import { IsIn, IsNotEmpty, IsOptional, IsString, IsUrl } from 'class-validator';

export class OAuthAuthorizeQueryDto {
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

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  code_challenge?: string;

  @IsOptional()
  @IsString()
  @IsIn(['S256'])
  code_challenge_method?: 'S256';

  @IsOptional()
  @IsString()
  nonce?: string;
}
