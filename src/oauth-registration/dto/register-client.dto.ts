import { ArrayMaxSize, ArrayMinSize, IsArray, IsOptional, IsString, IsUrl, Length, Matches } from 'class-validator';

export class RegisterClientDto {
  @IsString()
  @Length(1, 128)
  client_name!: string;

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  @Matches(/^(https?:\/\/|talerid:\/\/)/i, {
    each: true,
    message: 'redirect_uri must use https://, http:// (localhost only), or talerid:// scheme',
  })
  redirect_uris!: string[];

  @IsOptional()
  @IsUrl({ require_protocol: true })
  logo_uri?: string;

  @IsOptional()
  @IsString()
  scope?: string;
}
