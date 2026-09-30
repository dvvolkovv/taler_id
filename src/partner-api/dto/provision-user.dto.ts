import { IsEmail, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { EXTERNAL_ID_RE } from '../external-id.util';

export class ProvisionUserDto {
  @IsString({ message: 'invalid_external_id' })
  @Matches(EXTERNAL_ID_RE, { message: 'invalid_external_id' })
  externalId!: string;

  /** Партнёр обязан проверить её сам до вызова (у nadi — вход по коду из письма). */
  @IsEmail({}, { message: 'invalid_email' })
  @MaxLength(254, { message: 'invalid_email' })
  email!: string;

  @IsOptional()
  @IsString({ message: 'invalid_first_name' })
  @MaxLength(100, { message: 'invalid_first_name' })
  firstName?: string;

  @IsOptional()
  @IsString({ message: 'invalid_last_name' })
  @MaxLength(100, { message: 'invalid_last_name' })
  lastName?: string;

  /** Письма и уведомления TalerID существуют только на ru и en; всё остальное (uk, de, …) становится en. */
  @IsOptional()
  @IsString({ message: 'invalid_locale' })
  @MaxLength(10, { message: 'invalid_locale' })
  locale?: string;
}
