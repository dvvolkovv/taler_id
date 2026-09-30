import { IsEmail, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { EXTERNAL_ID_RE } from '../external-id.util';

export class ProvisionUserDto {
  @IsString()
  @Matches(EXTERNAL_ID_RE, { message: 'invalid_external_id' })
  externalId!: string;

  /** Партнёр обязан проверить её сам до вызова (у nadi — вход по коду из письма). */
  @IsEmail({}, { message: 'invalid_email' })
  @MaxLength(254)
  email!: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  lastName?: string;

  /** Язык человека у партнёра. Профиль TalerID знает ru и en, остальное станет en. */
  @IsOptional()
  @IsString()
  @MaxLength(10)
  locale?: string;
}
