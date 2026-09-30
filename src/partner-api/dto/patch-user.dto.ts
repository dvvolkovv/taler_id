import { IsOptional, IsString, MaxLength } from 'class-validator';

export class PatchUserDto {
  // null — стереть имя; @IsOptional пропускает null мимо остальных проверок.
  @IsOptional()
  @IsString({ message: 'invalid_first_name' })
  @MaxLength(100, { message: 'invalid_first_name' })
  firstName?: string | null;

  @IsOptional()
  @IsString({ message: 'invalid_last_name' })
  @MaxLength(100, { message: 'invalid_last_name' })
  lastName?: string | null;
}
