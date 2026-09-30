import { IsOptional, IsString, MaxLength } from 'class-validator';

export class PatchUserDto {
  @IsOptional()
  @IsString({ message: 'invalid_first_name' })
  @MaxLength(100, { message: 'invalid_first_name' })
  firstName?: string;

  @IsOptional()
  @IsString({ message: 'invalid_last_name' })
  @MaxLength(100, { message: 'invalid_last_name' })
  lastName?: string;
}
