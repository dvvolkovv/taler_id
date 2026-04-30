import {
  IsString,
  IsOptional,
  IsBoolean,
  IsNumber,
  IsIn,
} from 'class-validator';

export class UpdateGroupDto {
  @IsString()
  @IsOptional()
  name?: string;

  @IsString()
  @IsOptional()
  avatarUrl?: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsBoolean()
  @IsOptional()
  slowMode?: boolean;

  @IsBoolean()
  @IsOptional()
  topicsEnabled?: boolean;

  @IsNumber()
  @IsOptional()
  autoDeleteDays?: number | null;

  @IsString()
  @IsOptional()
  invitePolicy?: string;
}
