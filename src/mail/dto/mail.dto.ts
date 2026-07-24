import { IsArray, IsEmail, IsOptional, IsString, MaxLength, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateMailAccountDto {
  @IsString() @MaxLength(64)
  localpart!: string;
}

export class CreateAppPasswordDto {
  @IsString() @MaxLength(64)
  label!: string;
}

export class AttachmentDto {
  @IsString() @MaxLength(255)
  filename!: string;

  @IsString()
  contentBase64!: string;
}

export class SendMessageDto {
  @IsEmail()
  to!: string;

  @IsString() @MaxLength(255)
  subject!: string;

  @IsString() @MaxLength(100_000)
  text!: string;

  @IsOptional() @IsString()
  inReplyTo?: string;

  @IsOptional() @IsArray() @ValidateNested({ each: true }) @Type(() => AttachmentDto)
  attachments?: AttachmentDto[];
}
