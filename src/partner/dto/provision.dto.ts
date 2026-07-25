import {
  ArrayNotEmpty,
  IsArray,
  IsEmail,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
} from 'class-validator';

export class ProvisionDto {
  // Phone in (near-)E.164 form. Linkeon verifies it by SMS and sends it with a
  // leading '+'. We accept common separators and canonicalize server-side.
  @IsString()
  @Matches(/^\+?[0-9][0-9\s\-().]{5,17}$/, {
    message: 'phone must be a valid phone number (E.164, e.g. +79656445804)',
  })
  phone!: string;

  @IsOptional()
  @IsEmail({}, { message: 'email must be a valid email address' })
  email?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;

  // Requested MCP scopes (this slice: ['mcp:calendar']). Every entry must be
  // within the linkeon-partner client's allowedScopes or the request is 400.
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  scopes!: string[];
}
