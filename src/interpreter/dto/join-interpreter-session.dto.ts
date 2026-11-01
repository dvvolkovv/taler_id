import { IsString, Matches, MaxLength } from 'class-validator';

export class JoinInterpreterSessionDto {
  /** As scanned or typed: the service normalizes case, spaces and dashes. */
  @IsString()
  @MaxLength(32)
  code!: string;

  /** The guest's language; whether the agent speaks it is the service's check. */
  @IsString()
  @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
  lang!: string;
}
