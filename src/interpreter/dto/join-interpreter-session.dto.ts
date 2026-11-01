import { IsString, Matches, MaxLength } from 'class-validator';

export class JoinInterpreterSessionDto {
  /**
   * As scanned or typed: the service normalizes case, spaces and dashes.
   * Every check names the same code, or class-validator's English sentence
   * ("code must be a string") would ride along in `message`.
   */
  @IsString({ message: 'code_not_found' })
  @MaxLength(32, { message: 'code_not_found' })
  code!: string;

  /** The guest's language; whether the agent speaks it is the service's check. */
  @IsString({ message: 'unsupported_language' })
  @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
  lang!: string;
}
