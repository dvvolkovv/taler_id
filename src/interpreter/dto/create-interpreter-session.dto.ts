import { IsString, Matches } from 'class-validator';

export class CreateInterpreterSessionDto {
  /** The host's language; whether the agent speaks it is the service's check. */
  @IsString({ message: 'unsupported_language' })
  @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
  lang!: string;
}
