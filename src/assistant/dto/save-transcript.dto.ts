import { IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { IsString } from 'class-validator';

class TranscriptMessage {
  @IsString()
  role: string;

  @IsString()
  text: string;
}

export class SaveTranscriptDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TranscriptMessage)
  messages: TranscriptMessage[];
}
