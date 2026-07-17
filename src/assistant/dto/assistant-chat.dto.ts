import {
  ArrayMaxSize,
  IsArray,
  IsIn,
  IsObject,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class AssistantActionDto {
  @IsIn([
    'message_sent',
    'event_created',
    'analyst_reply',
    'call_made',
    'contact_added',
    'channel_post',
  ])
  type: string;

  @IsString()
  entityId: string;

  @IsOptional()
  @IsString()
  conversationId?: string;

  @IsString()
  title: string;
}

export class AssistantEntryDto {
  @IsIn(['user', 'assistant'])
  role: 'user' | 'assistant';

  @IsIn(['voice', 'text'])
  source: 'voice' | 'text';

  @IsString()
  @MaxLength(8000)
  text: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => AssistantActionDto)
  action?: AssistantActionDto;
}

export class LogEntriesDto {
  @IsArray()
  @ArrayMaxSize(100)
  @ValidateNested({ each: true })
  @Type(() => AssistantEntryDto)
  entries: AssistantEntryDto[];
}

export class ToolResultDto {
  @IsString()
  tool_call_id: string;

  @IsString()
  output: string;
}

export class TurnDto {
  @IsOptional()
  @IsString()
  @MaxLength(8000)
  text?: string;

  @IsString()
  @MaxLength(32000)
  instructions: string;

  @IsArray()
  tools: any[];

  // Follow-up call of the same turn: echo of the assistant tool_calls
  // message returned by the previous /turn response + tool outputs.
  @IsOptional()
  @IsObject()
  pendingAssistantMessage?: any;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ToolResultDto)
  toolResults?: ToolResultDto[];
}
