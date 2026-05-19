import { IsString, IsOptional } from 'class-validator';

export class RunAgentRequestDto {
  @IsString()
  goal!: string;

  @IsOptional()
  @IsString()
  conversationId?: string;
}
