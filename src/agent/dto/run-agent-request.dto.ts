import { IsString, IsOptional, IsNotEmpty, MaxLength } from 'class-validator';

export class RunAgentRequestDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(4000)
  goal!: string;

  @IsOptional()
  @IsString()
  conversationId?: string;
}
