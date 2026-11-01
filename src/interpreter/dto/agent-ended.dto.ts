import { IsIn } from 'class-validator';

/** Why the agent stopped by itself (livekit-agent/interpreter.js). */
export const AGENT_END_REASONS = [
  'partner_left',
  'agent_lost',
  'translation_failed',
] as const;

export type AgentEndReason = (typeof AGENT_END_REASONS)[number];

export class AgentEndedDto {
  @IsIn(AGENT_END_REASONS)
  reason!: AgentEndReason;
}
