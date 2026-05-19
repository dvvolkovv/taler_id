export interface AgentToolCall {
  name: string;
  input: Record<string, unknown>;
  output: string;
}

export interface RunAgentResponseDto {
  finalText: string;
  toolCalls: AgentToolCall[]; // empty in Phase 0 — claude CLI runs tools internally
  aborted: boolean;
  conversationId?: string;
  durationMs?: number;
}
