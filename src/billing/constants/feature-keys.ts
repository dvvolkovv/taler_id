export const FEATURE_KEYS = {
  VOICE_ASSISTANT: 'voice_assistant',
  WEB_SEARCH: 'web_search',
  AI_TWIN: 'ai_twin',
  OUTBOUND_CALL: 'outbound_call',
  WHISPER_TRANSCRIBE: 'whisper_transcribe',
  MEETING_SUMMARY: 'meeting_summary',
} as const;

export type FeatureKey = (typeof FEATURE_KEYS)[keyof typeof FEATURE_KEYS];

export const ALL_FEATURE_KEYS: FeatureKey[] = Object.values(FEATURE_KEYS);
