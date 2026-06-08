export interface ManaxSpeakerEmbedding {
  speakerId: string;
  vector: number[];
  coverageFraction?: number;
}

export interface ManaxJobResult {
  durationSec?: number;
  speakerEmbeddings?: ManaxSpeakerEmbedding[];
  quality?: { speechCoverage?: number };
}

export interface ManaxJobResponse {
  jobId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  attempt?: number;
  error?: string;
  result?: ManaxJobResult;
}

export interface OwnerVerifyResult {
  isOwner: boolean | null;     // null = fail-open (could not decide)
  similarity?: number;
  audioSec?: number;
  manaxLatencyMs?: number;
}

export interface OwnerEnrollResult {
  ok: boolean;
  speakerId?: string;
  embedding?: number[];
  embeddingDim?: number;
  audioSec?: number;
  error?: 'audio_too_short' | 'no_speech_detected' | 'manax_unavailable' | 'feature_disabled';
}
