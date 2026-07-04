import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { randomBytes } from 'crypto';
import FormData from 'form-data';
import { cosine } from './cosine';
import { OwnerEnrollResult, OwnerVerifyResult } from './voice-gate.types';

export interface EmbedResult {
  embedding: number[] | null;
  audioSec?: number;
  embedLatencyMs?: number;
  error?: 'embed_unavailable' | 'no_speech_detected';
}

/**
 * Returns 192-dim ECAPA embedding for arbitrary audio by calling the local
 * voice-embed-service sidecar (PM2 process at 127.0.0.1:18082 on DEV). The
 * sidecar wraps speechbrain/spkrec-ecapa-voxceleb and is fast: tens of ms
 * inference for 1-sec windows, ~4 sec for 98-sec audio.
 *
 * Fail-open posture: any HTTP error or empty embedding returns
 * isOwner=null from verify(), so the assistant session keeps working
 * without gating rather than breaking when the sidecar is down.
 */
@Injectable()
export class VoiceGateService {
  private readonly log = new Logger('VoiceGateService');
  private readonly baseUrl: string;
  private readonly threshold: number;
  private readonly enabled: boolean;
  private readonly verifyTimeoutMs = 2000;
  private readonly enrollTimeoutMs = 15_000;

  constructor(private readonly config: ConfigService) {
    this.baseUrl = config.get<string>('VOICE_EMBED_URL', 'http://127.0.0.1:18082');
    this.threshold = parseFloat(config.get<string>('OWNER_VOICE_THRESHOLD', '0.3'));
    this.enabled = config.get<string>('OWNER_VOICE_ENABLED', 'true') !== 'false';
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  async enroll(audio: Buffer): Promise<OwnerEnrollResult> {
    if (!this.enabled) {
      return { ok: false, error: 'feature_disabled' };
    }
    const emb = await this.embedAudio(audio, this.enrollTimeoutMs);
    if (emb.error === 'embed_unavailable') {
      return { ok: false, error: 'manax_unavailable' };
    }
    if (emb.embedding === null) {
      return { ok: false, error: 'no_speech_detected' };
    }
    return {
      ok: true,
      speakerId: `spk_${randomBytes(10).toString('hex')}`,
      embedding: emb.embedding,
      embeddingDim: emb.embedding.length,
      audioSec: emb.audioSec,
    };
  }

  async verify(audio: Buffer, ownerEmbedding: number[]): Promise<OwnerVerifyResult> {
    if (!this.enabled || !ownerEmbedding || ownerEmbedding.length === 0) {
      return { isOwner: null };
    }
    const emb = await this.embedAudio(audio, this.verifyTimeoutMs);
    if (emb.embedding === null) {
      return { isOwner: null, audioSec: emb.audioSec, manaxLatencyMs: emb.embedLatencyMs };
    }
    const sim = cosine(emb.embedding, ownerEmbedding);
    return {
      isOwner: sim >= this.threshold,
      similarity: sim,
      audioSec: emb.audioSec,
      manaxLatencyMs: emb.embedLatencyMs,
    };
  }

  async embedAudio(audio: Buffer, timeoutMs = this.verifyTimeoutMs): Promise<EmbedResult> {
    const form = new FormData();
    form.append('audio', audio, { filename: 'audio.wav', contentType: 'audio/wav' });
    const start = Date.now();
    try {
      const resp = await axios.post<{ vector: number[]; dim: number; audioSec: number }>(
        `${this.baseUrl}/embed`,
        form,
        {
          headers: form.getHeaders(),
          timeout: timeoutMs,
          maxContentLength: 5_000_000,
        },
      );
      const latency = Date.now() - start;
      if (!resp.data?.vector || resp.data.vector.length === 0) {
        return { embedding: null, error: 'no_speech_detected', embedLatencyMs: latency };
      }
      return {
        embedding: resp.data.vector,
        audioSec: resp.data.audioSec,
        embedLatencyMs: latency,
      };
    } catch (e: any) {
      // HTTP 422 from sidecar means audio is too short for ECAPA — treat
      // as no_speech_detected rather than embed_unavailable.
      if (e.response?.status === 422) {
        return { embedding: null, error: 'no_speech_detected', embedLatencyMs: Date.now() - start };
      }
      this.log.warn(`voice-embed-service unavailable, fail-open: ${e.message}`);
      return { embedding: null, error: 'embed_unavailable', embedLatencyMs: Date.now() - start };
    }
  }
}
