import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import FormData from 'form-data';
import { cosine } from './cosine';
import { ManaxJobResponse, ManaxSpeakerEmbedding, OwnerEnrollResult, OwnerVerifyResult } from './voice-gate.types';

export interface EmbedResult {
  embedding: number[] | null;
  speakerId?: string;
  audioSec?: number;
  manaxLatencyMs?: number;
  error?: 'manax_unavailable' | 'no_speech_detected';
}

@Injectable()
export class VoiceGateService {
  private readonly log = new Logger('VoiceGateService');
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly threshold: number;
  private readonly enabled: boolean;
  private readonly verifyTimeoutMs = 2000;   // per 1-sec window — short
  private readonly enrollTimeoutMs = 30_000; // 15-30 sec audio + model load — long

  constructor(private readonly config: ConfigService) {
    this.baseUrl = config.get<string>('MANAX_BASE_URL', 'http://127.0.0.1:8791');
    this.apiKey = config.get<string>('MANAX_API_KEY', '');
    this.threshold = parseFloat(config.get<string>('OWNER_VOICE_THRESHOLD', '0.5'));
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
    if (emb.error === 'manax_unavailable') {
      return { ok: false, error: 'manax_unavailable' };
    }
    if (emb.embedding === null) {
      return { ok: false, error: 'no_speech_detected' };
    }
    return {
      ok: true,
      speakerId: emb.speakerId,
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
      return { isOwner: null, audioSec: emb.audioSec, manaxLatencyMs: emb.manaxLatencyMs };
    }
    const sim = cosine(emb.embedding, ownerEmbedding);
    return {
      isOwner: sim >= this.threshold,
      similarity: sim,
      audioSec: emb.audioSec,
      manaxLatencyMs: emb.manaxLatencyMs,
    };
  }

  async embedAudio(audio: Buffer, timeoutMs = this.verifyTimeoutMs): Promise<EmbedResult> {
    // Manax sync endpoint /api/v1/audio/upload-all-in-one hangs in practice;
    // submit to async /jobs/upload-all-in-one and poll status until terminal.
    const form = new FormData();
    form.append('audioFile', audio, { filename: 'audio.wav', contentType: 'audio/wav' });
    form.append('requestJson', JSON.stringify({ mode: 'enroll', language: 'ru' }));

    const start = Date.now();
    const headers = { ...form.getHeaders(), 'X-Api-Key': this.apiKey };
    try {
      const submitResp = await axios.post<{ jobId: string }>(
        `${this.baseUrl}/api/v1/jobs/upload-all-in-one`,
        form,
        { headers, timeout: 5000, maxContentLength: 5_000_000 },
      );
      const jobId = submitResp.data.jobId;
      if (!jobId) {
        return { embedding: null, error: 'manax_unavailable', manaxLatencyMs: Date.now() - start };
      }
      // Poll with backoff. Status GETs count against Manax's request rate
      // budget; spamming them at 250ms eats the quota in a few seconds.
      const deadline = start + timeoutMs;
      let pollIntervalMs = 500;
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, pollIntervalMs));
        pollIntervalMs = Math.min(pollIntervalMs * 1.5, 2000);
        const statusResp = await axios.get<{ status: string }>(
          `${this.baseUrl}/api/v1/jobs/${jobId}/status`,
          { headers: { 'X-Api-Key': this.apiKey }, timeout: 5000 },
        );
        const s = statusResp.data.status;
        if (s === 'completed' || s === 'failed') {
          const resultResp = await axios.get<ManaxJobResponse>(
            `${this.baseUrl}/api/v1/jobs/${jobId}`,
            { headers: { 'X-Api-Key': this.apiKey }, timeout: 5000 },
          );
          const latency = Date.now() - start;
          if (s === 'failed') {
            this.log.warn(`Manax job ${jobId} failed: ${resultResp.data.error ?? '?'}`);
            return { embedding: null, error: 'manax_unavailable', manaxLatencyMs: latency };
          }
          const embs = resultResp.data.result?.speakerEmbeddings ?? [];
          if (embs.length === 0) {
            return { embedding: null, error: 'no_speech_detected', manaxLatencyMs: latency };
          }
          const best = this.pickBestEmbedding(embs);
          return {
            embedding: best.vector,
            speakerId: best.speakerId,
            audioSec: resultResp.data.result?.durationSec,
            manaxLatencyMs: latency,
          };
        }
      }
      this.log.warn(`Manax job ${jobId} timed out after ${timeoutMs}ms`);
      return { embedding: null, error: 'manax_unavailable', manaxLatencyMs: Date.now() - start };
    } catch (e: any) {
      this.log.warn(`Manax unavailable, fail-open: ${e.message}`);
      return { embedding: null, error: 'manax_unavailable', manaxLatencyMs: Date.now() - start };
    }
  }

  private pickBestEmbedding(embs: ManaxSpeakerEmbedding[]): ManaxSpeakerEmbedding {
    return embs.reduce((best, cur) =>
      (cur.coverageFraction ?? 0) > (best.coverageFraction ?? 0) ? cur : best,
    );
  }
}
