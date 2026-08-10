import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Readable } from 'stream';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';
import { GatingService } from '../billing/services/gating.service';
import { LedgerService } from '../billing/services/ledger.service';
import { PricingService } from '../billing/services/pricing.service';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';

/** Whisper принимает до 25 МБ; голосовое столько не весит, но проверим. */
const MAX_AUDIO_BYTES = 25 * 1024 * 1024;

/**
 * Если клиент не прислал длительность, считаем её по размеру файла.
 * Запись идёт в AAC ~32 кбит/с, то есть примерно 4 КБ в секунду. Оценка нужна
 * только для тарификации; при заниженной оценке мы недосписали бы, поэтому
 * округление всегда вверх.
 */
const BYTES_PER_SECOND_ESTIMATE = 4000;

@Injectable()
export class VoiceTranscribeService {
  private readonly logger = new Logger(VoiceTranscribeService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: FileStorageService,
    private readonly gating: GatingService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
  ) {}

  /**
   * Расшифровывает голосовое сообщение и запоминает текст в самом сообщении.
   *
   * Повторный вызов возвращает уже готовый текст и **не списывает второй раз**:
   * кнопка в интерфейсе одна на всех участников беседы, и без этой проверки
   * каждый нажавший платил бы за одно и то же.
   */
  async transcribeMessage(messageId: string, userId: string) {
    const message = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: {
        id: true,
        conversationId: true,
        fileType: true,
        s3Key: true,
        fileSize: true,
        metadata: true,
        deletedAt: true,
      },
    });
    if (!message || message.deletedAt) throw new NotFoundException('Message not found');

    // Право читать сообщение = право его расшифровать.
    const participant = await this.prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: {
          conversationId: message.conversationId,
          userId,
        },
      },
    });
    if (!participant) throw new ForbiddenException('Not a participant');

    const meta = (message.metadata ?? {}) as Record<string, any>;
    if (typeof meta.transcript === 'string' && meta.transcript.length > 0) {
      return { transcript: meta.transcript, cached: true };
    }

    if (message.fileType !== 'audio' || !message.s3Key) {
      throw new BadRequestException('Message has no voice recording');
    }
    if ((message.fileSize ?? 0) > MAX_AUDIO_BYTES) {
      throw new BadRequestException('Recording is too large to transcribe');
    }

    const seconds = this.estimateSeconds(meta, message.fileSize);
    const minutes = seconds / 60;

    const session = await this.gating.startSession(
      userId,
      FEATURE_KEYS.WHISPER_TRANSCRIBE,
    );
    const cost = await this.pricing.calculatePlanckCost(
      FEATURE_KEYS.WHISPER_TRANSCRIBE,
      minutes,
    );

    let tx: { id: string };
    try {
      tx = await this.ledger.debit(userId, cost, 'SPEND', {
        featureKey: FEATURE_KEYS.WHISPER_TRANSCRIBE,
        sessionId: session.id,
        metadata: { messageId, durationMin: minutes },
      });
    } catch (err) {
      await this.gating.endSession(session.id, 'failed').catch(() => undefined);
      throw err;
    }

    try {
      const audio = await this.readObject(message.s3Key);
      const transcript = await this.callWhisper(audio);
      await this.gating.endSession(session.id, 'completed');

      // Пустой ответ Whisper — это тишина в записи, а не ошибка. Запоминаем
      // прочерк, чтобы кнопка не предлагала расшифровать снова и снова.
      const finalText = transcript.trim();
      const updated = await this.prisma.message.update({
        where: { id: messageId },
        data: { metadata: { ...meta, transcript: finalText } },
        select: { metadata: true },
      });
      return {
        transcript: (updated.metadata as any).transcript as string,
        cached: false,
      };
    } catch (err) {
      // За неслучившуюся расшифровку деньги возвращаем.
      await this.ledger
        .refund(tx.id, `whisper error: ${String(err).slice(0, 200)}`)
        .catch(() => undefined);
      await this.gating.endSession(session.id, 'failed').catch(() => undefined);
      this.logger.warn(`transcribe failed for message ${messageId}: ${err}`);
      throw new BadRequestException('Transcription failed');
    }
  }

  /** Длительность из метаданных, иначе оценка по размеру файла. */
  private estimateSeconds(meta: Record<string, any>, fileSize: number | null): number {
    const ms = meta?.durationMs;
    if (typeof ms === 'number' && Number.isFinite(ms) && ms > 0) {
      return ms / 1000;
    }
    if (fileSize && fileSize > 0) {
      return Math.ceil(fileSize / BYTES_PER_SECOND_ESTIMATE);
    }
    return 1; // минимальная единица тарификации
  }

  private async readObject(key: string): Promise<Buffer> {
    const { stream } = await this.storage.getObject(key);
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of stream as Readable) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_AUDIO_BYTES) throw new Error('recording too large');
      chunks.push(buf);
    }
    return Buffer.concat(chunks);
  }

  private async callWhisper(audio: Buffer): Promise<string> {
    const key = process.env.OPENAI_API_KEY;
    if (!key) throw new Error('OPENAI_API_KEY is not set');

    const form = new FormData();
    form.append('file', new Blob([new Uint8Array(audio)], { type: 'audio/mp4' }), 'voice.m4a');
    form.append('model', 'whisper-1');
    // Голосовое короткое — разбивка по сегментам и тайм-коды тут ни к чему.
    form.append('response_format', 'json');

    const res = await fetch('https://api.openai.com/v1/audio/transcriptions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}` },
      body: form,
    });
    if (!res.ok) {
      throw new Error(`Whisper ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    const data = (await res.json()) as any;
    return typeof data.text === 'string' ? data.text : '';
  }
}
