import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { VoiceTranscribeService } from './voice-transcribe.service';

describe('VoiceTranscribeService', () => {
  let service: VoiceTranscribeService;
  let prisma: any;
  let storage: any;
  let gating: any;
  let ledger: any;
  let pricing: any;
  let fetchMock: jest.Mock;

  const voiceMessage = (over: any = {}) => ({
    id: 'm-1',
    conversationId: 'conv-1',
    fileType: 'audio',
    s3Key: 'voice/m-1.m4a',
    fileSize: 40000,
    metadata: {},
    deletedAt: null,
    ...over,
  });

  beforeEach(() => {
    prisma = {
      message: {
        findUnique: jest.fn().mockResolvedValue(voiceMessage()),
        update: jest.fn().mockImplementation(({ data }: any) => ({ metadata: data.metadata })),
      },
      conversationParticipant: { findUnique: jest.fn().mockResolvedValue({ role: 'MEMBER' }) },
    };
    storage = {
      getObject: jest.fn().mockResolvedValue({
        stream: (async function* () {
          yield Buffer.from('audio-bytes');
        })(),
      }),
    };
    gating = {
      startSession: jest.fn().mockResolvedValue({ id: 'sess-1' }),
      endSession: jest.fn().mockResolvedValue(undefined),
    };
    ledger = {
      debit: jest.fn().mockResolvedValue({ id: 'tx-1' }),
      refund: jest.fn().mockResolvedValue(undefined),
    };
    pricing = { calculatePlanckCost: jest.fn().mockResolvedValue(100n) };

    service = new VoiceTranscribeService(prisma, storage, gating, ledger, pricing);
    process.env.OPENAI_API_KEY = 'test-key';
    fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ text: 'привет из голосового' }),
    });
    (global as any).fetch = fetchMock;
  });

  it('transcribes and stores the text on the message', async () => {
    const out = await service.transcribeMessage('m-1', 'u-1');

    expect(out.transcript).toBe('привет из голосового');
    expect(prisma.message.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { metadata: { transcript: 'привет из голосового' } },
      }),
    );
  });

  it('returns the stored text without paying twice', async () => {
    // Кнопка одна на всех участников: без этой проверки каждый нажавший
    // платил бы за одну и ту же расшифровку.
    prisma.message.findUnique.mockResolvedValue(
      voiceMessage({ metadata: { transcript: 'уже расшифровано' } }),
    );

    const out = await service.transcribeMessage('m-1', 'u-1');

    expect(out).toEqual({ transcript: 'уже расшифровано', cached: true });
    expect(ledger.debit).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a non-participant', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue(null);

    await expect(service.transcribeMessage('m-1', 'u-stranger'))
      .rejects.toThrow(ForbiddenException);
    expect(ledger.debit).not.toHaveBeenCalled();
  });

  it('refuses a message that is not a voice recording', async () => {
    prisma.message.findUnique.mockResolvedValue(
      voiceMessage({ fileType: 'image', s3Key: 'img.png' }),
    );

    await expect(service.transcribeMessage('m-1', 'u-1'))
      .rejects.toThrow(BadRequestException);
  });

  it('refuses a deleted message', async () => {
    prisma.message.findUnique.mockResolvedValue(voiceMessage({ deletedAt: new Date() }));

    await expect(service.transcribeMessage('m-1', 'u-1'))
      .rejects.toThrow(NotFoundException);
  });

  it('bills by the duration the client reported', async () => {
    prisma.message.findUnique.mockResolvedValue(
      voiceMessage({ metadata: { durationMs: 30_000 } }),
    );

    await service.transcribeMessage('m-1', 'u-1');

    expect(pricing.calculatePlanckCost).toHaveBeenCalledWith('whisper_transcribe', 0.5);
  });

  it('estimates the duration from file size when none was reported', async () => {
    // Старые голосовые метаданных не несут, но платить за них всё равно надо.
    await service.transcribeMessage('m-1', 'u-1');

    const [, minutes] = pricing.calculatePlanckCost.mock.calls[0];
    expect(minutes).toBeGreaterThan(0);
  });

  it('refunds when Whisper fails', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500, text: async () => 'boom' });

    await expect(service.transcribeMessage('m-1', 'u-1')).rejects.toThrow(BadRequestException);
    expect(ledger.refund).toHaveBeenCalledWith('tx-1', expect.stringContaining('Whisper 500'));
    expect(gating.endSession).toHaveBeenCalledWith('sess-1', 'failed');
  });

  it('does not charge when the debit itself fails', async () => {
    ledger.debit.mockRejectedValue(new Error('insufficient funds'));

    await expect(service.transcribeMessage('m-1', 'u-1')).rejects.toThrow('insufficient funds');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(gating.endSession).toHaveBeenCalledWith('sess-1', 'failed');
  });

  it('stores an empty transcript for a silent recording', async () => {
    // Тишина — это ответ, а не ошибка: иначе кнопка предлагала бы
    // расшифровать снова и снова, списывая каждый раз.
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ text: '   ' }) });

    const out = await service.transcribeMessage('m-1', 'u-1');

    expect(out.transcript).toBe('');
    expect(prisma.message.update).toHaveBeenCalled();
  });

  it('keeps other metadata when writing the transcript', async () => {
    prisma.message.findUnique.mockResolvedValue(
      voiceMessage({ metadata: { waveform: [0.1, 0.2], durationMs: 5000 } }),
    );

    await service.transcribeMessage('m-1', 'u-1');

    expect(prisma.message.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: {
          metadata: {
            waveform: [0.1, 0.2],
            durationMs: 5000,
            transcript: 'привет из голосового',
          },
        },
      }),
    );
  });
});
