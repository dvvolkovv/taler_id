import { sanitizeVoiceMeta, WAVEFORM_MAX_BARS } from './voice-meta.util';

describe('sanitizeVoiceMeta', () => {
  it('keeps a normal waveform and duration', () => {
    expect(sanitizeVoiceMeta({ waveform: [0, 0.5, 1], durationMs: 4200 })).toEqual({
      waveform: [0, 0.5, 1],
      durationMs: 4200,
    });
  });

  it('returns null when there is nothing usable', () => {
    expect(sanitizeVoiceMeta(undefined)).toBeNull();
    expect(sanitizeVoiceMeta({})).toBeNull();
    expect(sanitizeVoiceMeta({ waveform: [] })).toBeNull();
  });

  it('clamps values into 0..1 instead of trusting the client', () => {
    expect(sanitizeVoiceMeta({ waveform: [-5, 0.5, 42] })?.waveform).toEqual([0, 0.5, 1]);
  });

  it('drops non-numeric entries', () => {
    // Клиент может прислать что угодно; массив идёт прямо в отрисовку.
    expect(sanitizeVoiceMeta({ waveform: [0.2, 'громко' as any, null as any, 0.8] })?.waveform)
      .toEqual([0.2, 0.8]);
  });

  it('rejects NaN and Infinity', () => {
    expect(sanitizeVoiceMeta({ waveform: [NaN, Infinity, 0.3] })?.waveform).toEqual([0.3]);
  });

  it('caps an over-long waveform instead of storing it whole', () => {
    // Иначе одним сообщением можно записать в базу мегабайт чисел.
    const out = sanitizeVoiceMeta({ waveform: new Array(5000).fill(0.5) });
    expect(out?.waveform).toHaveLength(WAVEFORM_MAX_BARS);
  });

  it('ignores a waveform that is not an array', () => {
    expect(sanitizeVoiceMeta({ waveform: 'нет' as any })).toBeNull();
  });

  it('keeps duration alone when the waveform is unusable', () => {
    expect(sanitizeVoiceMeta({ waveform: 'нет' as any, durationMs: 1500 }))
      .toEqual({ durationMs: 1500 });
  });

  it('rejects a nonsensical duration', () => {
    expect(sanitizeVoiceMeta({ durationMs: -1 })).toBeNull();
    expect(sanitizeVoiceMeta({ durationMs: 0 })).toBeNull();
    expect(sanitizeVoiceMeta({ durationMs: 'долго' as any })).toBeNull();
  });

  it('caps an absurd duration', () => {
    // Четыре часа голосового — это не голосовое, а ошибка клиента.
    expect(sanitizeVoiceMeta({ durationMs: 4 * 3600_000 })?.durationMs)
      .toBeLessThanOrEqual(2 * 3600_000);
  });

  it('rounds duration to a whole millisecond', () => {
    expect(sanitizeVoiceMeta({ durationMs: 1500.7 })?.durationMs).toBe(1501);
  });

  it('ignores any other key the client tries to smuggle in', () => {
    // Message.metadata используется служебными путями — чужого туда попадать
    // не должно.
    const out = sanitizeVoiceMeta({
      durationMs: 1000,
      transcript: 'подделка',
      newsType: 'critical',
    } as any);
    expect(out).toEqual({ durationMs: 1000 });
  });
});
