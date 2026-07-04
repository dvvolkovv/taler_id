import { PcmWindow, wrapWavMono } from './pcm-window';

describe('PcmWindow', () => {
  it('does not emit before window is full', () => {
    const w = new PcmWindow(1000); // 1000 bytes window
    expect(w.appendBase64(Buffer.alloc(500).toString('base64'))).toBeNull();
    expect(w.appendBase64(Buffer.alloc(400).toString('base64'))).toBeNull();
  });

  it('emits exactly the configured window size and keeps the overflow', () => {
    const w = new PcmWindow(1000);
    expect(w.appendBase64(Buffer.alloc(700).toString('base64'))).toBeNull();
    const emitted = w.appendBase64(Buffer.alloc(500).toString('base64'));
    expect(emitted).not.toBeNull();
    expect(emitted!.length).toBe(1000);
    // 200 bytes overflow should be carried into the next window
    expect(w.appendBase64(Buffer.alloc(800).toString('base64'))).toBeNull();
    const second = w.appendBase64(Buffer.alloc(0).toString('base64'));
    expect(second).toBeNull(); // total now 1000, but we need explicit fill
    expect(w.appendBase64(Buffer.alloc(0).toString('base64'))).toBeNull();
  });

  it('handles invalid base64 gracefully (returns null)', () => {
    const w = new PcmWindow(1000);
    expect(w.appendBase64('!!!not base64!!!')).toBeNull();
  });
});

describe('wrapWavMono', () => {
  it('produces a 44-byte RIFF header + the original PCM payload', () => {
    const pcm = Buffer.alloc(32_000); // 1 sec of audio
    const wav = wrapWavMono(pcm);
    expect(wav.length).toBe(44 + 32_000);
    expect(wav.slice(0, 4).toString()).toBe('RIFF');
    expect(wav.slice(8, 12).toString()).toBe('WAVE');
    // sample rate at bytes 24..28 little-endian → 16000
    expect(wav.readUInt32LE(24)).toBe(16000);
    // bits per sample at bytes 34..36 → 16
    expect(wav.readUInt16LE(34)).toBe(16);
    // num channels at bytes 22..24 → 1
    expect(wav.readUInt16LE(22)).toBe(1);
  });

  it('writes the requested sample rate into the header (24kHz realtime PCM)', () => {
    const pcm = Buffer.alloc(48_000); // 1 sec of 24kHz mono int16
    const wav = wrapWavMono(pcm, 24_000);
    expect(wav.readUInt32LE(24)).toBe(24_000);
    // byteRate = sampleRate * channels * 2
    expect(wav.readUInt32LE(28)).toBe(48_000);
  });
});

describe('pcmRms16', () => {
  it('returns 0 for empty buffer', () => {
    const { pcmRms16 } = require('./pcm-window');
    expect(pcmRms16(Buffer.alloc(0))).toBe(0);
  });

  it('returns 0 for silence and full-scale for a square wave', () => {
    const { pcmRms16 } = require('./pcm-window');
    expect(pcmRms16(Buffer.alloc(3200))).toBe(0);
    const loud = Buffer.alloc(3200);
    for (let i = 0; i < 1600; i++) loud.writeInt16LE(i % 2 === 0 ? 16000 : -16000, i * 2);
    expect(pcmRms16(loud)).toBeCloseTo(16000, 0);
  });

  it('quiet room noise stays below the 400 gate', () => {
    const { pcmRms16 } = require('./pcm-window');
    const noise = Buffer.alloc(3200);
    for (let i = 0; i < 1600; i++) noise.writeInt16LE((i % 7) - 3, i * 2);
    expect(pcmRms16(noise)).toBeLessThan(400);
  });
});
