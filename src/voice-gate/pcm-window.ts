export class PcmWindow {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(private readonly windowBytes: number) {}

  /**
   * Append base64-encoded PCM bytes. Returns a Buffer of exactly windowBytes
   * once enough audio has been accumulated; otherwise returns null. Overflow
   * (bytes past windowBytes) is carried into the next call.
   */
  appendBase64(b64: string): Buffer | null {
    let chunk: Buffer;
    try {
      chunk = Buffer.from(b64, 'base64');
    } catch {
      return null;
    }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length <= this.windowBytes) {
      return null;
    }
    const emitted = this.buffer.subarray(0, this.windowBytes);
    this.buffer = Buffer.from(this.buffer.subarray(this.windowBytes));
    return emitted;
  }

  reset(): void {
    this.buffer = Buffer.alloc(0);
  }
}

/**
 * Wrap 16kHz mono int16 PCM in a RIFF/WAV header. voice-embed-service
 * uses torchaudio.load which expects a real audio container, not a raw
 * PCM byte stream.
 */
export function wrapWav16kMono(pcm: Buffer): Buffer {
  const sampleRate = 16_000;
  const numChannels = 1;
  const bitsPerSample = 16;
  const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
  const blockAlign = numChannels * (bitsPerSample / 8);

  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);              // fmt chunk size
  header.writeUInt16LE(1, 20);               // PCM
  header.writeUInt16LE(numChannels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bitsPerSample, 34);
  header.write('data', 36);
  header.writeUInt32LE(pcm.length, 40);

  return Buffer.concat([header, pcm]);
}
