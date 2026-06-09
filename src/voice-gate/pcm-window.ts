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
