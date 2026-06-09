import { PcmWindow } from './pcm-window';

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
