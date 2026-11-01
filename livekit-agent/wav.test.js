// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { wrapWavMono, readWav, rms } = require('./wav');

test('a wrapped buffer reads back as the same samples and rate', () => {
  const samples = Int16Array.from([0, 1000, -1000, 32767, -32768]);
  const wav = wrapWavMono(samples, 24000);
  assert.strictEqual(wav.toString('ascii', 0, 4), 'RIFF');
  const back = readWav(wav);
  assert.strictEqual(back.sampleRate, 24000);
  assert.deepStrictEqual(Array.from(back.samples), Array.from(samples));
});

test('the header carries the real sample rate', () => {
  const wav = wrapWavMono(new Int16Array(10), 16000);
  assert.strictEqual(wav.readUInt32LE(24), 16000);
  assert.strictEqual(wav.readUInt32LE(28), 32000);
});

test('a subarray is wrapped from its own offset, not from the start of its buffer', () => {
  const big = Int16Array.from([1, 2, 3, 4, 5, 6]);
  const back = readWav(wrapWavMono(big.subarray(2, 4), 8000));
  assert.deepStrictEqual(Array.from(back.samples), [3, 4]);
});

test('extra chunks before data are skipped and stereo is averaged', () => {
  const fmt = Buffer.alloc(24);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(16, 4);
  fmt.writeUInt16LE(1, 8); // PCM
  fmt.writeUInt16LE(2, 10); // stereo
  fmt.writeUInt32LE(24000, 12);
  fmt.writeUInt32LE(96000, 16);
  fmt.writeUInt16LE(4, 20);
  fmt.writeUInt16LE(16, 22);
  const fllr = Buffer.alloc(12);
  fllr.write('FLLR', 0, 'ascii');
  fllr.writeUInt32LE(4, 4);
  const pcm = Buffer.alloc(8);
  pcm.writeInt16LE(100, 0);
  pcm.writeInt16LE(300, 2);
  pcm.writeInt16LE(-50, 4);
  pcm.writeInt16LE(-150, 6);
  const dataHeader = Buffer.alloc(8);
  dataHeader.write('data', 0, 'ascii');
  dataHeader.writeUInt32LE(8, 4);
  const body = Buffer.concat([Buffer.from('WAVE', 'ascii'), fmt, fllr, dataHeader, pcm]);
  const riff = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), body]);
  riff.writeUInt32LE(body.length, 4);

  const { sampleRate, samples } = readWav(riff);
  assert.strictEqual(sampleRate, 24000);
  assert.deepStrictEqual(Array.from(samples), [200, -100]);
});

test('WAVE_FORMAT_EXTENSIBLE with PCM inside reads like plain PCM', () => {
  const plain = wrapWavMono(Int16Array.from([7, -7]), 24000);
  const fmt = Buffer.alloc(8 + 40);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(40, 4);
  fmt.writeUInt16LE(0xfffe, 8); // WAVE_FORMAT_EXTENSIBLE
  fmt.writeUInt16LE(1, 10);
  fmt.writeUInt32LE(24000, 12);
  fmt.writeUInt32LE(48000, 16);
  fmt.writeUInt16LE(2, 20);
  fmt.writeUInt16LE(16, 22);
  fmt.writeUInt16LE(22, 24); // cbSize
  fmt.writeUInt16LE(16, 26); // valid bits
  fmt.writeUInt32LE(4, 28); // channel mask
  fmt.writeUInt16LE(1, 32); // SubFormat GUID starts with the PCM code
  const body = Buffer.concat([Buffer.from('WAVE', 'ascii'), fmt, plain.subarray(36)]);
  const riff = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), body]);
  riff.writeUInt32LE(body.length, 4);
  assert.deepStrictEqual(Array.from(readWav(riff).samples), [7, -7]);
});

test('a file without a data chunk is refused', () => {
  const fmt = Buffer.alloc(24);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(16, 4);
  fmt.writeUInt16LE(1, 8); // PCM
  fmt.writeUInt16LE(1, 10); // mono
  fmt.writeUInt32LE(24000, 12);
  fmt.writeUInt32LE(48000, 16);
  fmt.writeUInt16LE(2, 20);
  fmt.writeUInt16LE(16, 22);
  const body = Buffer.concat([Buffer.from('WAVE', 'ascii'), fmt]);
  const riff = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), body]);
  riff.writeUInt32LE(body.length, 4);
  assert.throws(() => readWav(riff), /without a fmt or data chunk/);
});

test('an odd-sized chunk is skipped together with its pad byte', () => {
  const fmt = Buffer.alloc(24);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(16, 4);
  fmt.writeUInt16LE(1, 8); // PCM
  fmt.writeUInt16LE(1, 10); // mono
  fmt.writeUInt32LE(24000, 12);
  fmt.writeUInt32LE(48000, 16);
  fmt.writeUInt16LE(2, 20);
  fmt.writeUInt16LE(16, 22);
  const list = Buffer.alloc(8);
  list.write('LIST', 0, 'ascii');
  list.writeUInt32LE(3, 4);
  const payload = Buffer.from([0, 0, 0, 0]); // 3 bytes of LIST data + 1 pad byte
  const pcm = Buffer.alloc(4);
  pcm.writeInt16LE(11, 0);
  pcm.writeInt16LE(-11, 2);
  const dataHeader = Buffer.alloc(8);
  dataHeader.write('data', 0, 'ascii');
  dataHeader.writeUInt32LE(4, 4);
  const body = Buffer.concat([Buffer.from('WAVE', 'ascii'), fmt, list, payload, dataHeader, pcm]);
  const riff = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), body]);
  riff.writeUInt32LE(body.length, 4);
  const { samples } = readWav(riff);
  assert.deepStrictEqual(Array.from(samples), [11, -11]);
});

test('a truncated fmt chunk or zero channels is a clear error', () => {
  // Test 1: truncated fmt chunk
  const truncated = Buffer.concat([
    Buffer.from('RIFF', 'ascii'),
    Buffer.alloc(4),
    Buffer.from('WAVE', 'ascii'),
    Buffer.from('fmt ', 'ascii'),
    Buffer.alloc(4),
  ]);
  truncated.writeUInt32LE(12, 4); // body length
  assert.throws(() => readWav(truncated), /truncated fmt chunk/);

  // Test 2: zero channels
  const wav = wrapWavMono(Int16Array.from([1, 2]), 24000);
  wav.writeUInt16LE(0, 22); // channels = 0
  assert.throws(() => readWav(wav), /zero channels/);
});

test('anything but PCM16 is refused', () => {
  const wav = wrapWavMono(new Int16Array(4), 24000);
  wav.writeUInt16LE(3, 20); // IEEE float
  assert.throws(() => readWav(wav), /need PCM16/);
});

test('rms is 0 for silence and the magnitude for a constant', () => {
  assert.strictEqual(rms(new Int16Array(100)), 0);
  assert.strictEqual(rms(new Int16Array(100).fill(-2000)), 2000);
  assert.strictEqual(rms(new Int16Array(0)), 0);
});
