'use strict';
/**
 * Just enough WAV for the interpreter: wrap PCM16 mono for the voice-embed
 * service, read the bench's fixtures, and the RMS level used as the cheap
 * "is anyone talking" test.
 *
 * The sample rate in the header must be the real one. torchaudio trusts it:
 * a 24 kHz stream labelled 16 kHz plays 1.5x slow and its embedding matches
 * nobody (the voice gate learned this the hard way, see
 * src/voice-gate/pcm-window.ts).
 */

function wrapWavMono(int16, sampleRate) {
  const pcm = Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength);
  const header = Buffer.alloc(44);
  header.write('RIFF', 0, 'ascii');
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8, 'ascii');
  header.write('fmt ', 12, 'ascii');
  header.writeUInt32LE(16, 16); // fmt chunk size
  header.writeUInt16LE(1, 20); // PCM
  header.writeUInt16LE(1, 22); // mono
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * 2, 28); // byte rate
  header.writeUInt16LE(2, 32); // block align
  header.writeUInt16LE(16, 34); // bits per sample
  header.write('data', 36, 'ascii');
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
}

/** PCM16 WAV → mono samples. Stereo is averaged; other formats are refused. */
function readWav(buffer) {
  if (buffer.toString('ascii', 0, 4) !== 'RIFF' || buffer.toString('ascii', 8, 12) !== 'WAVE') {
    throw new Error('not a RIFF/WAVE file');
  }
  let fmt = null;
  let data = null;
  let offset = 12;
  // afconvert writes extra chunks (FLLR padding and the like): walk them all.
  while (offset + 8 <= buffer.length) {
    const id = buffer.toString('ascii', offset, offset + 4);
    const size = buffer.readUInt32LE(offset + 4);
    const body = offset + 8;
    if (id === 'fmt ') {
      if (size < 16 || body + 16 > buffer.length) {
        throw new Error('truncated fmt chunk');
      }
      let format = buffer.readUInt16LE(body);
      // WAVE_FORMAT_EXTENSIBLE keeps the real format code at the start of
      // its SubFormat GUID; afconvert writes it for some layouts.
      if (format === 0xfffe && size >= 26 && body + 26 <= buffer.length) format = buffer.readUInt16LE(body + 24);
      fmt = {
        format,
        channels: buffer.readUInt16LE(body + 2),
        sampleRate: buffer.readUInt32LE(body + 4),
        bitsPerSample: buffer.readUInt16LE(body + 14),
      };
    } else if (id === 'data') {
      data = buffer.subarray(body, Math.min(body + size, buffer.length));
    }
    offset = body + size + (size % 2);
  }
  if (!fmt || !data) throw new Error('WAV without a fmt or data chunk');
  if (fmt.format !== 1 || fmt.bitsPerSample !== 16) {
    throw new Error(`unsupported WAV (format ${fmt.format}, ${fmt.bitsPerSample} bit): need PCM16`);
  }
  if (fmt.channels < 1) throw new Error('WAV with zero channels');
  const frames = Math.floor(data.length / (2 * fmt.channels));
  const samples = new Int16Array(frames);
  for (let i = 0; i < frames; i++) {
    let sum = 0;
    for (let c = 0; c < fmt.channels; c++) sum += data.readInt16LE((i * fmt.channels + c) * 2);
    samples[i] = Math.round(sum / fmt.channels);
  }
  return { sampleRate: fmt.sampleRate, samples };
}

/** Root-mean-square level of PCM16 samples, 0–32768. */
function rms(int16) {
  if (int16.length === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < int16.length; i++) sumSq += int16[i] * int16[i];
  return Math.sqrt(sumSq / int16.length);
}

module.exports = { wrapWavMono, readWav, rms };
