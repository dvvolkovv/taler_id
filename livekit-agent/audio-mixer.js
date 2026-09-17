/**
 * Folds every participant's PCM into the one stream OpenAI Realtime expects.
 *
 * The Realtime input buffer is a single mono timeline. LiveKit hands us one
 * track per participant, and appending each track's frames to that buffer as
 * they arrive interleaves them: the model receives neither voice but a shuffle
 * of both, and settles on whoever's frames come denser. The other person is
 * never heard at all — which looks exactly like a Realtime limitation and isn't
 * one. Summing the tracks on a clock of our own is the whole fix.
 *
 * The mixer holds one backlog per participant and drains a fixed frame from
 * each on every tick, so a caller driving it at `frameMs` produces real-time
 * audio regardless of how LiveKit chunks its frames.
 */

const DEFAULT_SAMPLE_RATE = 24000;
const DEFAULT_FRAME_MS = 20;
/** Audio older than this is stale by the time it would be spoken. */
const DEFAULT_MAX_BACKLOG_MS = 400;

function createAudioMixer(opts = {}) {
  const sampleRate = opts.sampleRate ?? DEFAULT_SAMPLE_RATE;
  const frameMs = opts.frameMs ?? DEFAULT_FRAME_MS;
  const maxBacklogMs = opts.maxBacklogMs ?? DEFAULT_MAX_BACKLOG_MS;

  const frameSamples = Math.round((sampleRate / 1000) * frameMs);
  const maxBacklogSamples = Math.round((sampleRate / 1000) * maxBacklogMs);

  /** identity → PCM16 not yet folded into the mix. */
  const backlog = new Map();

  return {
    frameSamples,

    /** Participants currently holding a lane, talking or not. */
    get size() {
      return backlog.size;
    },

    has(identity) {
      return backlog.has(identity);
    },

    /**
     * Opens a lane. Called on subscribe rather than on first frame, so that a
     * participant who joins and stays quiet still counts as present — otherwise
     * the mixer would look idle and the caller would skip the tick.
     */
    add(identity) {
      if (!backlog.has(identity)) backlog.set(identity, new Int16Array(0));
    },

    remove(identity) {
      backlog.delete(identity);
    },

    clear() {
      backlog.clear();
    },

    /** Appends one participant's samples. Copies — LiveKit reuses frame buffers. */
    push(identity, samples) {
      const prev = backlog.get(identity);
      let merged;
      if (prev && prev.length > 0) {
        merged = new Int16Array(prev.length + samples.length);
        merged.set(prev, 0);
        merged.set(samples, prev.length);
      } else {
        merged = Int16Array.from(samples);
      }
      // A burst must not push the mix further and further behind the live call,
      // so when the backlog overruns it is the oldest samples that go.
      if (merged.length > maxBacklogSamples) {
        merged = merged.slice(merged.length - maxBacklogSamples);
      }
      backlog.set(identity, merged);
    },

    /**
     * Drains one frame from every lane and sums them. Lanes with nothing to
     * give contribute silence, which is what keeps the timeline continuous.
     */
    take() {
      const sum = new Int32Array(frameSamples);
      for (const [identity, buf] of backlog) {
        if (buf.length === 0) continue;
        const n = Math.min(buf.length, frameSamples);
        for (let i = 0; i < n; i++) sum[i] += buf[i];
        backlog.set(identity, buf.slice(n));
      }
      // People talking over each other sum past full scale; clamping keeps that
      // as loud overlap instead of letting it wrap into a crackle.
      const out = new Int16Array(frameSamples);
      for (let i = 0; i < frameSamples; i++) {
        const v = sum[i];
        out[i] = v > 32767 ? 32767 : v < -32768 ? -32768 : v;
      }
      return out;
    },
  };
}

module.exports = { createAudioMixer };
