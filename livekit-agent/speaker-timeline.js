'use strict';
/**
 * Per-participant speech timeline — "who was making sound when".
 *
 * The recorder already holds a separate PCM stream per participant; the mixed
 * MP3 that goes to Whisper throws that apart away. Keeping a cheap energy
 * timeline alongside each stream lets the backend put names on the transcript
 * segments of the single mixed transcription, instead of paying Whisper once
 * per participant just to learn who spoke.
 *
 * Deliberately not a real VAD: no model, no spectral analysis. Each stream is
 * one person's own microphone, so loudness relative to that microphone's own
 * noise floor is enough, and it costs a multiply-add per sample.
 */

/** Energy is measured over windows this long. */
const WINDOW_MS = 100;

/** Below this RMS nothing counts as speech, whatever the noise floor says —
 *  otherwise a dead-silent stream turns its own dither into conversation. */
const MIN_ABS_RMS = 250;

/** Where the threshold sits between the stream's noise floor and its peaks. */
const THRESHOLD_RATIO = 0.25;

/** Gaps shorter than this are breaths inside a phrase, not turn changes. */
const MERGE_GAP_MS = 600;

/** Runs shorter than this are clicks, keystrokes and notification blips. */
const MIN_SPEECH_MS = 200;

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[idx];
}

/**
 * RMS windows → [[startSec, endSec], …] on the meeting clock.
 *
 * `offsetMs` is what the participant's own stream is behind the recorder's
 * start: someone who joined 90 s in has their first sample at meeting-time 90 s,
 * and without this every late joiner's speech would be attributed to whatever
 * was being said in the first minutes.
 */
function intervalsFromWindows(windows, opts = {}) {
  const windowMs = opts.windowMs || WINDOW_MS;
  const offsetMs = opts.offsetMs || 0;
  if (!windows || windows.length === 0) return [];

  const sorted = [...windows].sort((a, b) => a - b);
  const floor = percentile(sorted, 0.2);
  const peak = percentile(sorted, 0.95);
  // Relative to this microphone's own floor, so a noisy room raises the bar
  // instead of reading as one unbroken utterance.
  const threshold = Math.max(
    MIN_ABS_RMS,
    floor + THRESHOLD_RATIO * (peak - floor),
  );

  const runs = [];
  let start = null;
  windows.forEach((rms, i) => {
    if (rms >= threshold) {
      if (start === null) start = i;
    } else if (start !== null) {
      runs.push([start, i]);
      start = null;
    }
  });
  if (start !== null) runs.push([start, windows.length]);

  const mergeGap = MERGE_GAP_MS / windowMs;
  const merged = [];
  for (const run of runs) {
    const last = merged[merged.length - 1];
    if (last && run[0] - last[1] <= mergeGap) last[1] = run[1];
    else merged.push([...run]);
  }

  const minWindows = MIN_SPEECH_MS / windowMs;
  return merged
    .filter(([from, to]) => to - from >= minWindows)
    .map(([from, to]) => [
      (offsetMs + from * windowMs) / 1000,
      (offsetMs + to * windowMs) / 1000,
    ]);
}

/** Accumulates RMS per window from PCM frames as they stream in. */
class TrackEnergy {
  constructor({ sampleRate, windowMs = WINDOW_MS, offsetMs = 0 }) {
    this.samplesPerWindow = Math.round((sampleRate * windowMs) / 1000);
    this.windowMs = windowMs;
    this.offsetMs = offsetMs;
    this.windows = [];
    this.sumSquares = 0;
    this.count = 0;
  }

  /** `samples` is an Int16Array — frames arrive at whatever size LiveKit picks,
   *  so window boundaries fall inside frames and are carried across calls. */
  push(samples) {
    for (let i = 0; i < samples.length; i++) {
      const s = samples[i];
      this.sumSquares += s * s;
      if (++this.count >= this.samplesPerWindow) {
        this.windows.push(Math.sqrt(this.sumSquares / this.count));
        this.sumSquares = 0;
        this.count = 0;
      }
    }
  }

  intervals() {
    return intervalsFromWindows(this.windows, {
      windowMs: this.windowMs,
      offsetMs: this.offsetMs,
    });
  }
}

/** Union of several interval lists — one participant can publish more than one
 *  track (the translator adds one per language direction). */
function mergeIntervals(lists) {
  const all = [].concat(...lists).sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const [from, to] of all) {
    const last = out[out.length - 1];
    if (last && from <= last[1]) last[1] = Math.max(last[1], to);
    else out.push([from, to]);
  }
  return out;
}

module.exports = {
  TrackEnergy,
  intervalsFromWindows,
  mergeIntervals,
  WINDOW_MS,
};
