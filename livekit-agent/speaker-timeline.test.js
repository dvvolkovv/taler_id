// Run with: node --test livekit-agent/
//
// Turns each participant's own PCM stream into "when was this person actually
// talking". The recorder already has the streams; all that was missing was the
// timeline, without which the mixed transcript can never say who spoke.
const test = require('node:test');
const assert = require('node:assert');
const {
  TrackEnergy,
  intervalsFromWindows,
  mergeIntervals,
} = require('./speaker-timeline');

const WINDOW_MS = 100;

/** RMS window series: `n` windows at `level` (0..32767). */
const flat = (n, level) => new Array(n).fill(level);

test('continuous speech becomes one interval', () => {
  const windows = [...flat(5, 40), ...flat(20, 4000), ...flat(5, 40)];

  const intervals = intervalsFromWindows(windows, { windowMs: WINDOW_MS });

  assert.strictEqual(intervals.length, 1);
  assert.ok(Math.abs(intervals[0][0] - 0.5) < 0.15, `start ${intervals[0][0]}`);
  assert.ok(Math.abs(intervals[0][1] - 2.5) < 0.15, `end ${intervals[0][1]}`);
});

test('pauses between words do not split a sentence', () => {
  // 200 ms of breath in the middle of a phrase — the same person, still talking.
  const windows = [
    ...flat(5, 40),
    ...flat(10, 4000),
    ...flat(2, 40),
    ...flat(10, 4000),
    ...flat(5, 40),
  ];

  const intervals = intervalsFromWindows(windows, { windowMs: WINDOW_MS });

  assert.strictEqual(intervals.length, 1);
});

test('a long silence does split two utterances', () => {
  const windows = [
    ...flat(10, 4000),
    ...flat(30, 40),
    ...flat(10, 4000),
  ];

  const intervals = intervalsFromWindows(windows, { windowMs: WINDOW_MS });

  assert.strictEqual(intervals.length, 2);
});

test('a single click is not an utterance', () => {
  // One 100 ms spike: a keyboard, a door, a notification.
  const windows = [...flat(20, 40), 6000, ...flat(20, 40)];

  assert.deepStrictEqual(
    intervalsFromWindows(windows, { windowMs: WINDOW_MS }),
    [],
  );
});

test('silence yields nothing', () => {
  assert.deepStrictEqual(
    intervalsFromWindows(flat(50, 30), { windowMs: WINDOW_MS }),
    [],
  );
});

test('a noisy microphone does not read as constant speech', () => {
  // Fan/street noise at a level that would trip a fixed threshold, with one
  // genuine utterance standing above it.
  const windows = [...flat(40, 900), ...flat(20, 9000), ...flat(40, 900)];

  const intervals = intervalsFromWindows(windows, { windowMs: WINDOW_MS });

  assert.strictEqual(intervals.length, 1);
  assert.ok(intervals[0][0] >= 3.5 && intervals[0][1] <= 6.5);
});

test('intervals are placed on the meeting clock, not the track clock', () => {
  // A participant who joined 90 s after the recorder started: their first
  // sample is meeting-time 90 s, not 0.
  const windows = [...flat(5, 40), ...flat(20, 4000)];

  const intervals = intervalsFromWindows(windows, {
    windowMs: WINDOW_MS,
    offsetMs: 90_000,
  });

  assert.ok(Math.abs(intervals[0][0] - 90.5) < 0.15, `start ${intervals[0][0]}`);
});

test('TrackEnergy windows raw PCM frames as they arrive', () => {
  const energy = new TrackEnergy({ sampleRate: 48000, windowMs: WINDOW_MS });
  const samplesPerWindow = 4800;
  const loud = new Int16Array(samplesPerWindow).fill(8000);
  const quiet = new Int16Array(samplesPerWindow).fill(20);

  // Frames do not arrive window-aligned — LiveKit hands over 10 ms chunks,
  // ten to a window. One second of quiet, two of speech, one of quiet.
  for (let i = 0; i < 100; i++) energy.push(quiet.subarray(0, 480));
  for (let i = 0; i < 200; i++) energy.push(loud.subarray(0, 480));
  for (let i = 0; i < 100; i++) energy.push(quiet.subarray(0, 480));

  const intervals = energy.intervals();

  assert.strictEqual(intervals.length, 1);
  assert.ok(Math.abs(intervals[0][0] - 1.0) < 0.15, `start ${intervals[0][0]}`);
  assert.ok(Math.abs(intervals[0][1] - 3.0) < 0.15, `end ${intervals[0][1]}`);
});

test('one participant publishing two tracks yields a single timeline', () => {
  // The translator publishes an extra track per language direction, so the same
  // person can own several streams. Overlapping and touching runs collapse.
  const merged = mergeIntervals([
    [
      [0, 2],
      [10, 12],
    ],
    [
      [1.5, 3],
      [20, 21],
    ],
  ]);

  assert.deepStrictEqual(merged, [
    [0, 3],
    [10, 12],
    [20, 21],
  ]);
});
