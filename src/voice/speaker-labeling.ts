/**
 * Puts a name on each Whisper segment of a mixed meeting recording.
 *
 * The recording that goes to Whisper is a single mix, so the transcript comes
 * back with timings and no speakers. The recorder, though, holds one PCM stream
 * per participant, and can report when each of them was actually making sound.
 * Overlapping the two is what turns "[12:03] ..." into "[12:03] Vladimir: ...",
 * and it costs one Whisper pass rather than one per participant.
 *
 * The rules below are deliberately reluctant. An unnamed line reads as "we don't
 * know who said this", which is honest; a wrong name reads as fact and ends up
 * quoted back at people in the recap.
 */

/** Fraction of the segment the winner must cover to be named at all. */
const MIN_COVERAGE = 0.35;

/** How far ahead of the runner-up the winner must be. Speakerphones bleed one
 *  participant's voice into everybody else's microphone, so "loudest wins by a
 *  hair" would hand whole passages to the wrong person. */
const MIN_DOMINANCE = 2;

export interface SpeakerTimelineEntry {
  identity: string;
  name: string;
  /** [startSec, endSec] of speech, on the meeting clock. */
  intervals: [number, number][];
}

export interface TimedSegment {
  start: number;
  end: number;
  text: string;
}

export type LabelledSegment = TimedSegment & { speaker: string | null };

/** Seconds of `intervals` that fall inside [start, end). */
function overlapSeconds(
  intervals: [number, number][],
  start: number,
  end: number,
): number {
  let total = 0;
  for (const [from, to] of intervals) {
    const lo = Math.max(from, start);
    const hi = Math.min(to, end);
    if (hi > lo) total += hi - lo;
  }
  return total;
}

/**
 * Display labels, one per participant.
 *
 * Web guests routinely join under the same display name ("Гость"), and two
 * identities collapsed into one label would read as a single person talking to
 * themselves. Later duplicates get a counter; the first keeps the plain name.
 */
function resolveLabels(timeline: SpeakerTimelineEntry[]): string[] {
  const seen = new Map<string, number>();
  return timeline.map((entry) => {
    const n = (seen.get(entry.name) ?? 0) + 1;
    seen.set(entry.name, n);
    return n === 1 ? entry.name : `${entry.name} ${n}`;
  });
}

export function labelSegments(
  segments: TimedSegment[],
  timeline: SpeakerTimelineEntry[],
): LabelledSegment[] {
  const labels = resolveLabels(timeline);

  return segments.map((segment) => {
    const duration = segment.end - segment.start;
    // Whisper collapses very short clips into one segment with no timings at
    // all (start === end === 0). There is nothing to overlap against.
    if (!(duration > 0)) return { ...segment, speaker: null };

    let best = { label: null as string | null, overlap: 0 };
    let runnerUp = 0;

    timeline.forEach((entry, i) => {
      const overlap = overlapSeconds(
        entry.intervals,
        segment.start,
        segment.end,
      );
      if (overlap > best.overlap) {
        runnerUp = best.overlap;
        best = { label: labels[i], overlap };
      } else if (overlap > runnerUp) {
        runnerUp = overlap;
      }
    });

    if (best.overlap < duration * MIN_COVERAGE) {
      return { ...segment, speaker: null };
    }
    if (runnerUp > 0 && best.overlap < runnerUp * MIN_DOMINANCE) {
      return { ...segment, speaker: null };
    }
    return { ...segment, speaker: best.label };
  });
}

/**
 * Reads the `speakerTimeline` Json column into something safe to work with.
 *
 * Legacy rows hold null, and whatever shape a future recorder sends lands here
 * unvalidated — a malformed timeline should cost the transcript its speaker
 * labels, not fail the transcription the user already paid for.
 */
export function readSpeakerTimeline(raw: unknown): SpeakerTimelineEntry[] {
  if (!Array.isArray(raw)) return [];

  const entries: SpeakerTimelineEntry[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const { identity, name, intervals } = item as Record<string, unknown>;
    if (typeof identity !== 'string' || typeof name !== 'string') continue;
    if (!Array.isArray(intervals)) continue;

    const clean = intervals.filter(
      (iv): iv is [number, number] =>
        Array.isArray(iv) &&
        iv.length === 2 &&
        Number.isFinite(iv[0]) &&
        Number.isFinite(iv[1]) &&
        iv[1] > iv[0],
    );
    if (clean.length > 0) entries.push({ identity, name, intervals: clean });
  }
  return entries;
}

/** `[mm:ss] Имя: текст`, falling back to `[mm:ss] текст` where attribution
 *  wasn't confident enough. */
export function formatTranscript(segments: LabelledSegment[]): string {
  return segments
    .map((s) => {
      const mm = String(Math.floor(s.start / 60)).padStart(2, '0');
      const ss = String(Math.floor(s.start % 60)).padStart(2, '0');
      return `[${mm}:${ss}] ${s.speaker ? `${s.speaker}: ` : ''}${s.text}`;
    })
    .join('\n');
}
