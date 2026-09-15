// Speaker labels for a mixed recording.
//
// The meeting is transcribed as one mixed track, so Whisper hands back segments
// with timings but no idea who spoke. The recorder does know: it holds a separate
// PCM stream per participant and can say who was making sound when. Matching the
// two gives real attribution without paying Whisper once per participant.
//
// Everything here is about the matching rule, which is where the judgement calls
// live: partial coverage, crosstalk, speakerphone bleed, silence.
import {
  labelSegments,
  readSpeakerTimeline,
  SpeakerTimelineEntry,
} from './speaker-labeling';

const volkov: SpeakerTimelineEntry = {
  identity: 'guest-1',
  name: 'Dmitry Volkov',
  intervals: [[0, 10]],
};
const vladimir: SpeakerTimelineEntry = {
  identity: 'guest-2',
  name: 'Vladimir',
  intervals: [[12, 20]],
};

describe('labelSegments', () => {
  it('names the speaker whose voice covers the segment', () => {
    const labelled = labelSegments([{ start: 1, end: 5, text: 'привет' }], [
      volkov,
      vladimir,
    ]);

    expect(labelled).toEqual([
      { start: 1, end: 5, text: 'привет', speaker: 'Dmitry Volkov' },
    ]);
  });

  it('weighs total overlap, not whichever interval starts first', () => {
    // Volkov drops a word at the very start, Vladimir carries the rest.
    const chatty: SpeakerTimelineEntry = {
      identity: 'guest-2',
      name: 'Vladimir',
      intervals: [
        [10.5, 12],
        [12.5, 19],
      ],
    };
    const interjection: SpeakerTimelineEntry = {
      identity: 'guest-1',
      name: 'Dmitry Volkov',
      intervals: [[10, 10.6]],
    };

    const [labelled] = labelSegments(
      [{ start: 10, end: 19, text: 'длинная реплика' }],
      [interjection, chatty],
    );

    expect(labelled.speaker).toBe('Vladimir');
  });

  it('leaves a segment unnamed when two people talk over each other', () => {
    // Speakerphone bleed and genuine crosstalk look the same from here. Guessing
    // between them is how the recap ends up confidently wrong.
    const a: SpeakerTimelineEntry = {
      identity: 'guest-1',
      name: 'Dmitry Volkov',
      intervals: [[0, 4]],
    };
    const b: SpeakerTimelineEntry = {
      identity: 'guest-2',
      name: 'Dmitry Timoshenko',
      intervals: [[0.2, 4]],
    };

    const [labelled] = labelSegments([{ start: 0, end: 4, text: 'разом' }], [
      a,
      b,
    ]);

    expect(labelled.speaker).toBeNull();
  });

  it('leaves a segment unnamed when nobody was making sound', () => {
    const [labelled] = labelSegments(
      [{ start: 30, end: 34, text: 'музыка на фоне' }],
      [volkov, vladimir],
    );

    expect(labelled.speaker).toBeNull();
  });

  it('leaves a segment unnamed when the voice barely clips it', () => {
    // 0.4 s of a 8 s segment is someone saying "ага" underneath, not the speaker.
    const [labelled] = labelSegments(
      [{ start: 9.6, end: 17.6, text: 'долгая мысль' }],
      [volkov],
    );

    expect(labelled.speaker).toBeNull();
  });

  it('survives the zero-length segment Whisper returns for short clips', () => {
    const [labelled] = labelSegments([{ start: 0, end: 0, text: 'да' }], [
      volkov,
    ]);

    expect(labelled.speaker).toBeNull();
  });

  it('keeps two participants with the same display name apart', () => {
    // Web guests routinely join as "Гость"; one shared label would merge them.
    const guestA: SpeakerTimelineEntry = {
      identity: 'guest-aaa',
      name: 'Гость',
      intervals: [[0, 5]],
    };
    const guestB: SpeakerTimelineEntry = {
      identity: 'guest-bbb',
      name: 'Гость',
      intervals: [[10, 15]],
    };

    const labelled = labelSegments(
      [
        { start: 1, end: 4, text: 'первый' },
        { start: 11, end: 14, text: 'второй' },
      ],
      [guestA, guestB],
    );

    expect(labelled[0].speaker).toBe('Гость');
    expect(labelled[1].speaker).toBe('Гость 2');
  });

  it('returns segments untouched when the recorder sent no timeline', () => {
    const labelled = labelSegments([{ start: 1, end: 5, text: 'привет' }], []);

    expect(labelled[0].speaker).toBeNull();
  });
});

describe('readSpeakerTimeline', () => {
  // The column is Json: legacy rows hold null, and whatever a future recorder
  // version sends lands here unvalidated. Nothing in this path is worth a 500.
  it('accepts what the recorder writes', () => {
    expect(
      readSpeakerTimeline([
        { identity: 'guest-1', name: 'Vladimir', intervals: [[0, 2.5]] },
      ]),
    ).toEqual([
      { identity: 'guest-1', name: 'Vladimir', intervals: [[0, 2.5]] },
    ]);
  });

  it('treats a missing or non-array timeline as no timeline', () => {
    expect(readSpeakerTimeline(null)).toEqual([]);
    expect(readSpeakerTimeline(undefined)).toEqual([]);
    expect(readSpeakerTimeline({})).toEqual([]);
    expect(readSpeakerTimeline('[]')).toEqual([]);
  });

  it('drops entries and intervals it cannot read', () => {
    expect(
      readSpeakerTimeline([
        { identity: 'a', name: 'Кто-то', intervals: [[1, 2], [3], 'x', [5, 4]] },
        { identity: 'b' },
        null,
        { identity: 'c', name: 'Пусто', intervals: [] },
      ]),
    ).toEqual([{ identity: 'a', name: 'Кто-то', intervals: [[1, 2]] }]);
  });
});
