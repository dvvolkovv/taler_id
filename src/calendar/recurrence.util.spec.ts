import { expandOccurrences, expandRoutineOccurrences } from './recurrence.util';

const iso = (d: Date) => d.toISOString();

describe('expandRoutineOccurrences (deadline-bounded routines)', () => {
  // Mirrors the "Занятие с Савой" bug: a daily routine anchored 2026-11-07
  // 14:00Z whose deadline was set to 2026-11-22 16:00Z (21:00 local, UTC+5).
  // It must stop on the 22nd — no occurrence on the 23rd or later.
  const anchor = new Date('2026-11-07T14:00:00.000Z');
  const rec = { frequency: 'daily', interval: 1 };
  const from = new Date('2026-11-20T00:00:00.000Z');
  const to = new Date('2026-11-30T00:00:00.000Z');

  it('drops occurrences after the deadline (last day = deadline day)', () => {
    const deadline = new Date('2026-11-22T16:00:00.000Z');
    const out = expandRoutineOccurrences(anchor, rec, deadline, from, to).map(iso);
    expect(out).toEqual([
      '2026-11-20T14:00:00.000Z',
      '2026-11-21T14:00:00.000Z',
      '2026-11-22T14:00:00.000Z', // 14:00Z <= 16:00Z deadline → kept
    ]);
    expect(out).not.toContain('2026-11-23T14:00:00.000Z');
  });

  it('keeps an occurrence falling exactly at the deadline instant', () => {
    const deadline = new Date('2026-11-22T14:00:00.000Z'); // == occurrence time
    const out = expandRoutineOccurrences(anchor, rec, deadline, from, to).map(iso);
    expect(out[out.length - 1]).toBe('2026-11-22T14:00:00.000Z');
  });

  it('with no deadline behaves exactly like expandOccurrences', () => {
    for (const dl of [null, undefined]) {
      expect(expandRoutineOccurrences(anchor, rec, dl, from, to).map(iso)).toEqual(
        expandOccurrences(anchor, rec, from, to).map(iso),
      );
    }
  });

  it('a deadline before the window start yields no occurrences (routine ended)', () => {
    const deadline = new Date('2026-11-10T00:00:00.000Z');
    expect(expandRoutineOccurrences(anchor, rec, deadline, from, to)).toEqual([]);
  });

  it('a deadline after the window end does not shrink the window', () => {
    const deadline = new Date('2027-01-01T00:00:00.000Z');
    expect(expandRoutineOccurrences(anchor, rec, deadline, from, to).map(iso)).toEqual(
      expandOccurrences(anchor, rec, from, to).map(iso),
    );
  });

  it('caps a weekly byDay routine at the deadline too', () => {
    const wAnchor = new Date('2026-11-03T09:00:00.000Z'); // a Tuesday
    const wRec = { freq: 'weekly', interval: 1, byDay: ['TU'] };
    const deadline = new Date('2026-11-17T23:59:00.000Z'); // Tue Nov 17 kept, Nov 24 dropped
    const out = expandRoutineOccurrences(
      wAnchor,
      wRec,
      deadline,
      new Date('2026-11-01T00:00:00.000Z'),
      new Date('2026-12-31T00:00:00.000Z'),
    ).map(iso);
    expect(out).toEqual([
      '2026-11-03T09:00:00.000Z',
      '2026-11-10T09:00:00.000Z',
      '2026-11-17T09:00:00.000Z',
    ]);
  });
});
