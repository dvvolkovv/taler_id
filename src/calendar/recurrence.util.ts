/**
 * Recurrence expansion shared by calendar events and routine tasks.
 *
 * Canonical rule shape (calendar API spec §3.3):
 *   { freq: 'daily'|'weekly'|'monthly'|'yearly', interval?, byDay?: [MO..SU], count?, until? }
 * Back-compat with the mobile app's legacy shape { frequency, interval, endAt }:
 * we read `freq ?? frequency` and `until ?? endAt`.
 *
 * `count`/`until` bound the SERIES (counted from `anchor`), independent of the
 * [from, to] read window. Occurrences are produced at the anchor's time-of-day.
 */
const WEEKDAY_INDEX: Record<string, number> = {
  SU: 0, MO: 1, TU: 2, WE: 3, TH: 4, FR: 5, SA: 6,
};

function startOfDay(d: Date): Date {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  return x;
}

function startOfWeekMonday(d: Date): Date {
  const x = startOfDay(d);
  const wd = x.getDay();
  x.setDate(x.getDate() - (wd === 0 ? 6 : wd - 1));
  return x;
}

function advanceDate(date: Date, freq: string, interval: number): Date {
  const d = new Date(date);
  switch (freq) {
    case 'daily':
      d.setDate(d.getDate() + interval);
      break;
    case 'weekly':
      d.setDate(d.getDate() + 7 * interval);
      break;
    case 'monthly':
      d.setMonth(d.getMonth() + interval);
      break;
    case 'yearly':
      d.setFullYear(d.getFullYear() + interval);
      break;
  }
  return d;
}

/**
 * Returns the occurrence start-instants within [from, to]. With no `rec.freq`
 * (non-recurring), returns [anchor] if it falls in the window, else [].
 */
export function expandOccurrences(
  anchor: Date,
  rec: any,
  from: Date,
  to: Date,
): Date[] {
  const freq: string | undefined = rec?.freq ?? rec?.frequency;
  if (!freq) {
    return anchor >= from && anchor <= to ? [anchor] : [];
  }

  const interval = Math.max(1, Number(rec.interval) || 1);
  const count: number | undefined =
    typeof rec.count === 'number' && rec.count > 0 ? rec.count : undefined;
  const until: Date | null =
    rec.until || rec.endAt ? new Date(rec.until ?? rec.endAt) : null;
  const byDay: Set<number> | null =
    Array.isArray(rec.byDay) && rec.byDay.length
      ? new Set(
          (rec.byDay as string[])
            .map((d) => WEEKDAY_INDEX[d])
            .filter((n) => n !== undefined),
        )
      : null;

  const out: Date[] = [];
  let emitted = 0;
  // Records one series occurrence; returns false when the series must stop.
  const emit = (d: Date): boolean => {
    if (until && d > until) return false;
    if (d >= from && d <= to) out.push(new Date(d));
    emitted++;
    return !(count && emitted >= count);
  };

  if (freq === 'weekly' && byDay) {
    const anchorWeek = startOfWeekMonday(anchor).getTime();
    const timeOfDayMs = anchor.getTime() - startOfDay(anchor).getTime();
    let day = startOfDay(anchor);
    let safety = 0;
    while (safety < 4000) {
      safety++;
      const occ = new Date(day.getTime() + timeOfDayMs);
      if (occ >= anchor) {
        const weekIdx = Math.round(
          (startOfWeekMonday(occ).getTime() - anchorWeek) / (7 * 86400000),
        );
        if (weekIdx % interval === 0 && byDay.has(occ.getDay())) {
          if (!emit(occ)) break;
        }
      }
      if (occ > to && (!until || occ <= until)) break;
      day = new Date(day);
      day.setDate(day.getDate() + 1);
    }
  } else {
    let current = new Date(anchor);
    let safety = 0;
    while (safety < 6000) {
      safety++;
      if (until && current > until) break;
      if (current > to) break;
      if (!emit(current)) break;
      current = advanceDate(current, freq, interval);
    }
  }

  return out.sort((a, b) => a.getTime() - b.getTime());
}
