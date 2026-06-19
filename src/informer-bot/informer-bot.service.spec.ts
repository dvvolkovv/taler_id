import { InformerBotService } from './informer-bot.service';

// We exercise the helper via a tiny subclass that exposes it.
class TestableService extends InformerBotService {
  constructor() {
    super(null as any, null as any, null as any, null as any);
  }
  public _nextMorningInBerlin(now?: Date): Date {
    return (this as any).nextMorningInBerlin(now);
  }
}

describe('InformerBotService.nextMorningInBerlin', () => {
  const svc = new TestableService();

  function berlinHourOf(d: Date): number {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Europe/Berlin',
      hour: 'numeric',
      hour12: false,
    }).formatToParts(d);
    return parseInt(parts.find((p) => p.type === 'hour')!.value, 10);
  }

  it('result is exactly 09:00 Berlin time', () => {
    const out = svc._nextMorningInBerlin(new Date('2026-06-19T06:00:00Z'));
    expect(berlinHourOf(out)).toBe(9);
  });

  it('when called before 9 AM Berlin, returns today 09:00 Berlin', () => {
    // 2026-06-19 06:00 UTC = 08:00 CEST (summer +2). Berlin 08:00 < 09:00 → today.
    const out = svc._nextMorningInBerlin(new Date('2026-06-19T06:00:00Z'));
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Europe/Berlin',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(out);
    const get = (t: string) => parts.find((p) => p.type === t)!.value;
    expect(`${get('year')}-${get('month')}-${get('day')}`).toBe('2026-06-19');
  });

  it('when called after 9 AM Berlin, returns tomorrow 09:00 Berlin', () => {
    // 2026-06-19 12:00 UTC = 14:00 CEST → after 09:00 → tomorrow.
    const out = svc._nextMorningInBerlin(new Date('2026-06-19T12:00:00Z'));
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Europe/Berlin',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(out);
    const get = (t: string) => parts.find((p) => p.type === t)!.value;
    expect(`${get('year')}-${get('month')}-${get('day')}`).toBe('2026-06-20');
  });

  it('handles DST: winter morning resolves to 09:00 CET (UTC+1)', () => {
    // 2026-01-15 06:00 UTC = 07:00 CET → before 09:00 → today.
    const out = svc._nextMorningInBerlin(new Date('2026-01-15T06:00:00Z'));
    expect(berlinHourOf(out)).toBe(9);
    expect(out.toISOString()).toBe('2026-01-15T08:00:00.000Z'); // 09:00 CET = 08:00 UTC
  });

  it('handles DST: summer morning resolves to 09:00 CEST (UTC+2)', () => {
    const out = svc._nextMorningInBerlin(new Date('2026-07-15T05:00:00Z'));
    expect(berlinHourOf(out)).toBe(9);
    expect(out.toISOString()).toBe('2026-07-15T07:00:00.000Z'); // 09:00 CEST = 07:00 UTC
  });
});

describe('InformerBotService.parseActionCode (refill codes)', () => {
  const svc = new TestableService();

  const cases: [string, string][] = [
    ['REFILL_ACK', '✅ Понял, работаю'],
    ['REFILL_SNOOZE_1H', '🔕 Заглушить 1 час'],
    ['REFILL_SNOOZE_MORNING', '🔕 До утра 9:00'],
    ['REFILL_DISABLE', '🔇 Совсем отключить'],
    ['REFILL_ENABLE', '🔔 Включить обратно'],
    ['REFILL_SETTINGS', '⚙️ Настройки алёртов'],
  ];

  for (const [code, label] of cases) {
    it(`recognises human label "${label}" → ${code}`, () => {
      expect(svc.parseActionCode(label)).toBe(code);
    });
    it(`recognises raw code "${code}"`, () => {
      expect(svc.parseActionCode(code)).toBe(code);
    });
  }
});
