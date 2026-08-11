import {
  generateInviteCode,
  inviteUnusable,
  normalizePublicUsername,
} from './invite.util';

describe('normalizePublicUsername', () => {
  it('accepts a normal handle and lowercases it', () => {
    // Хранить в одном регистре обязательно: иначе @News и @news — две разные
    // беседы, и ссылка ведёт не туда, куда человек набрал.
    expect(normalizePublicUsername('TalerNews')).toBe('talernews');
  });

  it('strips a leading @', () => {
    expect(normalizePublicUsername('@talernews')).toBe('talernews');
  });

  it('allows digits and underscores', () => {
    expect(normalizePublicUsername('taler_news_2026')).toBe('taler_news_2026');
  });

  it('rejects anything too short or too long', () => {
    expect(normalizePublicUsername('abcd')).toBeNull();
    expect(normalizePublicUsername('a'.repeat(33))).toBeNull();
  });

  it('rejects forbidden characters', () => {
    expect(normalizePublicUsername('taler news')).toBeNull();
    expect(normalizePublicUsername('taler-news')).toBeNull();
    expect(normalizePublicUsername('новости')).toBeNull();
    expect(normalizePublicUsername('taler.news')).toBeNull();
  });

  it('rejects a handle that starts with a digit or underscore', () => {
    // Так его не спутать с id и не сломать разбор упоминаний.
    expect(normalizePublicUsername('2026news')).toBeNull();
    expect(normalizePublicUsername('_news')).toBeNull();
  });

  it('rejects reserved words', () => {
    // Эти имена заняты маршрутами и служебными страницами.
    for (const w of ['admin', 'api', 'invite', 'oauth', 'support', 'talerid']) {
      expect(normalizePublicUsername(w)).toBeNull();
    }
  });

  it('rejects empty input', () => {
    expect(normalizePublicUsername('')).toBeNull();
    expect(normalizePublicUsername(null)).toBeNull();
    expect(normalizePublicUsername('@')).toBeNull();
  });
});

describe('generateInviteCode', () => {
  it('produces a code of the expected shape', () => {
    const code = generateInviteCode();
    expect(code).toMatch(/^[A-Za-z0-9_-]{16,}$/);
  });

  it('does not repeat itself', () => {
    // Код — единственное, что защищает беседу: предсказуемый пускает чужих.
    const seen = new Set(Array.from({ length: 500 }, () => generateInviteCode()));
    expect(seen.size).toBe(500);
  });
});

describe('inviteUnusable', () => {
  const now = new Date('2026-08-11T12:00:00Z');
  const base = { revokedAt: null, expiresAt: null, maxUses: null, uses: 0 };

  it('lets a fresh invite through', () => {
    expect(inviteUnusable(base, now)).toBeNull();
  });

  it('rejects a revoked invite', () => {
    expect(inviteUnusable({ ...base, revokedAt: new Date() }, now)).toBe('revoked');
  });

  it('rejects an expired invite', () => {
    expect(inviteUnusable({ ...base, expiresAt: new Date('2026-08-11T11:59:00Z') }, now))
      .toBe('expired');
  });

  it('accepts one that expires later', () => {
    expect(inviteUnusable({ ...base, expiresAt: new Date('2026-08-11T12:01:00Z') }, now))
      .toBeNull();
  });

  it('rejects one that ran out of uses', () => {
    expect(inviteUnusable({ ...base, maxUses: 3, uses: 3 }, now)).toBe('exhausted');
  });

  it('accepts one with uses left', () => {
    expect(inviteUnusable({ ...base, maxUses: 3, uses: 2 }, now)).toBeNull();
  });

  it('treats revocation as stronger than a remaining use', () => {
    expect(inviteUnusable({ ...base, revokedAt: new Date(), maxUses: 10, uses: 0 }, now))
      .toBe('revoked');
  });
});
