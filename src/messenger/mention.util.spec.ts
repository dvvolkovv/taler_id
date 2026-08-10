import { extractMentionHandles, resolveMentions } from './mention.util';

describe('extractMentionHandles', () => {
  it('finds a plain mention', () => {
    expect(extractMentionHandles('привет @anna, глянь')).toEqual(['anna']);
  });

  it('finds several and de-duplicates them', () => {
    expect(extractMentionHandles('@anna @boris @anna')).toEqual(['anna', 'boris']);
  });

  it('is case-insensitive on the handle', () => {
    // Логины в базе в своём регистре; сравнивать надо по нижнему.
    expect(extractMentionHandles('@Anna и @ANNA')).toEqual(['anna']);
  });

  it('ignores an email address', () => {
    // Классический ложный положительный: почта содержит @ и похожа на упоминание.
    expect(extractMentionHandles('пиши на anna@taler.test')).toEqual([]);
  });

  it('ignores a bare @', () => {
    expect(extractMentionHandles('собака @ и всё')).toEqual([]);
  });

  it('stops the handle at punctuation', () => {
    expect(extractMentionHandles('@anna, @boris. @carl!')).toEqual(['anna', 'boris', 'carl']);
  });

  it('accepts underscores and digits', () => {
    expect(extractMentionHandles('@ivan_2026 тут')).toEqual(['ivan_2026']);
  });

  it('ignores a handle that is too short to be a username', () => {
    expect(extractMentionHandles('@a')).toEqual([]);
  });

  it('caps an absurdly long run instead of taking it whole', () => {
    const out = extractMentionHandles('@' + 'a'.repeat(200));
    expect(out).toHaveLength(1);
    expect(out[0].length).toBeLessThanOrEqual(32);
  });

  it('handles a mention at the very start and very end', () => {
    expect(extractMentionHandles('@anna')).toEqual(['anna']);
    expect(extractMentionHandles('спроси @boris')).toEqual(['boris']);
  });

  it('returns nothing for empty or missing content', () => {
    expect(extractMentionHandles('')).toEqual([]);
    expect(extractMentionHandles(null as any)).toEqual([]);
  });
});

describe('resolveMentions', () => {
  const participants = [
    { userId: 'u-anna', username: 'anna' },
    { userId: 'u-boris', username: 'Boris' },
    { userId: 'u-noname', username: null },
  ];

  it('maps handles to participant ids', () => {
    expect(resolveMentions('привет @anna', participants, 'u-me')).toEqual(['u-anna']);
  });

  it('matches regardless of the stored casing', () => {
    expect(resolveMentions('@boris глянь', participants, 'u-me')).toEqual(['u-boris']);
  });

  it('ignores handles that belong to nobody in this conversation', () => {
    // Иначе упоминанием можно было бы пробить пуш постороннему.
    expect(resolveMentions('@stranger привет', participants, 'u-me')).toEqual([]);
  });

  it('does not mention the author themselves', () => {
    // Собственное упоминание — это уведомление самому себе.
    expect(resolveMentions('@anna пишу сам', participants, 'u-anna')).toEqual([]);
  });

  it('survives participants without a username', () => {
    expect(() => resolveMentions('@anna', participants, 'u-me')).not.toThrow();
  });

  it('returns an empty array when there is nothing to resolve', () => {
    expect(resolveMentions('обычный текст', participants, 'u-me')).toEqual([]);
  });
});
