import {
  generatePartnerKey,
  hashPartnerKey,
  parsePartnerKey,
  partnerKeyMatches,
} from './partner-key.util';

describe('partner key', () => {
  it('generates tidp_<slug>_<secret> and parses the slug back', () => {
    const key = generatePartnerKey('nadi');
    expect(key).toMatch(/^tidp_nadi_[A-Za-z0-9_-]{43}$/);
    expect(parsePartnerKey(key)).toEqual({ slug: 'nadi' });
  });

  it('takes the slug up to the first underscore even if the secret has underscores', () => {
    expect(parsePartnerKey('tidp_nadi_abc_def_ghi_jkl_mno_pqr_stu_vwx_yz0123')).toEqual({ slug: 'nadi' });
  });

  it.each(['', 'nadi_x', 'tidp_', 'tidp__secret', `tidp_NADI_${'a'.repeat(43)}`, 'tidp_nadi_short'])(
    'rejects malformed key %p',
    (key: string) => {
      expect(parsePartnerKey(key)).toBeNull();
    },
  );

  it('matches only the exact key', () => {
    const key = generatePartnerKey('nadi');
    const hash = hashPartnerKey(key);
    expect(partnerKeyMatches(key, hash)).toBe(true);
    expect(partnerKeyMatches(`${key}x`, hash)).toBe(false);
    expect(partnerKeyMatches(key, 'not-hex')).toBe(false);
  });

  it('refuses to generate a key for an invalid slug', () => {
    expect(() => generatePartnerKey('Bad_Slug')).toThrow('invalid partner slug');
  });
});
