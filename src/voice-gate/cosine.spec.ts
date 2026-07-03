import { cosine } from './cosine';

describe('cosine', () => {
  it('same direction → 1', () => {
    expect(cosine([1, 0, 0], [1, 0, 0])).toBeCloseTo(1.0, 6);
  });

  it('orthogonal → 0', () => {
    expect(cosine([1, 0, 0], [0, 1, 0])).toBeCloseTo(0.0, 6);
  });

  it('opposite → -1', () => {
    expect(cosine([1, 0, 0], [-1, 0, 0])).toBeCloseTo(-1.0, 6);
  });

  it('partial overlap (1,1,0 vs 1,0,0) → 1/sqrt(2)', () => {
    expect(cosine([1, 1, 0], [1, 0, 0])).toBeCloseTo(1 / Math.sqrt(2), 6);
  });

  it('throws on length mismatch', () => {
    expect(() => cosine([1, 2], [1, 2, 3])).toThrow(/length/i);
  });

  it('returns 0 when either vector has zero norm', () => {
    expect(cosine([0, 0, 0], [1, 0, 0])).toBe(0);
    expect(cosine([1, 0, 0], [0, 0, 0])).toBe(0);
  });
});
