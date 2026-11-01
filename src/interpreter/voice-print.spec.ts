import {
  SAME_PRINT_COSINE,
  VOICE_PRINT_DIM,
  hasUsableVoicePrint,
} from './voice-print';

// The agent's own rules, which these constants copy (see voice-print.ts).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const agentRouting = require('../../livekit-agent/interpreter-routing.js') as {
  EMBEDDING_DIM: number;
  SAME_PRINT_COSINE: number;
};

const print = (value: number) => Array<number>(VOICE_PRINT_DIM).fill(value);

describe('voice print rules: the copy matches the agent', () => {
  it('uses the print length and same-print threshold of the agent', () => {
    expect(VOICE_PRINT_DIM).toBe(agentRouting.EMBEDDING_DIM);
    expect(SAME_PRINT_COSINE).toBe(agentRouting.SAME_PRINT_COSINE);
  });
});

describe('hasUsableVoicePrint', () => {
  it('accepts 192 finite numbers with a length', () => {
    expect(VOICE_PRINT_DIM).toBe(192);
    expect(hasUsableVoicePrint(print(0.07))).toBe(true);
    expect(hasUsableVoicePrint([1, ...print(0).slice(1)])).toBe(true);
  });

  it('refuses the empty default and anything that is not an array', () => {
    for (const e of [[], null, undefined, 'x', 42, { length: 192 }]) {
      expect(hasUsableVoicePrint(e)).toBe(false);
    }
  });

  it('refuses a print of the wrong length', () => {
    expect(hasUsableVoicePrint(print(0.1).slice(1))).toBe(false);
    expect(hasUsableVoicePrint([...print(0.1), 0.1])).toBe(false);
  });

  it('refuses non-finite and non-numeric elements, and holes', () => {
    for (const bad of [NaN, Infinity, -Infinity, '0.1', null]) {
      const e: unknown[] = print(0.1);
      e[100] = bad;
      expect(hasUsableVoicePrint(e)).toBe(false);
    }
    expect(hasUsableVoicePrint(new Array(VOICE_PRINT_DIM))).toBe(false);
  });

  it('refuses a print with no length: all zeros', () => {
    expect(hasUsableVoicePrint(print(0))).toBe(false);
  });

  it('refuses prints whose squares underflow or overflow, which Math.hypot would pass', () => {
    const tiny = print(1e-170);
    const huge = print(1e170);
    // The point of not using hypot: it rescales and reports a usable length.
    expect(Math.hypot(...tiny)).toBeGreaterThan(0);
    expect(Number.isFinite(Math.hypot(...huge))).toBe(true);

    expect(hasUsableVoicePrint(tiny)).toBe(false);
    expect(hasUsableVoicePrint(huge)).toBe(false);
  });
});
