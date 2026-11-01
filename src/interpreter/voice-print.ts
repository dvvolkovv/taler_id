/** Length of an ECAPA voice print, as stored in Profile.ownerEmbedding. */
export const VOICE_PRINT_DIM = 192;

/**
 * Two prints at least this alike (cosine) leave the voice gate nothing to
 * tell apart: one person behind two accounts, or a broken enrollment.
 * Different people's prints sit far below it; a copy, rescaled or not, at 1.
 * Mirrors SAME_PRINT_COSINE in livekit-agent/interpreter-routing.js, which
 * refuses such a pair — but only after the host's billing has opened.
 */
export const SAME_PRINT_COSINE = 0.99;

/**
 * Whether the agent's voice gate can score speech against this print.
 *
 * The same rule as checkPerson in livekit-agent/interpreter-routing.js: the
 * agent refuses any other print, but by then the host's billing is open, so
 * the backend refuses first. A sum of squares, not Math.hypot: hypot rescales
 * internally and reports a usable length for prints whose squares underflow to
 * 0 or overflow to Infinity — the very prints the agent's cosine cannot use.
 */
export function hasUsableVoicePrint(e: unknown): e is number[] {
  if (!Array.isArray(e) || e.length !== VOICE_PRINT_DIM) return false;
  let sumOfSquares = 0;
  // An index loop, not every(): every() skips holes.
  for (let i = 0; i < VOICE_PRINT_DIM; i++) {
    const v: unknown = e[i];
    if (typeof v !== 'number' || !Number.isFinite(v)) return false;
    sumOfSquares += v * v;
  }
  return sumOfSquares > 0 && Number.isFinite(sumOfSquares);
}
