import { createHash } from 'crypto';

/**
 * LiveKit participant identity for a human caller/callee.
 *
 * LiveKit uses the participant *identity* as a unique key within a room: two
 * connections with the same identity collide (`DUPLICATE_IDENTITY`) and kick
 * each other. Using the bare `userId` therefore breaks multi-device — the same
 * account logged in on a phone + tablet + PC can't coexist in a call, and they
 * fight in a reconnect loop.
 *
 * We make the identity device-unique by appending a short, stable hash of the
 * caller's session id: `${userId}#${deviceHash}`.
 *   - Distinct per device (each login session is a device) → no cross-device kick.
 *   - Stable per session → a same-device reconnect reuses the identity, so
 *     LiveKit cleanly replaces the old connection instead of leaving a ghost.
 *   - The raw session id is hashed (not exposed) — the call peer only sees an
 *     opaque 8-char tag, never the session token.
 *
 * Agents (`ai-assistant`, `meeting-recorder`, `voice-translator`), guests
 * (`guest-…`) and listeners (`listener-…`) keep their own bare identities (no
 * `#`), so [parseUserId] leaves them untouched.
 */
export function makeParticipantIdentity(
  userId: string,
  sessionId?: string,
): string {
  if (!sessionId) return userId;
  const deviceHash = createHash('sha256')
    .update(sessionId)
    .digest('hex')
    .slice(0, 8);
  return `${userId}#${deviceHash}`;
}

/**
 * Recover the bare `userId` from a participant identity produced by
 * [makeParticipantIdentity]. Safe for legacy bare-userId identities and for
 * agent/guest/listener identities (returns them unchanged when there's no `#`).
 */
export function parseUserId(identity: string): string {
  const i = identity.indexOf('#');
  return i === -1 ? identity : identity.slice(0, i);
}
