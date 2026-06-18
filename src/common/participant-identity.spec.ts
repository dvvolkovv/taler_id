import {
  makeParticipantIdentity,
  parseUserId,
} from './participant-identity';

describe('participant-identity', () => {
  const user = 'b1bbfab5-74d7-4659-8c4c-d19b4a033a2d';

  it('returns the bare userId when no session is given (legacy/back-compat)', () => {
    expect(makeParticipantIdentity(user)).toBe(user);
  });

  it('appends a stable 8-char device hash for a session', () => {
    const id = makeParticipantIdentity(user, 'session-AAA');
    expect(id.startsWith(`${user}#`)).toBe(true);
    expect(id.split('#')[1]).toHaveLength(8);
    // deterministic per session (so a same-device reconnect reuses the identity)
    expect(makeParticipantIdentity(user, 'session-AAA')).toBe(id);
  });

  it('produces distinct identities for different sessions (devices)', () => {
    expect(makeParticipantIdentity(user, 'session-AAA')).not.toBe(
      makeParticipantIdentity(user, 'session-BBB'),
    );
  });

  it('does not leak the raw session id', () => {
    expect(makeParticipantIdentity(user, 'session-AAA')).not.toContain(
      'session-AAA',
    );
  });

  it('parseUserId recovers the bare userId from a device identity', () => {
    expect(parseUserId(makeParticipantIdentity(user, 'session-AAA'))).toBe(user);
  });

  it('parseUserId leaves bare / agent / guest / listener identities unchanged', () => {
    expect(parseUserId(user)).toBe(user);
    expect(parseUserId('ai-assistant')).toBe('ai-assistant');
    expect(parseUserId('meeting-recorder')).toBe('meeting-recorder');
    expect(parseUserId('guest-1a2b3c4d')).toBe('guest-1a2b3c4d');
    expect(parseUserId('listener-' + user)).toBe('listener-' + user);
  });
});
