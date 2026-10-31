'use strict';
/**
 * What the interpreter tells the two phones over the LiveKit data channel,
 * topic `interp`, always addressed — a caption is for its listener (or, for
 * the speaker's own recognised text, for the speaker), never broadcast.
 *
 *   caption  { role: 'translation' | 'source', speaker, text, final }
 *            simultaneous engine: deltas, final=false (the phone breaks lines
 *            on a pause); phrase engine: whole phrases, final=true
 *   speaking { speaker, on }  — the gate started / stopped letting them through
 *   status   { state: 'reconnecting' | 'ok' | 'failed' }
 */
const TOPIC = 'interp';

const caption = (role, speaker, text, final) => ({ type: 'caption', role, speaker, text, final: Boolean(final) });
const speaking = (speaker, on) => ({ type: 'speaking', speaker, on: Boolean(on) });
const status = (state) => ({ type: 'status', state });

async function send(localParticipant, identities, msg) {
  // An empty destination list is a broadcast in LiveKit. Anything but a
  // non-empty array of identities — a Set (no .length), null, blanks — is
  // nobody to send to.
  const list = Array.isArray(identities) ? identities.filter(Boolean) : [];
  if (!localParticipant || list.length === 0) return false;
  await localParticipant.publishData(Buffer.from(JSON.stringify(msg)), {
    reliable: true,
    topic: TOPIC,
    destination_identities: list,
  });
  return true;
}

module.exports = { TOPIC, caption, speaking, status, send };
