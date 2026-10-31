'use strict';
/**
 * Who of the two is in the room, by person rather than device, and when one
 * of them has been away too long. Each person gets the grace period from the
 * start too — someone who scanned the code but never connected ends the
 * conversation the same way as someone whose phone lost the network.
 *
 * Also the address book for data messages: a person's current identities
 * (userId#device) are where their captions go.
 *
 * A set of identities per person, not a counter. @livekit/rtc-node reports one
 * identity's arrivals and departures strictly in turn: a reconnect that
 * replaces a participant (same identity, new sid) arrives as Disconnected and
 * then Connected, and the Room throws rather than emit a second Connected for
 * an identity it still holds. arrive() itself can be called twice for one
 * participant (the event, then the snapshot of the room taken after connect),
 * and a counter would never come back down to zero.
 */
const { baseIdentity } = require('./translator-targets');

function createPresenceWatch({
  people,
  graceMs,
  onGone,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  log = console,
}) {
  const present = new Map(people.map((p) => [p, new Set()]));
  const timers = new Map();
  let closed = false;

  function startClock(person) {
    if (closed || timers.has(person)) return;
    timers.set(person, setTimer(() => {
      timers.delete(person);
      if (closed) return;
      // onGone ends the conversation. Called from a timer, a throw would be an
      // uncaught exception and take the whole agent process down.
      try {
        onGone(person);
      } catch (e) {
        log.error(`[INTERPRETER] presence watch: onGone(${person}) failed: ${e && e.message}`);
      }
    }, graceMs));
  }

  for (const p of people) startClock(p);

  return {
    arrive(identity) {
      const person = baseIdentity(identity);
      const devices = present.get(person);
      if (closed || !devices) return;
      devices.add(identity);
      const t = timers.get(person);
      if (t) {
        clearTimer(t);
        timers.delete(person);
      }
    },
    leave(identity) {
      const person = baseIdentity(identity);
      const devices = present.get(person);
      if (closed || !devices) return;
      devices.delete(identity);
      if (devices.size === 0) startClock(person);
    },
    identitiesOf(person) {
      return [...(present.get(person) || [])];
    },
    presentPeople() {
      return people.filter((p) => present.get(p).size > 0);
    },
    close() {
      closed = true;
      for (const t of timers.values()) clearTimer(t);
      timers.clear();
    },
  };
}

module.exports = { createPresenceWatch };
