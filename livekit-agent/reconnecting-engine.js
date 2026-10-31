'use strict';
/**
 * Keeps one translation engine alive for a whole conversation. If OpenAI
 * drops the socket, it reconnects after 1, 2 and 4 seconds and gives up after
 * the third failure in a row; a successful reconnect starts that count over.
 * A session that keeps dropping right after it comes up never fails three
 * times in a row, so drops are also counted for the whole conversation and
 * past maxDrops (20) the wrapper gives up: endless reconnects would bill
 * OpenAI for a conversation that is effectively dead.
 * Audio that arrives while there is no socket is dropped: a translation of the
 * gap arriving later would be worse than none.
 *
 * factory({ onReady, onClose }) → { sendAudio, close }; onClose({ unexpected })
 * tells a dropped socket from one we closed. Statuses: 'reconnecting', 'ok'
 * (back after reconnecting), 'failed' (gave up — the caller ends the session).
 * Signals from an engine that is no longer the current one are ignored: a
 * second onClose, or an onReady after close(), must not schedule another
 * connection or report a status.
 */
function createReconnectingEngine({
  factory,
  delaysMs = [1000, 2000, 4000],
  maxDrops = 20,
  onStatus = () => {},
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  log = console,
}) {
  let engine = null;
  let closed = false;
  let failures = 0;
  let drops = 0;
  let timer = null;
  let reconnecting = false;
  let failed = false;

  // onStatus reaches into the interpreter (broadcast, ending the session); a
  // throw there must not escape from a timer and take the agent down.
  function status(state) {
    try {
      onStatus(state);
    } catch (e) {
      log.error(`[INTERPRETER] reconnecting engine: onStatus(${state}) failed: ${e.message}`);
    }
  }

  function connect() {
    let self = null;
    self = factory({
      onReady: () => {
        if (engine !== self) return; // closed by us or superseded
        failures = 0;
        if (reconnecting) {
          reconnecting = false;
          status('ok');
        }
      },
      onClose: ({ unexpected }) => {
        if (engine !== self) return; // already handled, or closed by us
        engine = null;
        if (closed || !unexpected) return;
        retry();
      },
    });
    engine = self;
  }

  function retry() {
    drops += 1;
    if (failures >= delaysMs.length || drops > maxDrops) {
      if (!failed) {
        failed = true;
        status('failed');
      }
      return;
    }
    const delay = delaysMs[failures];
    failures += 1;
    if (!reconnecting) {
      reconnecting = true;
      status('reconnecting');
    }
    timer = setTimer(() => {
      timer = null;
      if (closed) return;
      try {
        connect();
      } catch (e) {
        // E.g. the socket constructor refusing a bad URL. Uncaught, this would
        // be an exception inside a timer; it is a failed attempt instead.
        log.error(`[INTERPRETER] reconnecting engine: reconnect failed: ${e.message}`);
        retry();
      }
    }, delay);
  }

  connect();

  return {
    sendAudio(int16) {
      if (engine) engine.sendAudio(int16);
    },
    close() {
      closed = true;
      if (timer) clearTimer(timer);
      timer = null;
      const current = engine;
      engine = null;
      if (current) current.close();
    },
  };
}

module.exports = { createReconnectingEngine };
