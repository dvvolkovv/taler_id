'use strict';
/**
 * Keeps one translation engine alive for a whole conversation. If OpenAI
 * drops the socket, it reconnects after 1, 2 and 4 seconds and gives up after
 * the third failure in a row; a successful reconnect starts the count over.
 * Audio that arrives while there is no socket is dropped: a translation of the
 * gap arriving later would be worse than none.
 *
 * factory({ onReady, onClose }) → { sendAudio, close }; onClose({ unexpected })
 * tells a dropped socket from one we closed. Statuses: 'reconnecting', 'ok'
 * (back after reconnecting), 'failed' (gave up — the caller ends the session).
 */
function createReconnectingEngine({
  factory,
  delaysMs = [1000, 2000, 4000],
  onStatus = () => {},
  setTimer = setTimeout,
  clearTimer = clearTimeout,
}) {
  let engine = null;
  let closed = false;
  let failures = 0;
  let timer = null;
  let reconnecting = false;

  function connect() {
    let self = null;
    self = factory({
      onReady: () => {
        failures = 0;
        if (reconnecting) {
          reconnecting = false;
          onStatus('ok');
        }
      },
      onClose: ({ unexpected }) => {
        if (engine === self) engine = null;
        if (closed || !unexpected) return;
        retry();
      },
    });
    engine = self;
  }

  function retry() {
    if (failures >= delaysMs.length) {
      onStatus('failed');
      return;
    }
    const delay = delaysMs[failures];
    failures += 1;
    if (!reconnecting) {
      reconnecting = true;
      onStatus('reconnecting');
    }
    timer = setTimer(() => {
      timer = null;
      if (!closed) connect();
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
