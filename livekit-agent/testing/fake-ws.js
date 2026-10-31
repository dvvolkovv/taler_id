'use strict';
// Stand-in for a `ws` WebSocket in unit tests. It records what the code under
// test sends (parsed back from JSON) and lets the test play the server.
// readyState follows the `ws` constants: 0 CONNECTING, 1 OPEN, 3 CLOSED.
const { EventEmitter } = require('events');

class FakeWs extends EventEmitter {
  constructor(url, options) {
    super();
    this.url = url;
    this.options = options;
    this.sent = [];
    this.readyState = 0;
  }

  send(data) {
    this.sent.push(JSON.parse(data));
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.emit('close', 1000, Buffer.alloc(0));
  }

  // ── the test's side ──

  open() {
    this.readyState = 1;
    this.emit('open');
  }

  serverSends(event) {
    this.emit('message', Buffer.from(JSON.stringify(event)));
  }

  serverCloses(code = 1006) {
    this.readyState = 3;
    this.emit('close', code, Buffer.alloc(0));
  }

  sentOfType(type) {
    return this.sent.filter((m) => m.type === type);
  }
}

/** A wsFactory that keeps every socket it made, newest last. */
function fakeWsFactory() {
  const sockets = [];
  const factory = (url, options) => {
    const ws = new FakeWs(url, options);
    sockets.push(ws);
    return ws;
  };
  return { factory, sockets, last: () => sockets[sockets.length - 1] };
}

module.exports = { FakeWs, fakeWsFactory };
