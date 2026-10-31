'use strict';
// Stand-in for a `ws` WebSocket in unit tests. It records what the code under
// test sends (parsed back from JSON) and lets the test play the server.
//
// Kept close to `ws` 8 where the code under test can tell the difference:
// close() on an open socket reports 1005 (no status received), and on a
// socket still connecting emits 'error' (synchronously, inside close()) and
// then 'close' with 1006; a socket closes once. Stricter than `ws` on
// purpose: send() throws unless the socket is open, while `ws` throws only
// while connecting and silently drops a send after close — real code must
// check readyState, never rely on that throw. Not copied: real `ws` closes
// asynchronously through CLOSING (2), the fake closes on the spot.
const { EventEmitter } = require('events');

class FakeWs extends EventEmitter {
  constructor(url, options) {
    super();
    this.url = url;
    this.options = options;
    this.sent = [];
    this.readyState = FakeWs.CONNECTING;
  }

  send(data) {
    if (this.readyState !== FakeWs.OPEN) {
      throw new Error(`WebSocket is not open: readyState ${this.readyState}`);
    }
    this.sent.push(JSON.parse(data));
  }

  close(code) {
    if (this.readyState === FakeWs.CLOSED) return;
    const wasConnecting = this.readyState === FakeWs.CONNECTING;
    this.readyState = FakeWs.CLOSED;
    if (wasConnecting) {
      this.emit('error', new Error('WebSocket was closed before the connection was established'));
      this.emit('close', 1006, Buffer.alloc(0));
      return;
    }
    this.emit('close', code ?? 1005, Buffer.alloc(0));
  }

  terminate() {
    if (this.readyState === FakeWs.CLOSED) return;
    this.readyState = FakeWs.CLOSED;
    this.emit('close', 1006, Buffer.alloc(0));
  }

  // ── the test's side ──

  open() {
    this.readyState = FakeWs.OPEN;
    this.emit('open');
  }

  serverSends(event) {
    this.emit('message', Buffer.from(JSON.stringify(event)));
  }

  serverCloses(code = 1006) {
    if (this.readyState === FakeWs.CLOSED) return;
    this.readyState = FakeWs.CLOSED;
    this.emit('close', code, Buffer.alloc(0));
  }

  sentOfType(type) {
    return this.sent.filter((m) => m.type === type);
  }
}
FakeWs.CONNECTING = 0;
FakeWs.OPEN = 1;
FakeWs.CLOSING = 2;
FakeWs.CLOSED = 3;

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
