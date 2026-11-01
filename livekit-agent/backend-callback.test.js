// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { notifyAgentEnded } = require('./backend-callback');

const quietLog = { warn() {} };

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('posts the reason to the session endpoint with the shared secret', async () => {
  let got;
  const { server, url } = await serve((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      got = { method: req.method, path: req.url, secret: req.headers['x-interpreter-secret'], body: JSON.parse(raw) };
      res.end('{}');
    });
  });
  try {
    const r = await notifyAgentEnded({ backendUrl: `${url}/`, secret: 's3', sessionId: 'abc 1', reason: 'partner_left', log: quietLog });
    assert.deepStrictEqual(r, { ok: true, status: 200 });
    assert.deepStrictEqual(got, {
      method: 'POST',
      path: '/interpreter/internal/sessions/abc%201/agent-ended',
      secret: 's3',
      body: { reason: 'partner_left' },
    });
  } finally {
    server.close();
  }
});

test('an HTTP error is reported, not thrown', async () => {
  const { server, url } = await serve((req, res) => { res.statusCode = 500; res.end(); });
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', retries: 0, log: quietLog }),
      { ok: false, status: 500 },
    );
  } finally {
    server.close();
  }
});

test('an unreachable backend is reported, not thrown', async () => {
  const { server, url } = await serve(() => {});
  await new Promise((r) => server.close(r));
  assert.deepStrictEqual(
    await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', retries: 0, log: quietLog }),
    { ok: false, status: 0 },
  );
});

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
}

test('a backend that takes the connection and never answers is cut off at timeoutMs', async () => {
  const server = http.createServer(() => {});
  // Without our timeout the call would wait out fetch's own 300 s; this
  // closes the socket after 2 s so such a regression fails fast.
  server.timeout = 2000;
  const url = await listen(server);
  try {
    const started = Date.now();
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', timeoutMs: 150, retries: 0, log: quietLog }),
      { ok: false, status: 0 },
    );
    assert.ok(Date.now() - started < 1500);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test('a response that stalls after its headers does not keep the connection open', async () => {
  // The socket that carried the request, not every connection: after it
  // closes, Node 20's fetch opens one more idle connection of its own and
  // drops it about 3 s later.
  let requestSocketClosed = null;
  const server = http.createServer((req, res) => {
    requestSocketClosed = false;
    req.socket.on('close', () => { requestSocketClosed = true; });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"ok":true'); // and nothing more
  });
  const url = await listen(server);
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', timeoutMs: 1000, retries: 0, log: quietLog }),
      { ok: true, status: 200 },
    );
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.strictEqual(requestSocketClosed, true);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test('a body the fetchFn has already read does not change the outcome', async () => {
  const { server, url } = await serve((req, res) => res.end('{}'));
  const fetchFn = async (...args) => {
    const res = await fetch(...args);
    await res.text(); // cancel() on a read body rejects
    return res;
  };
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', fetchFn, retries: 0, log: quietLog }),
      { ok: true, status: 200 },
    );
  } finally {
    server.close();
  }
});

test('a fetchFn rejecting with a bare value is reported, not thrown', async () => {
  assert.deepStrictEqual(
    await notifyAgentEnded({
      backendUrl: 'http://127.0.0.1:1', secret: 's', sessionId: 'x', reason: 'r',
      fetchFn: async () => { throw undefined; }, retries: 0, log: quietLog,
    }),
    { ok: false, status: 0 },
  );
});

function counting() {
  const delays = [];
  return { delays, setTimer: (fn, ms) => { delays.push(ms); fn(); } };
}

test('a 5xx is retried once, after retryDelayMs', async () => {
  let hits = 0;
  const { server, url } = await serve((req, res) => {
    hits += 1;
    res.statusCode = hits === 1 ? 503 : 200;
    res.end('{}');
  });
  const { delays, setTimer } = counting();
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'partner_left', setTimer, log: quietLog }),
      { ok: true, status: 200 },
    );
    assert.strictEqual(hits, 2);
    assert.deepStrictEqual(delays, [1500]);
  } finally {
    server.close();
  }
});

test('a network error is retried once', async () => {
  const { server, url } = await serve((req, res) => res.end('{}'));
  let calls = 0;
  const fetchFn = (...args) => (++calls === 1 ? Promise.reject(new Error('blip')) : fetch(...args));
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'agent_lost', fetchFn, setTimer: counting().setTimer, log: quietLog }),
      { ok: true, status: 200 },
    );
    assert.strictEqual(calls, 2);
  } finally {
    server.close();
  }
});

test('after one retry it gives up and reports the last answer', async () => {
  let hits = 0;
  const { server, url } = await serve((req, res) => { hits += 1; res.statusCode = 500; res.end(); });
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', setTimer: counting().setTimer, log: quietLog }),
      { ok: false, status: 500 },
    );
    assert.strictEqual(hits, 2);
  } finally {
    server.close();
  }
});

test('a 4xx is not retried', async () => {
  let hits = 0;
  const { server, url } = await serve((req, res) => { hits += 1; res.statusCode = 401; res.end(); });
  const { delays, setTimer } = counting();
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', setTimer, log: quietLog }),
      { ok: false, status: 401 },
    );
    assert.strictEqual(hits, 1);
    assert.deepStrictEqual(delays, []);
  } finally {
    server.close();
  }
});
