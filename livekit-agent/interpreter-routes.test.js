// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const { registerInterpreterRoutes } = require('./interpreter-routes');

async function app(handlers, secret = 's3cret') {
  const a = express();
  a.use(express.json());
  registerInterpreterRoutes(a, { secret, ...handlers });
  return new Promise((resolve) => {
    const server = a.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

const json = (body) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-interpreter-secret': 's3cret' },
  body: JSON.stringify(body),
});

test('without the right secret nothing runs', async () => {
  let called = false;
  const { server, url } = await app({ start: async () => { called = true; } });
  try {
    const none = await fetch(`${url}/interpreter/start`, { method: 'POST' });
    const wrong = await fetch(`${url}/interpreter/start`, { method: 'POST', headers: { 'x-interpreter-secret': 'nope' } });
    assert.deepStrictEqual([none.status, wrong.status], [401, 401]);
    assert.strictEqual(called, false);
  } finally {
    server.close();
  }
});

test('with no secret configured the routes refuse to work', async () => {
  const { server, url } = await app({}, '');
  try {
    assert.strictEqual((await fetch(`${url}/interpreter/selftest`)).status, 503);
  } finally {
    server.close();
  }
});

test('start passes the body through and maps a 400 from the interpreter', async () => {
  const seen = [];
  const { server, url } = await app({
    start: async (body) => {
      seen.push(body);
      if (body.bad) {
        const e = new Error('exactly two participants required');
        e.statusCode = 400;
        throw e;
      }
      return { status: 'started' };
    },
  });
  try {
    const ok = await fetch(`${url}/interpreter/start`, json({ roomName: 'r' }));
    assert.deepStrictEqual([ok.status, await ok.json()], [200, { status: 'started' }]);
    const bad = await fetch(`${url}/interpreter/start`, json({ bad: true }));
    assert.deepStrictEqual([bad.status, await bad.json()], [400, { error: 'exactly two participants required' }]);
    assert.deepStrictEqual(seen, [{ roomName: 'r' }, { bad: true }]);
  } finally {
    server.close();
  }
});

test('stop needs a room name', async () => {
  const { server, url } = await app({ stop: async (roomName) => ({ status: 'stopped', roomName }) });
  try {
    assert.strictEqual((await fetch(`${url}/interpreter/stop`, json({}))).status, 400);
    const ok = await fetch(`${url}/interpreter/stop`, json({ roomName: 'r1' }));
    assert.deepStrictEqual(await ok.json(), { status: 'stopped', roomName: 'r1' });
  } finally {
    server.close();
  }
});

test('status answers for the room in the path', async () => {
  const { server, url } = await app({ status: (roomName) => ({ running: false, roomName }) });
  try {
    const res = await fetch(`${url}/interpreter/status/interp-1`, { headers: { 'x-interpreter-secret': 's3cret' } });
    assert.deepStrictEqual(await res.json(), { running: false, roomName: 'interp-1' });
  } finally {
    server.close();
  }
});

test('selftest reports how long it took', async () => {
  const { server, url } = await app({ selftest: async () => ({ ok: true, reason: 'fine' }) });
  try {
    const body = await (await fetch(`${url}/interpreter/selftest`, { headers: { 'x-interpreter-secret': 's3cret' } })).json();
    assert.strictEqual(body.ok, true);
    assert.strictEqual(typeof body.latencyMs, 'number');
  } finally {
    server.close();
  }
});

test('every route is behind the guard, not just start', async () => {
  const calls = { stop: false, status: false, selftest: false };
  const { server, url } = await app({
    stop: async () => { calls.stop = true; return { status: 'stopped' }; },
    status: () => { calls.status = true; return { running: false }; },
    selftest: async () => { calls.selftest = true; return { ok: true }; },
  });
  const body = JSON.stringify({ roomName: 'r' });
  try {
    const answers = await Promise.all([
      fetch(`${url}/interpreter/stop`, { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
      fetch(`${url}/interpreter/status/r`),
      fetch(`${url}/interpreter/selftest`),
      fetch(`${url}/interpreter/stop`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-interpreter-secret': 'nope' }, body }),
      fetch(`${url}/interpreter/status/r`, { headers: { 'x-interpreter-secret': 'nope' } }),
      fetch(`${url}/interpreter/selftest`, { headers: { 'x-interpreter-secret': 'nope' } }),
    ]);
    assert.deepStrictEqual(answers.map((r) => r.status), [401, 401, 401, 401, 401, 401]);
    assert.deepStrictEqual(calls, { stop: false, status: false, selftest: false });
  } finally {
    server.close();
  }
});

test('a failing status is a JSON error, not an HTML page with the stack', async () => {
  const { server, url } = await app({ status: () => { throw new Error('unexpected session state'); } });
  try {
    const res = await fetch(`${url}/interpreter/status/r`, { headers: { 'x-interpreter-secret': 's3cret' } });
    assert.strictEqual(res.status, 500);
    assert.match(res.headers.get('content-type') || '', /application\/json/);
    assert.deepStrictEqual(await res.json(), { error: 'unexpected session state' });
  } finally {
    server.close();
  }
});

test('a failing stop is a JSON error', async () => {
  const { server, url } = await app({ stop: async () => { throw new Error('room disconnect failed'); } });
  try {
    const res = await fetch(`${url}/interpreter/stop`, json({ roomName: 'r' }));
    assert.deepStrictEqual([res.status, await res.json()], [500, { error: 'room disconnect failed' }]);
  } finally {
    server.close();
  }
});

test('a failing selftest still reports how long it took', async () => {
  const { server, url } = await app({ selftest: async () => { throw new Error('OpenAI unreachable'); } });
  try {
    const res = await fetch(`${url}/interpreter/selftest`, { headers: { 'x-interpreter-secret': 's3cret' } });
    const body = await res.json();
    assert.deepStrictEqual([res.status, body.ok, body.reason, typeof body.latencyMs], [500, false, 'OpenAI unreachable', 'number']);
  } finally {
    server.close();
  }
});
