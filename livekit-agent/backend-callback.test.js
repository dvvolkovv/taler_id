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
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', log: quietLog }),
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
    await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', log: quietLog }),
    { ok: false, status: 0 },
  );
});
