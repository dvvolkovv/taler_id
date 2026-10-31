// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { createVoiceEmbedClient, cosine } = require('./voice-embed-client');

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}
function body(req) {
  return new Promise((resolve) => {
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts)));
  });
}
function stop(server) {
  server.closeAllConnections();
  return new Promise((r) => server.close(r));
}

test('a PCM window goes out as a WAV file and the vector comes back', async () => {
  let got;
  const { server, url } = await serve(async (req, res) => {
    got = { path: req.url, type: req.headers['content-type'], body: await body(req) };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ vector: [0.1, 0.2], dim: 2 }));
  });
  try {
    const client = createVoiceEmbedClient({ baseUrl: `${url}/`, timeoutMs: 1000 });
    assert.deepStrictEqual(await client.embedPcm(new Int16Array(2400), 24000), [0.1, 0.2]);
    assert.strictEqual(got.path, '/embed');
    assert.match(got.type, /^multipart\/form-data/);
    const text = got.body.toString('latin1');
    assert.match(text, /name="audio"; filename="audio.wav"/);
    assert.ok(text.includes('RIFF'));
    assert.ok(!text.includes('window_sec'));
  } finally {
    await stop(server);
  }
});

test('windowSec is passed for enrollment-style averaging', async () => {
  let text;
  const { server, url } = await serve(async (req, res) => {
    text = (await body(req)).toString('latin1');
    res.end(JSON.stringify({ vector: [1] }));
  });
  try {
    await createVoiceEmbedClient({ baseUrl: url }).embedWav(Buffer.from('RIFFxxxx'), { windowSec: 3, timeout: 1000 });
    assert.match(text, /name="window_sec"\r\n\r\n3\r\n/);
  } finally {
    await stop(server);
  }
});

test('an HTTP error is an error', async () => {
  const { server, url } = await serve((req, res) => { res.statusCode = 422; res.end('{"detail":"audio_too_short"}'); });
  try {
    await assert.rejects(createVoiceEmbedClient({ baseUrl: url, timeoutMs: 1000 }).embedPcm(new Int16Array(10), 24000), /HTTP 422/);
  } finally {
    await stop(server);
  }
});

test('an empty vector is an error', async () => {
  const { server, url } = await serve((req, res) => res.end('{"vector":[]}'));
  try {
    await assert.rejects(createVoiceEmbedClient({ baseUrl: url, timeoutMs: 1000 }).embedPcm(new Int16Array(10), 24000), /no vector/);
  } finally {
    await stop(server);
  }
});

test('a slow service is cut off at the timeout', async () => {
  const { server, url } = await serve((req, res) => setTimeout(() => res.end('{"vector":[1]}'), 300));
  try {
    await assert.rejects(
      createVoiceEmbedClient({ baseUrl: url, timeoutMs: 50 }).embedPcm(new Int16Array(10), 24000),
      (e) => e.name === 'AbortError',
    );
  } finally {
    await stop(server);
  }
});

test('cosine: same direction 1, orthogonal 0, zero vector 0, mismatch throws', () => {
  assert.ok(Math.abs(cosine([1, 2], [2, 4]) - 1) < 1e-12);
  assert.strictEqual(cosine([1, 0], [0, 1]), 0);
  assert.strictEqual(cosine([0, 0], [1, 1]), 0);
  assert.throws(() => cosine([1], [1, 2]), /length mismatch/);
});
