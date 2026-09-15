// Run with: node --test livekit-agent/recorder-endpoints.test.js
//
// The recorder talks to the backend from four places, and one of them had
// drifted to `/api/voice/meetings/save` — a path that does not exist (404,
// while the real one answers 401 behind its guard). The branch that drifted is
// the fail-loud one: the save that exists precisely so an empty recording shows
// up in the UI as failed instead of vanishing. It was vanishing itself.
//
// Nothing in that path is reachable from a unit test — it needs a LiveKit room
// that produced no audio — so this pins the class of mistake instead: every
// backend call goes to one spelling of the route.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const source = fs.readFileSync(path.join(__dirname, 'recorder.js'), 'utf8');

test('every meeting save posts to the same backend route', () => {
  const routes = [...source.matchAll(/BACKEND_URL\}(\/\S*?meetings\/save)`/g)].map(
    (m) => m[1],
  );

  assert.ok(routes.length >= 2, `expected several save calls, found ${routes.length}`);
  assert.deepStrictEqual([...new Set(routes)], ['/voice/meetings/save']);
});

test('no backend call carries an /api prefix the server does not serve', () => {
  const prefixed = [...source.matchAll(/BACKEND_URL\}(\/api\/\S*?)`/g)].map((m) => m[1]);

  assert.deepStrictEqual(prefixed, []);
});
