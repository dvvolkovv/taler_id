const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { runFfmpegProcess } = require('./ffmpeg-process');

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.kills = [];
  }

  kill(signal) {
    this.kills.push(signal);
    return true;
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true');
    await delay(5);
  }
}

test('resolves stdout and bounded stderr after a zero exit', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess(['-version'], {
    spawnImpl: (command, args, options) => {
      assert.equal(command, 'ffmpeg');
      assert.deepEqual(args, ['-version']);
      assert.deepEqual(options, { stdio: ['ignore', 'pipe', 'pipe'] });
      return child;
    },
  });
  child.stdout.emit('data', 'out');
  child.stderr.emit('data', 'err');
  child.emit('close', 0, null);

  assert.deepEqual(await promise, { stdout: 'out', stderr: 'err' });
});

test('rejects a spawn error', async () => {
  const child = new FakeChild();
  const expected = new Error('spawn failed');
  const promise = runFfmpegProcess([], { spawnImpl: () => child });
  const rejection = assert.rejects(promise, (error) => error === expected);
  child.emit('error', expected);
  await rejection;
});

test('rejects a nonzero exit with stderr and the exit code', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], { spawnImpl: () => child });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_EXIT');
    assert.equal(error.exitCode, 2);
    assert.match(error.stderr, /bad input/);
    return true;
  });
  child.stderr.emit('data', 'bad input');
  child.emit('close', 2, null);
  await rejection;
});

test('keeps only the configured tail of stdout and stderr', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    maxLogTailChars: 8,
  });
  child.stdout.emit('data', 'abcdefghij');
  child.stderr.emit('data', '1234567890');
  child.emit('close', 0, null);

  assert.deepEqual(await promise, { stdout: 'cdefghij', stderr: '34567890' });
});

test('decodes UTF-8 split across Buffer chunks independently per stream', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], { spawnImpl: () => child });
  const input = Buffer.from('A€B');

  child.stdout.emit('data', input.subarray(0, 2));
  child.stderr.emit('data', input.subarray(0, 2));
  child.stdout.emit('data', input.subarray(2));
  child.stderr.emit('data', input.subarray(2));
  child.emit('close', 0, null);

  assert.deepEqual(await promise, { stdout: 'A€B', stderr: 'A€B' });
});

test('keeps whole surrogate pairs when trimming the log tail', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    maxLogTailChars: 1,
  });

  child.stdout.emit('data', Buffer.from('A😀'));
  child.stderr.emit('data', Buffer.from('B😀'));
  child.emit('close', 0, null);

  assert.deepEqual(await promise, { stdout: '😀', stderr: '😀' });
});

test('retains exactly the default tail across Buffer chunks on both streams', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], { spawnImpl: () => child });
  const defaultLimit = 64 * 1024;
  const stdoutSuffix = 'stdout-end';
  const stderrSuffix = 'stderr-end';
  const stdoutText = `${'a'.repeat(40 * 1024)}${'b'.repeat(40 * 1024)}${stdoutSuffix}`;
  const stderrText = `${'1'.repeat(40 * 1024)}${'2'.repeat(40 * 1024)}${stderrSuffix}`;

  child.stdout.emit('data', Buffer.alloc(40 * 1024, 'a'));
  child.stderr.emit('data', Buffer.alloc(40 * 1024, '1'));
  child.stdout.emit('data', Buffer.alloc(40 * 1024, 'b'));
  child.stderr.emit('data', Buffer.alloc(40 * 1024, '2'));
  child.stdout.emit('data', Buffer.from(stdoutSuffix));
  child.stderr.emit('data', Buffer.from(stderrSuffix));
  child.emit('close', 0, null);

  const result = await promise;
  assert.equal(result.stdout.length, defaultLimit);
  assert.equal(result.stderr.length, defaultLimit);
  assert.equal(result.stdout, stdoutText.slice(-defaultLimit));
  assert.equal(result.stderr, stderrText.slice(-defaultLimit));
  assert.ok(result.stdout.endsWith(`${'b'.repeat(128)}${stdoutSuffix}`));
  assert.ok(result.stderr.endsWith(`${'2'.repeat(128)}${stderrSuffix}`));
});
