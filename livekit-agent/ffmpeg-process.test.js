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

test('total runtime may exceed the idle limit while progress continues', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 200,
  });
  for (const time of ['00:00:01.00', '00:00:02.00', '00:00:03.00', '00:00:04.00']) {
    child.stderr.emit('data', `frame=10 time=${time} bitrate=48kbits/s`);
    await delay(75);
    assert.deepEqual(child.kills, []);
  }
  child.emit('close', 0, null);
  await promise;
});

test('a stalled process gets SIGTERM and rejects FFMPEG_STALLED', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 50,
    killTimeoutMs: 1000,
  });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    assert.equal(error.signal, 'SIGTERM');
    return true;
  });

  await waitFor(() => child.kills.includes('SIGTERM'));
  child.emit('close', null, 'SIGTERM');
  await rejection;
});

test('SIGKILL is sent and the promise rejects if SIGTERM is ignored', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 50,
    killTimeoutMs: 50,
  });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    assert.equal(error.signal, 'SIGKILL');
    return true;
  });

  await waitFor(() => child.kills.includes('SIGKILL'));
  await rejection;
  assert.deepEqual(child.kills, ['SIGTERM', 'SIGKILL']);
});

test('completion clears the watchdog and listeners', async () => {
  const child = new FakeChild();
  let cleared = false;
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    setIntervalImpl: () => ({ unref() {} }),
    clearIntervalImpl: () => {
      cleared = true;
    },
  });
  child.emit('close', 0, null);
  await promise;

  assert.equal(cleared, true);
  assert.equal(child.listenerCount('close'), 0);
  assert.equal(child.listenerCount('error'), 0);
  assert.equal(child.stdout.listenerCount('data'), 0);
  assert.equal(child.stderr.listenerCount('data'), 0);
});

test('keeps the stall rejection when SIGTERM is followed by error and close', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 50,
    killTimeoutMs: 1000,
    maxLogTailChars: 4,
  });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    assert.equal(error.signal, 'SIGTERM');
    assert.equal(error.stderr, '6789');
    return true;
  });

  child.stderr.emit('data', '0123456789');
  await waitFor(() => child.kills.includes('SIGTERM'));
  child.emit('error', new Error('kill delivery failed'));
  child.emit('close', null, 'SIGTERM');
  await rejection;
  assert.deepEqual(child.kills, ['SIGTERM']);
});

test('parses progress before trimming the diagnostic stderr tail', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 100,
    killTimeoutMs: 1000,
  });

  await delay(50);
  child.stderr.emit(
    'data',
    `time=00:00:01.00 ${'x'.repeat(70 * 1024)}`,
  );
  await delay(60);
  assert.deepEqual(child.kills, []);
  child.emit('close', 0, null);

  const result = await promise;
  assert.equal(result.stderr.length, 64 * 1024);
});

function createManualTimers() {
  const timers = {
    intervals: new Set(),
    timeouts: new Set(),
    idleCallback: null,
    killCallback: null,
    setIntervalImpl(callback) {
      const handle = { unref() {} };
      timers.intervals.add(handle);
      timers.idleCallback = callback;
      return handle;
    },
    clearIntervalImpl(handle) {
      timers.intervals.delete(handle);
    },
    setTimeoutImpl(callback) {
      const handle = { unref() {} };
      timers.timeouts.add(handle);
      timers.killCallback = callback;
      return handle;
    },
    clearTimeoutImpl(handle) {
      timers.timeouts.delete(handle);
    },
  };
  return timers;
}

test('escalates to SIGKILL when SIGTERM synchronously emits an error', async () => {
  const child = new FakeChild();
  const timers = createManualTimers();
  const eperm = new Error('kill delivery failed');
  eperm.code = 'EPERM';
  child.kill = (signal) => {
    child.kills.push(signal);
    if (signal === 'SIGTERM') child.emit('error', eperm);
    return true;
  };
  let currentTime = 0;
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 100,
    killTimeoutMs: 1000,
    now: () => currentTime,
    ...timers,
  });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    assert.equal(error.signal, 'SIGKILL');
    assert.equal(error.cause, eperm);
    return true;
  });

  currentTime = 100;
  timers.idleCallback();
  timers.killCallback();
  timers.killCallback();
  await rejection;

  assert.deepEqual(child.kills, ['SIGTERM', 'SIGKILL']);
  assert.equal(timers.intervals.size, 0);
  assert.equal(timers.timeouts.size, 0);
  assert.equal(child.listenerCount('close'), 0);
  assert.equal(child.listenerCount('error'), 0);
  assert.equal(child.stdout.listenerCount('data'), 0);
  assert.equal(child.stderr.listenerCount('data'), 0);
});

test('waits for a whitespace delimiter before accepting a split timestamp', async () => {
  const child = new FakeChild();
  const timers = createManualTimers();
  let currentTime = 0;
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 100,
    killTimeoutMs: 1000,
    now: () => currentTime,
    ...timers,
  });

  child.stderr.emit('data', 'time=00:00:01.');
  currentTime = 50;
  child.stderr.emit('data', '00 ');
  currentTime = 100;
  timers.idleCallback();
  assert.deepEqual(child.kills, []);

  child.emit('close', 0, null);
  await promise;
  assert.equal(timers.intervals.size, 0);
  assert.equal(timers.timeouts.size, 0);
});

test('only strictly increasing complete timestamps reset the idle watchdog', async () => {
  const stalledChild = new FakeChild();
  const stalledTimers = createManualTimers();
  let stalledTime = 0;
  const stalledPromise = runFfmpegProcess([], {
    spawnImpl: () => stalledChild,
    idleTimeoutMs: 100,
    killTimeoutMs: 1000,
    now: () => stalledTime,
    ...stalledTimers,
  });
  const rejection = assert.rejects(stalledPromise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    return true;
  });

  stalledChild.stderr.emit('data', 'time=00:00:02.00 ');
  stalledTime = 50;
  stalledChild.stderr.emit('data', 'time=00:00:02.00 ');
  stalledTime = 75;
  stalledChild.stderr.emit('data', 'time=00:00:01.00 ');
  stalledTime = 100;
  stalledTimers.idleCallback();
  assert.deepEqual(stalledChild.kills, ['SIGTERM']);
  stalledChild.emit('close', null, 'SIGTERM');
  await rejection;

  const progressingChild = new FakeChild();
  const progressingTimers = createManualTimers();
  let progressingTime = 0;
  const progressingPromise = runFfmpegProcess([], {
    spawnImpl: () => progressingChild,
    idleTimeoutMs: 100,
    killTimeoutMs: 1000,
    now: () => progressingTime,
    ...progressingTimers,
  });

  progressingChild.stderr.emit('data', 'time=00:00:01.00 ');
  progressingTime = 75;
  progressingChild.stderr.emit('data', 'time=00:00:02.00 ');
  progressingTime = 100;
  progressingTimers.idleCallback();
  assert.deepEqual(progressingChild.kills, []);

  progressingChild.emit('close', 0, null);
  await progressingPromise;
  assert.equal(stalledTimers.intervals.size, 0);
  assert.equal(stalledTimers.timeouts.size, 0);
  assert.equal(progressingTimers.intervals.size, 0);
  assert.equal(progressingTimers.timeouts.size, 0);
});
