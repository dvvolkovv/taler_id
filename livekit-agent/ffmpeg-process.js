'use strict';

const { spawn } = require('node:child_process');
const { StringDecoder } = require('node:string_decoder');

const DEFAULT_MAX_LOG_TAIL_CHARS = 64 * 1024;
const DEFAULT_IDLE_TIMEOUT_MS = 300000;
const DEFAULT_KILL_TIMEOUT_MS = 10000;
const PROGRESS_CARRY_CHARS = 64;

function appendTail(previous, chunk, limit) {
  const next = previous + chunk;
  if (next.length <= limit) return next;

  let start = next.length - limit;
  const first = next.charCodeAt(start);
  const preceding = next.charCodeAt(start - 1);
  if (
    start > 0 &&
    first >= 0xdc00 &&
    first <= 0xdfff &&
    preceding >= 0xd800 &&
    preceding <= 0xdbff
  ) {
    start -= 1;
  }
  return next.slice(start);
}

function runFfmpegProcess(args, options = {}) {
  const {
    command = 'ffmpeg',
    spawnImpl = spawn,
    maxLogTailChars = DEFAULT_MAX_LOG_TAIL_CHARS,
    idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
    killTimeoutMs = DEFAULT_KILL_TIMEOUT_MS,
    now = Date.now,
    setIntervalImpl = setInterval,
    clearIntervalImpl = clearInterval,
    setTimeoutImpl = setTimeout,
    clearTimeoutImpl = clearTimeout,
  } = options;

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(error);
      return;
    }

    let stdout = '';
    let stderr = '';
    let progressCarry = '';
    let settled = false;
    let lastProgressAt = now();
    let lastMediaSeconds = null;
    let stalling = false;
    let stallCause = null;
    let killSignal = 'SIGTERM';
    let killTimer = null;
    let watchdog;
    const stdoutDecoder = new StringDecoder('utf8');
    const stderrDecoder = new StringDecoder('utf8');

    const onStdout = (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      stdout = appendTail(
        stdout,
        stdoutDecoder.write(buffer),
        maxLogTailChars,
      );
    };
    const onStderr = (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const decoded = stderrDecoder.write(buffer);
      const progressText = progressCarry + decoded;
      for (const match of progressText.matchAll(
        /time=(\d+):(\d+):(\d+(?:\.\d+)?)(?=\s)/g,
      )) {
        const mediaSeconds =
          Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3]);
        if (lastMediaSeconds === null || mediaSeconds > lastMediaSeconds) {
          lastMediaSeconds = mediaSeconds;
          lastProgressAt = now();
        }
      }
      progressCarry = progressText.slice(-PROGRESS_CARRY_CHARS);
      stderr = appendTail(stderr, decoded, maxLogTailChars);
    };
    const onError = (error) => {
      if (stalling) {
        captureStallCause(error);
        return;
      }
      finish(error);
    };
    const onClose = (code, signal) => {
      stdout = appendTail(stdout, stdoutDecoder.end(), maxLogTailChars);
      stderr = appendTail(stderr, stderrDecoder.end(), maxLogTailChars);
      if (stalling) {
        finish(stallError());
        return;
      }
      if (code === 0) {
        finish(null, { stdout, stderr });
        return;
      }
      const error = new Error(
        `ffmpeg exited with code ${code}${signal ? ` (${signal})` : ''}`,
      );
      error.code = 'FFMPEG_EXIT';
      error.exitCode = code;
      error.signal = signal;
      error.stderr = stderr;
      finish(error);
    };

    function captureStallCause(error) {
      if (stallCause === null) stallCause = error;
    }

    function stallError() {
      const error = new Error(
        `ffmpeg made no progress for ${idleTimeoutMs} ms` +
          (lastMediaSeconds === null ? '' : ` (last time=${lastMediaSeconds}s)`),
      );
      error.code = 'FFMPEG_STALLED';
      error.signal = killSignal;
      error.stderr = stderr;
      if (stallCause !== null) error.cause = stallCause;
      return error;
    }

    function onIdleCheck() {
      if (settled || stalling) return;
      if (now() - lastProgressAt < idleTimeoutMs) return;

      stalling = true;
      killSignal = 'SIGTERM';
      killTimer = setTimeoutImpl(onKillTimeout, killTimeoutMs);
      if (killTimer && typeof killTimer.unref === 'function') {
        killTimer.unref();
      }
      try {
        child.kill('SIGTERM');
      } catch (error) {
        captureStallCause(error);
      }
    }

    function onKillTimeout() {
      if (settled || !stalling || killTimer === null) return;

      const timer = killTimer;
      killTimer = null;
      clearTimeoutImpl(timer);
      killSignal = 'SIGKILL';
      try {
        child.kill('SIGKILL');
      } catch (error) {
        captureStallCause(error);
      }
      finish(stallError());
    }

    function finish(error, value) {
      if (settled) return;
      settled = true;
      clearIntervalImpl(watchdog);
      if (killTimer !== null) {
        clearTimeoutImpl(killTimer);
        killTimer = null;
      }
      child.stdout.removeListener('data', onStdout);
      child.stderr.removeListener('data', onStderr);
      child.removeListener('error', onError);
      child.removeListener('close', onClose);
      if (error) reject(error);
      else resolve(value);
    }

    child.stdout.on('data', onStdout);
    child.stderr.on('data', onStderr);
    child.on('error', onError);
    child.on('close', onClose);

    watchdog = setIntervalImpl(
      onIdleCheck,
      Math.max(10, Math.min(1000, idleTimeoutMs)),
    );
    if (watchdog && typeof watchdog.unref === 'function') {
      watchdog.unref();
    }
  });
}

module.exports = {
  runFfmpegProcess,
  DEFAULT_IDLE_TIMEOUT_MS,
  DEFAULT_KILL_TIMEOUT_MS,
};
