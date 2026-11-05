'use strict';

const { spawn } = require('node:child_process');
const { StringDecoder } = require('node:string_decoder');

const DEFAULT_MAX_LOG_TAIL_CHARS = 64 * 1024;

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
    let settled = false;
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
      stderr = appendTail(
        stderr,
        stderrDecoder.write(buffer),
        maxLogTailChars,
      );
    };
    const onError = (error) => finish(error);
    const onClose = (code, signal) => {
      stdout = appendTail(stdout, stdoutDecoder.end(), maxLogTailChars);
      stderr = appendTail(stderr, stderrDecoder.end(), maxLogTailChars);
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

    function finish(error, value) {
      if (settled) return;
      settled = true;
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
  });
}

module.exports = { runFfmpegProcess };
