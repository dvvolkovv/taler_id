const test = require('node:test');
const assert = require('node:assert/strict');
const { recordingStatus } = require('./recording-result');

test('done means a recording exists and no processing failed', () => {
  assert.equal(recordingStatus('https://x/recording.mp3', false), 'done');
});

test('partial means a recording exists but some processing failed', () => {
  assert.equal(recordingStatus('https://x/recording.mp3', true), 'partial');
});

test('failed means there is no usable recording, regardless of earlier errors', () => {
  assert.equal(recordingStatus(null, false), 'failed');
  assert.equal(recordingStatus(null, true), 'failed');
  assert.equal(recordingStatus('', false), 'failed');
  assert.equal(recordingStatus('', true), 'failed');
});
