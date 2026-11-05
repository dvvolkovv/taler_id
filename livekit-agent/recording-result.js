'use strict';

/**
 * A usable file decides whether the result is partial or failed; hadErrors
 * decides whether a usable file is allowed to be called complete.
 */
function recordingStatus(recordingUrl, hadErrors) {
  if (!recordingUrl) return 'failed';
  return hadErrors ? 'partial' : 'done';
}

module.exports = { recordingStatus };
