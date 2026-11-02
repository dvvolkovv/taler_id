// Getting translated PCM onto a LiveKit track. Moved out of translator.js
// unchanged: the face-to-face interpreter publishes through the same path.

// In-place linear gain with int16 clamping (soft-limit at full scale).
function applyGain(int16, gain) {
  if (gain === 1) return int16;
  for (let i = 0; i < int16.length; i++) {
    const v = int16[i] * gain;
    int16[i] = v > 32767 ? 32767 : v < -32768 ? -32768 : v | 0;
  }
  return int16;
}

// ─── Async Frame Queue (prevents concurrent captureFrame calls) ───

function createFrameQueue(audioSource, targetLang) {
  const queue = [];
  let processing = false;

  async function processQueue() {
    if (processing) return;
    processing = true;
    while (queue.length > 0) {
      const frame = queue.shift();
      try {
        await audioSource.captureFrame(frame);
      } catch (e) {
        if (!e.message.includes('closed')) {
          console.error(`[TRANSLATOR] captureFrame error (${targetLang}):`, e.message);
        }
        break; // stop processing if source is broken
      }
    }
    processing = false;
  }

  return {
    push(frame) {
      // Drop frames if queue gets too large (> 50 frames = ~1 sec at 24kHz/480)
      if (queue.length > 300) {
        queue.splice(0, queue.length - 200); // keep last 200 (~4s)
      }
      queue.push(frame);
      processQueue();
    }
  };
}

module.exports = { applyGain, createFrameQueue };
