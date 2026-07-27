// Shared LiveKit credentials for the agent processes.
//
// Mirrors src/common/livekit-credentials.ts on the backend side. These sign
// room access tokens, so the pair that used to sit here as an `||` fallback
// (`lkdevkey` / `lkSecret2024TalerID`) is published in this repository and must
// never be what a running agent uses: anyone reading it could mint a token for
// any room.
//
// Each agent calls require('dotenv').config() first, so this reads the values
// after the agent's own .env has been loaded.

const COMMITTED_SECRET = 'lkSecret2024TalerID';

function readLivekitCredentials() {
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;

  const missing = [
    apiKey ? null : 'LIVEKIT_API_KEY',
    apiSecret ? null : 'LIVEKIT_API_SECRET',
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(
      `${missing.join(' and ')} must be set in the agent's .env — ` +
        'LiveKit tokens cannot be signed without them.',
    );
  }

  if (apiSecret === COMMITTED_SECRET) {
    throw new Error(
      'LIVEKIT_API_SECRET is the value committed to this repository. ' +
        'Rotate it in LiveKit and set the real secret in .env.',
    );
  }

  return { apiKey, apiSecret };
}

module.exports = { readLivekitCredentials };
