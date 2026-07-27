/**
 * Single source for the LiveKit API credentials.
 *
 * These do more than identify us to the SFU: they sign every room access token
 * (`new AccessToken(...)`) and authenticate the admin `RoomServiceClient`, which
 * can list rooms and remove participants. LiveKit validates a token against the
 * key/secret pair alone — there is no further binding to a user — so anyone
 * holding the secret can mint a token for any room and join any call.
 *
 * The pair used to be inlined as an `||` fallback in eight files, which meant a
 * host brought up from .env.example (a fresh DEV box, a rebuilt DO node, local
 * docker-compose) silently started with credentials published in this repo, and
 * did so without any error. All three current environments do set the real
 * values — this keeps it that way by refusing to start without them rather than
 * quietly substituting a known secret.
 *
 * The dev pair survives for the test suite only: specs bind these at import
 * time and sign tokens with them.
 */
const IS_TEST = process.env.NODE_ENV === 'test';

const TEST_ONLY_KEY = 'lkdevkey';
const TEST_ONLY_SECRET = 'lkSecret2024TalerID';

export const LK_API_KEY =
  process.env.LIVEKIT_API_KEY ?? (IS_TEST ? TEST_ONLY_KEY : '');

export const LK_API_SECRET =
  process.env.LIVEKIT_API_SECRET ?? (IS_TEST ? TEST_ONLY_SECRET : '');

/**
 * Fails startup when the credentials are missing, instead of letting the app
 * come up and mint tokens the SFU will reject (or, previously, tokens signed
 * with a public secret). Called from bootstrap.
 */
export function assertLivekitCredentials(): void {
  const missing = [
    LK_API_KEY ? null : 'LIVEKIT_API_KEY',
    LK_API_SECRET ? null : 'LIVEKIT_API_SECRET',
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(
      `${missing.join(' and ')} must be set — LiveKit tokens cannot be signed ` +
        `without them. See .env.example.`,
    );
  }

  if (LK_API_SECRET === TEST_ONLY_SECRET) {
    throw new Error(
      'LIVEKIT_API_SECRET is set to the value committed in this repository. ' +
        'Rotate it in LiveKit and set the real secret in .env.',
    );
  }
}
