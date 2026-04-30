import type { OAuthClient, RotateResponse } from '../api';

export function RotateSecretModal(_: { client: OAuthClient; onClose: () => void; onRotated: (r: RotateResponse) => void }) {
  return null;
}
