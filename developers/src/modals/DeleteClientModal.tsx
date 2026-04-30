import type { OAuthClient } from '../api';

export function DeleteClientModal(_: { client: OAuthClient; onClose: () => void; onDeleted: () => void }) {
  return null;
}
