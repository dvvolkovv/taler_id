/** A function that returns a fresh access token (handles refresh internally). */
export type GetToken = () => Promise<string>;

export interface OAuthClient {
  client_id: string;
  client_id_issued_at: number;
  client_name: string;
  redirect_uris: string[];
  scope: string;
  logo_uri?: string;
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
}

export interface RegisterResponse extends OAuthClient {
  client_secret: string;
  client_secret_expires_at: number;
}

export interface RegisterPayload {
  client_name: string;
  redirect_uris: string[];
  scope?: string;
  logo_uri?: string;
}

export interface UpdatePayload {
  client_name?: string;
  redirect_uris?: string[];
  scope?: string;
  logo_uri?: string;
}

export interface RotateResponse {
  client_id: string;
  client_secret: string;
  client_secret_rotated_at: number;
}

async function call<T>(getToken: GetToken, path: string, init: RequestInit = {}): Promise<T> {
  const token = await getToken();
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      authorization: `Bearer ${token}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
  });
  if (!response.ok) {
    let detail: unknown;
    try { detail = await response.json(); } catch { detail = await response.text(); }
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(detail)}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const listClients = (getToken: GetToken) =>
  call<OAuthClient[]>(getToken, '/oauth/clients');

export const registerClient = (getToken: GetToken, payload: RegisterPayload) =>
  call<RegisterResponse>(getToken, '/oauth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

export const updateClient = (getToken: GetToken, clientId: string, payload: UpdatePayload) =>
  call<OAuthClient>(getToken, `/oauth/clients/${clientId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });

export const deleteClient = (getToken: GetToken, clientId: string) =>
  call<void>(getToken, `/oauth/clients/${clientId}`, { method: 'DELETE' });

export const rotateSecret = (getToken: GetToken, clientId: string) =>
  call<RotateResponse>(getToken, `/oauth/clients/${clientId}/rotate-secret`, {
    method: 'POST',
  });
