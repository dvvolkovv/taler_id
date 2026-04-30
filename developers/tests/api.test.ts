import { describe, it, expect, vi, beforeEach } from 'vitest';
import { listClients, registerClient, updateClient, deleteClient, rotateSecret } from '../src/api';

describe('api', () => {
  let fetchSpy: any;
  const getToken = async () => 'AT';

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch' as any).mockResolvedValue(
      new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
  });

  it('listClients GETs /oauth/clients with Bearer header', async () => {
    await listClients(getToken);
    expect(fetchSpy).toHaveBeenCalledWith('/oauth/clients', expect.objectContaining({
      headers: expect.objectContaining({ authorization: 'Bearer AT' }),
    }));
  });

  it('registerClient POSTs JSON body', async () => {
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ client_id: 'cid', client_secret: 'sec' }), { status: 200 }));
    const result = await registerClient(getToken, {
      client_name: 'a',
      redirect_uris: ['app://cb'],
      scope: 'openid',
    });
    expect(result.client_id).toBe('cid');
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/register');
    expect((call[1] as RequestInit).method).toBe('POST');
    const body = JSON.parse((call[1] as RequestInit).body as string);
    expect(body.client_name).toBe('a');
  });

  it('updateClient PATCHes /oauth/clients/:id', async () => {
    await updateClient(getToken, 'cid-1', { client_name: 'newname' });
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/clients/cid-1');
    expect((call[1] as RequestInit).method).toBe('PATCH');
  });

  it('deleteClient DELETEs /oauth/clients/:id', async () => {
    await deleteClient(getToken, 'cid-1');
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/clients/cid-1');
    expect((call[1] as RequestInit).method).toBe('DELETE');
  });

  it('rotateSecret POSTs to /oauth/clients/:id/rotate-secret', async () => {
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ client_id: 'cid', client_secret: 'NEW' }), { status: 200 }));
    const result = await rotateSecret(getToken, 'cid-1');
    expect(result.client_secret).toBe('NEW');
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/clients/cid-1/rotate-secret');
    expect((call[1] as RequestInit).method).toBe('POST');
  });

  it('throws Error on non-2xx response', async () => {
    fetchSpy.mockResolvedValue(new Response('{"error":"bad"}', { status: 400 }));
    await expect(listClients(getToken)).rejects.toThrow();
  });
});
