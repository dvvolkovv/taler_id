import { McpController } from './mcp.controller';

function makeRes(method: string) {
  const headers: Record<string, string> = {};
  const res: any = {
    method,
    statusCode: 200,
    _body: undefined as any,
    headersSent: false,
    setHeader: jest.fn((key: string, val: string) => { headers[key] = val; }),
    getHeader: (key: string) => headers[key],
    _headers: headers,
    status(code: number) { this.statusCode = code; return this; },
    end() { this.headersSent = true; return this; },
    json(body: any) { this._body = body; this.headersSent = true; return this; },
    on: jest.fn(),
  };
  return res;
}

function makeReq(method: string) {
  return { method } as any;
}

describe('McpController — method-not-allowed handler', () => {
  const factory: any = { buildServer: jest.fn() };
  const controller = new McpController(factory);

  it('OPTIONS → 204 + Allow: POST header (no body)', () => {
    const req = makeReq('OPTIONS');
    const res = makeRes('OPTIONS');
    controller.methodNotAllowed(req, res);
    expect(res.statusCode).toBe(204);
    expect(res._headers['Allow']).toBe('POST');
    expect(res._body).toBeUndefined();
  });

  it('GET → 405 + Allow: POST + JSON-RPC error body', () => {
    const req = makeReq('GET');
    const res = makeRes('GET');
    controller.methodNotAllowed(req, res);
    expect(res.statusCode).toBe(405);
    expect(res._headers['Allow']).toBe('POST');
    expect(res._body).toMatchObject({
      jsonrpc: '2.0',
      error: { code: -32000 },
      id: null,
    });
  });

  it('DELETE → 405 + Allow: POST + JSON-RPC error body', () => {
    const req = makeReq('DELETE');
    const res = makeRes('DELETE');
    controller.methodNotAllowed(req, res);
    expect(res.statusCode).toBe(405);
    expect(res._headers['Allow']).toBe('POST');
    expect(res._body).toMatchObject({
      jsonrpc: '2.0',
      error: { code: -32000 },
      id: null,
    });
  });
});
