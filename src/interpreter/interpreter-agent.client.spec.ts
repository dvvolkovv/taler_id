import { Logger } from '@nestjs/common';
import {
  AgentCallError,
  AgentStartBody,
  InterpreterAgentClient,
} from './interpreter-agent.client';

// Digits that appear nowhere but in the voice prints.
const MARK = 0.987654321;
const startBody: AgentStartBody = {
  sessionId: 's-1',
  roomName: 'interp-1',
  participants: [
    { userId: 'host-1', lang: 'ru', embedding: Array(192).fill(MARK) },
    { userId: 'guest-1', lang: 'de', embedding: Array(192).fill(-MARK) },
  ],
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

describe('InterpreterAgentClient', () => {
  const saved = {
    url: process.env.AI_AGENT_URL,
    secret: process.env.INTERPRETER_SHARED_SECRET,
  };
  let client: InterpreterAgentClient;
  let fetchFn: jest.Mock;
  let timeout: jest.SpyInstance;
  let logs: jest.SpyInstance[];

  beforeEach(() => {
    process.env.AI_AGENT_URL = 'http://agent.test:3100/';
    process.env.INTERPRETER_SHARED_SECRET = 'shh';
    client = new InterpreterAgentClient();
    fetchFn = jest.fn();
    client.fetchFn = fetchFn;
    timeout = jest.spyOn(AbortSignal, 'timeout');
    logs = (['log', 'warn', 'error'] as const).map((level) =>
      jest.spyOn(Logger.prototype, level).mockImplementation(() => undefined),
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
    for (const [key, value] of [
      ['AI_AGENT_URL', saved.url],
      ['INTERPRETER_SHARED_SECRET', saved.secret],
    ] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  /** Neither the error nor anything logged may carry a voice print. */
  const expectNoVoicePrint = (err?: unknown) => {
    const seen = JSON.stringify([
      err instanceof Error ? [err.message, err.stack] : err,
      logs.map((spy) => spy.mock.calls),
    ]);
    expect(seen).not.toContain('987654321');
  };

  describe('start', () => {
    it('posts both participants with the secret and a 35 s timeout', async () => {
      fetchFn.mockResolvedValue(json({ status: 'started' }));

      await client.start(startBody);

      const [url, init] = fetchFn.mock.calls[0];
      expect(url).toBe('http://agent.test:3100/interpreter/start');
      expect(init.method).toBe('POST');
      expect(init.headers).toEqual({
        'Content-Type': 'application/json',
        'x-interpreter-secret': 'shh',
      });
      expect(JSON.parse(init.body)).toEqual(startBody);
      expect(timeout).toHaveBeenCalledWith(35_000);
      expect(init.signal).toBe(timeout.mock.results[0].value);
    });

    it('accepts a start that is already running', async () => {
      fetchFn.mockResolvedValue(json({ status: 'already_running' }));
      await expect(client.start(startBody)).resolves.toBeUndefined();
    });

    it('turns a refusal into an AgentCallError with the agent status', async () => {
      fetchFn.mockResolvedValue(
        json({ error: 'participants have the same voice print' }, 400),
      );

      const err = await client.start(startBody).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(AgentCallError);
      expect((err as AgentCallError).status).toBe(400);
      expectNoVoicePrint(err);
    });

    it('reports an agent it could not reach as status 0', async () => {
      fetchFn.mockRejectedValue(
        Object.assign(new TypeError('fetch failed'), {
          cause: { code: 'ECONNREFUSED' },
        }),
      );

      const err = await client.start(startBody).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(AgentCallError);
      expect((err as AgentCallError).status).toBe(0);
      expect((err as AgentCallError).message).toContain('ECONNREFUSED');
      expectNoVoicePrint(err);
    });

    it('does not send the voice prints without the secret', async () => {
      delete process.env.INTERPRETER_SHARED_SECRET;

      await expect(client.start(startBody)).rejects.toBeInstanceOf(
        AgentCallError,
      );
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('defaults to the agent on localhost', async () => {
      delete process.env.AI_AGENT_URL;
      fetchFn.mockResolvedValue(json({ status: 'started' }));

      await client.start(startBody);

      expect(fetchFn.mock.calls[0][0]).toBe(
        'http://localhost:3100/interpreter/start',
      );
    });
  });

  describe('stop', () => {
    it('posts the room with the secret and a 10 s timeout', async () => {
      fetchFn.mockResolvedValue(json({ status: 'stopped' }));

      await client.stop('interp-1');

      const [url, init] = fetchFn.mock.calls[0];
      expect(url).toBe('http://agent.test:3100/interpreter/stop');
      expect(init.method).toBe('POST');
      expect(init.headers['x-interpreter-secret']).toBe('shh');
      expect(JSON.parse(init.body)).toEqual({ roomName: 'interp-1' });
      expect(timeout).toHaveBeenCalledWith(10_000);
    });

    it('never throws: the session is closing either way', async () => {
      fetchFn.mockRejectedValueOnce(new TypeError('fetch failed'));
      await expect(client.stop('interp-1')).resolves.toBeUndefined();

      fetchFn.mockResolvedValueOnce(json({ error: 'boom' }, 500));
      await expect(client.stop('interp-1')).resolves.toBeUndefined();

      delete process.env.INTERPRETER_SHARED_SECRET;
      await expect(client.stop('interp-1')).resolves.toBeUndefined();

      expect(logs[1]).toHaveBeenCalledTimes(3);
    });
  });

  describe('selftest', () => {
    it('passes the agent answer through with its status', async () => {
      fetchFn.mockResolvedValue(
        json({ ok: false, reason: 'phrase: 404' }, 500),
      );

      await expect(client.selftest()).resolves.toEqual({
        status: 500,
        body: { ok: false, reason: 'phrase: 404' },
      });
      const [url, init] = fetchFn.mock.calls[0];
      expect(url).toBe('http://agent.test:3100/interpreter/selftest');
      expect(init.method).toBe('GET');
      expect(init.body).toBeUndefined();
      expect(init.headers['x-interpreter-secret']).toBe('shh');
      expect(timeout).toHaveBeenCalledWith(25_000);
    });

    it('answers 503 with the status of an answer that is not JSON', async () => {
      fetchFn.mockResolvedValue(
        new Response('<html>502 Bad Gateway</html>', { status: 502 }),
      );

      await expect(client.selftest()).resolves.toEqual({
        status: 503,
        body: { ok: false, reason: 'agent answered 502, not JSON' },
      });
    });

    it('answers 503 when the agent cannot be reached', async () => {
      fetchFn.mockRejectedValue(
        new DOMException('The operation timed out.', 'TimeoutError'),
      );

      await expect(client.selftest()).resolves.toEqual({
        status: 503,
        body: { ok: false, reason: expect.stringContaining('unreachable') },
      });
    });
  });
});
