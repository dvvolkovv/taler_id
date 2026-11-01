import { ParseUUIDPipe, RequestMethod } from '@nestjs/common';
import {
  GUARDS_METADATA,
  HTTP_CODE_METADATA,
  METHOD_METADATA,
  PATH_METADATA,
  ROUTE_ARGS_METADATA,
} from '@nestjs/common/constants';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { InterpreterSecretGuard } from './interpreter-secret.guard';
import { InterpreterController } from './interpreter.controller';

const ROUTES = [
  ['languages', 'GET', 'languages'],
  ['create', 'POST', 'sessions'],
  ['join', 'POST', 'sessions/join'],
  ['newCode', 'POST', 'sessions/:id/code'],
  ['get', 'GET', 'sessions/:id'],
  ['end', 'POST', 'sessions/:id/end'],
  ['selftest', 'GET', 'selftest'],
  ['agentEnded', 'POST', 'internal/sessions/:id/agent-ended'],
] as const;

const handler = (name: (typeof ROUTES)[number][0]) =>
  InterpreterController.prototype[name];

describe('InterpreterController routes', () => {
  it('lives under /interpreter', () => {
    expect(Reflect.getMetadata(PATH_METADATA, InterpreterController)).toBe(
      'interpreter',
    );
  });

  it.each(ROUTES)('%s is %s %s', (name, method, path) => {
    expect(Reflect.getMetadata(METHOD_METADATA, handler(name))).toBe(
      RequestMethod[method],
    );
    expect(Reflect.getMetadata(PATH_METADATA, handler(name))).toBe(path);
  });

  it('puts every route a person calls behind the JWT guard', () => {
    for (const [name] of ROUTES.filter(([n]) => n !== 'agentEnded')) {
      expect(Reflect.getMetadata(GUARDS_METADATA, handler(name))).toEqual([
        JwtAuthGuard,
      ]);
    }
  });

  it('lets only the agent report an end, unthrottled, answered 200', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, handler('agentEnded'))).toEqual(
      [InterpreterSecretGuard],
    );
    for (const name of ['short', 'medium', 'long']) {
      expect(
        Reflect.getMetadata(`THROTTLER:SKIP${name}`, handler('agentEnded')),
      ).toBe(true);
    }
    expect(Reflect.getMetadata(HTTP_CODE_METADATA, handler('agentEnded'))).toBe(
      200,
    );
  });

  it.each(['newCode', 'get', 'end', 'agentEnded'] as const)(
    '%s takes the session id as a UUID',
    (name) => {
      const args: Record<string, { data?: unknown; pipes: unknown[] }> =
        Reflect.getMetadata(ROUTE_ARGS_METADATA, InterpreterController, name);
      const id = Object.values(args).find((a) => a.data === 'id');
      expect(id?.pipes).toContain(ParseUUIDPipe);
    },
  );
});

describe('InterpreterController handlers', () => {
  const user = { sub: 'user-1', session_id: 'login-1' };
  const ID = '0f8fad5b-d9cb-469f-a165-70867728950e';
  let service: Record<string, jest.Mock>;
  let controller: InterpreterController;

  beforeEach(() => {
    service = {
      languages: jest.fn().mockReturnValue({ enabled: true, languages: [] }),
      create: jest.fn().mockResolvedValue('created'),
      join: jest.fn().mockResolvedValue('joined'),
      newCode: jest.fn().mockResolvedValue('code'),
      get: jest.fn().mockResolvedValue('view'),
      end: jest.fn().mockResolvedValue({ status: 'ended' }),
      agentEnded: jest.fn().mockResolvedValue({ ok: true }),
      selftest: jest.fn(),
    };
    controller = new InterpreterController(service as any);
  });

  it('hands each request to the service', async () => {
    expect(controller.languages()).toEqual({ enabled: true, languages: [] });
    await expect(controller.create(user, { lang: 'ru' })).resolves.toBe(
      'created',
    );
    expect(service.create).toHaveBeenCalledWith(user, 'ru');
    await expect(
      controller.join(user, { code: 'abcd-efgh', lang: 'de' }),
    ).resolves.toBe('joined');
    expect(service.join).toHaveBeenCalledWith(user, 'abcd-efgh', 'de');
    await controller.newCode(user, ID);
    expect(service.newCode).toHaveBeenCalledWith('user-1', ID);
    await controller.get(user, ID);
    expect(service.get).toHaveBeenCalledWith('user-1', ID);
    await controller.end(user, ID);
    expect(service.end).toHaveBeenCalledWith('user-1', ID);
    await controller.agentEnded(ID, { reason: 'partner_left' });
    expect(service.agentEnded).toHaveBeenCalledWith(ID, 'partner_left');
  });

  it("answers the selftest with the agent's own status and body", async () => {
    service.selftest.mockResolvedValue({
      status: 500,
      body: { ok: false, reason: 'phrase: 404' },
    });
    const res = { status: jest.fn() };

    await expect(controller.selftest(res as any)).resolves.toEqual({
      ok: false,
      reason: 'phrase: 404',
    });
    expect(res.status).toHaveBeenCalledWith(500);
  });
});
