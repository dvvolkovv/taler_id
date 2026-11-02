import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { InterpreterSecretGuard } from './interpreter-secret.guard';

function ctxWithHeaders(headers: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers }) }),
  } as unknown as ExecutionContext;
}

describe('InterpreterSecretGuard', () => {
  let guard: InterpreterSecretGuard;
  const origEnv = process.env.INTERPRETER_SHARED_SECRET;

  beforeEach(() => {
    guard = new InterpreterSecretGuard();
    process.env.INTERPRETER_SHARED_SECRET = 'test-secret-value';
  });

  afterAll(() => {
    if (origEnv === undefined) delete process.env.INTERPRETER_SHARED_SECRET;
    else process.env.INTERPRETER_SHARED_SECRET = origEnv;
  });

  it('allows request with correct secret', () => {
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': 'test-secret-value' });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('rejects request with wrong secret', () => {
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': 'wrong' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it('rejects a secret of the right length that differs', () => {
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': 'test-secret-valuf' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it('rejects request without header', () => {
    expect(() => guard.canActivate(ctxWithHeaders({}))).toThrow(
      UnauthorizedException,
    );
  });

  it('fails closed when secret is not configured', () => {
    delete process.env.INTERPRETER_SHARED_SECRET;
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': '' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });
});
