import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { RecorderSecretGuard } from './recorder-secret.guard';

function ctxWithHeaders(headers: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers }) }),
  } as unknown as ExecutionContext;
}

describe('RecorderSecretGuard', () => {
  let guard: RecorderSecretGuard;
  const origEnv = process.env.RECORDER_SHARED_SECRET;

  beforeEach(() => {
    guard = new RecorderSecretGuard();
    process.env.RECORDER_SHARED_SECRET = 'test-secret-value';
  });

  afterAll(() => {
    if (origEnv === undefined) delete process.env.RECORDER_SHARED_SECRET;
    else process.env.RECORDER_SHARED_SECRET = origEnv;
  });

  it('allows request with correct secret', () => {
    const ctx = ctxWithHeaders({ 'x-recorder-secret': 'test-secret-value' });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('rejects request with wrong secret', () => {
    const ctx = ctxWithHeaders({ 'x-recorder-secret': 'wrong' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it('rejects request without header', () => {
    expect(() => guard.canActivate(ctxWithHeaders({}))).toThrow(
      UnauthorizedException,
    );
  });

  it('fails closed when secret is not configured', () => {
    delete process.env.RECORDER_SHARED_SECRET;
    const ctx = ctxWithHeaders({ 'x-recorder-secret': 'anything' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });
});
