import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { timingSafeEqual } from 'crypto';
import type { Request } from 'express';

/**
 * The agent's calls back into the backend (agent-ended). The agent is not a
 * user, so it proves itself with INTERPRETER_SHARED_SECRET, the same secret
 * the backend sends it, in x-interpreter-secret.
 */
@Injectable()
export class InterpreterSecretGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const expected = process.env.INTERPRETER_SHARED_SECRET;
    // Unset must not mean "an empty header matches".
    if (!expected) {
      throw new UnauthorizedException('interpreter_secret_not_configured');
    }

    const raw = req.headers['x-interpreter-secret'];
    const header = Array.isArray(raw) ? raw[0] : raw;
    if (typeof header !== 'string') {
      throw new UnauthorizedException('bad_interpreter_secret');
    }

    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new UnauthorizedException('bad_interpreter_secret');
    }
    return true;
  }
}
