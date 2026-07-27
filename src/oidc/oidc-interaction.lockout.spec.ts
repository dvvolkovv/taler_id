import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { OidcInteractionController } from './oidc-interaction.controller';

// Regression cover for the 2026-07-27 audit finding: this route read the
// lockout flag under `lockout:<identifier>` while the failure counter wrote
// `lockout:<userId>`, so password guessing here was never rate limited even
// though /auth/login locked the same account.
describe('OidcInteractionController lockout keying', () => {
  let controller: OidcInteractionController;
  let redis: any;
  let prisma: any;
  let store: Map<string, string>;
  let counters: Map<string, number>;

  const EMAIL = 'victim@example.com';
  const USER_ID = 'user-uuid-1';

  // The controller method under test is private; this is the narrow seam.
  const authenticate = (identifier: string, password: string) =>
    (controller as any).authenticateUser(identifier, password);

  beforeEach(async () => {
    store = new Map();
    counters = new Map();

    redis = {
      get: jest.fn(async (k: string) => store.get(k) ?? null),
      setEx: jest.fn(async (k: string, _ttl: number, v: string) => {
        store.set(k, v);
      }),
      del: jest.fn(async (k: string) => {
        store.delete(k);
        counters.delete(k);
      }),
      incr: jest.fn(async (k: string) => {
        const next = (counters.get(k) ?? 0) + 1;
        counters.set(k, next);
        return next;
      }),
      expire: jest.fn(async () => undefined),
    };

    const passwordHash = await bcrypt.hash('correct-horse', 4);
    prisma = {
      user: {
        findFirst: jest.fn(async ({ where }: any) => {
          const wanted = where.OR?.[0]?.email;
          return wanted === EMAIL
            ? { id: USER_ID, email: EMAIL, passwordHash }
            : null;
        }),
      },
    };

    controller = new OidcInteractionController({} as any, prisma, redis);
  });

  it('locks the account after five wrong passwords', async () => {
    for (let i = 0; i < 5; i++) {
      await expect(authenticate(EMAIL, 'wrong')).rejects.toThrow(
        UnauthorizedException,
      );
    }

    // Sixth attempt must be refused by the lockout, not by password mismatch.
    await expect(authenticate(EMAIL, 'wrong')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('refuses the correct password while locked out', async () => {
    for (let i = 0; i < 5; i++) {
      await expect(authenticate(EMAIL, 'wrong')).rejects.toThrow(
        UnauthorizedException,
      );
    }

    await expect(authenticate(EMAIL, 'correct-horse')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('throttles guessing at unknown identifiers too', async () => {
    for (let i = 0; i < 5; i++) {
      await expect(authenticate('nobody@example.com', 'x')).rejects.toThrow(
        UnauthorizedException,
      );
    }

    await expect(authenticate('nobody@example.com', 'x')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('keys the unknown-identifier bucket case-insensitively', async () => {
    for (let i = 0; i < 5; i++) {
      await expect(authenticate('Nobody@Example.com', 'x')).rejects.toThrow(
        UnauthorizedException,
      );
    }

    await expect(authenticate('nobody@example.com', 'x')).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('lets a good password through and clears the counter', async () => {
    await expect(authenticate(EMAIL, 'wrong')).rejects.toThrow(
      UnauthorizedException,
    );

    const user = await authenticate(EMAIL, 'correct-horse');
    expect(user.id).toBe(USER_ID);
    expect(redis.del).toHaveBeenCalledWith(`failed:${USER_ID}`);
  });
});
