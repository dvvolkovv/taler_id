import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { generateKeyPairSync } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as jwt from 'jsonwebtoken';
import { Public } from '../common/decorators/public.decorator';
import { MessengerAuthGuard } from './messenger-auth.guard';
import { PartnerAllowed } from './partner-allowed.decorator';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const keyPath = path.join(
  os.tmpdir(),
  `messenger-auth-guard-${process.pid}.pem`,
);
fs.writeFileSync(keyPath, publicKey);

class Handlers {
  @PartnerAllowed({ conversationParam: 'id' })
  allowed() {}

  @PartnerAllowed({ messageParam: 'id' })
  byMessage() {}

  notForPartners() {}

  @Public()
  open() {}
}

function ctx(handler: keyof Handlers, req: any) {
  return {
    getHandler: () => Handlers.prototype[handler],
    getClass: () => Handlers,
    switchToHttp: () => ({ getRequest: () => req }),
  } as any;
}

const principal = {
  userId: 'u1',
  partnerId: 'p1',
  partnerSlug: 'nadi',
  grantId: 'g1',
  expiresAt: 1_900_000_000,
};

describe('MessengerAuthGuard', () => {
  let tokens: any;
  let scope: any;
  let guard: MessengerAuthGuard;

  beforeEach(() => {
    tokens = { verify: jest.fn().mockResolvedValue(null) };
    scope = {
      assertConversation: jest.fn().mockResolvedValue(undefined),
      assertMessage: jest.fn().mockResolvedValue(undefined),
    };
    const config: any = {
      get: (key: string) => (key === 'jwt.publicKeyPath' ? keyPath : undefined),
    };
    guard = new MessengerAuthGuard(new Reflector(), tokens, scope, config);
  });
  afterAll(() => fs.unlinkSync(keyPath));

  it('lets public routes through without a token', async () => {
    await expect(guard.canActivate(ctx('open', { headers: {} }))).resolves.toBe(
      true,
    );
  });

  it('accepts the TalerID access token exactly as before, on any handler', async () => {
    const token = jwt.sign({ sub: 'u1', typ: 'access' }, privateKey, {
      algorithm: 'RS256',
      expiresIn: 60,
    });
    const req: any = {
      headers: { authorization: `Bearer ${token}` },
      params: {},
    };
    await expect(guard.canActivate(ctx('notForPartners', req))).resolves.toBe(
      true,
    );
    expect(req.user).toMatchObject({ sub: 'u1', typ: 'access' });
    expect(tokens.verify).not.toHaveBeenCalled();
  });

  it('does not take an OIDC id_token signed with the same key for an access token', async () => {
    const idToken = jwt.sign(
      { sub: 'u1', aud: 'client', iss: 'https://x/oauth' },
      privateKey,
      {
        algorithm: 'RS256',
        expiresIn: 60,
      },
    );
    const req = { headers: { authorization: `Bearer ${idToken}` }, params: {} };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('lets a partner token into an allowed handler and checks the conversation type', async () => {
    tokens.verify.mockResolvedValue(principal);
    const req: any = {
      headers: { authorization: 'Bearer opaque' },
      params: { id: 'conv-1' },
    };
    await expect(guard.canActivate(ctx('allowed', req))).resolves.toBe(true);
    expect(req.user).toEqual({ sub: 'u1', partner: principal });
    expect(scope.assertConversation).toHaveBeenCalledWith('conv-1');
  });

  it('checks the conversation of the message on message routes', async () => {
    tokens.verify.mockResolvedValue(principal);
    await guard.canActivate(
      ctx('byMessage', {
        headers: { authorization: 'Bearer opaque' },
        params: { id: 'msg-1' },
      }),
    );
    expect(scope.assertMessage).toHaveBeenCalledWith('msg-1');
  });

  it('403 for a partner token on a handler not opened to partners', async () => {
    tokens.verify.mockResolvedValue(principal);
    const req = { headers: { authorization: 'Bearer opaque' }, params: {} };
    await expect(guard.canActivate(ctx('notForPartners', req))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('passes on the 403 for a conversation of another type', async () => {
    tokens.verify.mockResolvedValue(principal);
    scope.assertConversation.mockRejectedValue(
      new ForbiddenException('not_available_for_partner'),
    );
    const req = {
      headers: { authorization: 'Bearer opaque' },
      params: { id: 'channel-1' },
    };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it.each([undefined, 'Basic abc', 'Bearer'])(
    '401 for authorization header %p',
    async (header: string | undefined) => {
      const req = { headers: { authorization: header }, params: {} };
      await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(
        UnauthorizedException,
      );
    },
  );

  it('401 for an unknown token', async () => {
    const req = { headers: { authorization: 'Bearer nope' }, params: {} };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
