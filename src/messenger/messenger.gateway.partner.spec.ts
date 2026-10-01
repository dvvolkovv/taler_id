import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { generateKeyPairSync } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as jwt from 'jsonwebtoken';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { AssistantChatService } from '../assistant/assistant-chat.service';
import { ApnsService } from '../common/apns.service';
import { FcmService } from '../common/fcm.service';
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { partnerUserRoom } from '../partner-core/partner.constants';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AiTwinService } from './ai-twin.service';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { PartnerConversationScope } from './partner-conversation-scope.service';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const keyPath = path.join(os.tmpdir(), `messenger-gateway-partner-${process.pid}.pem`);
fs.writeFileSync(keyPath, publicKey);

function fakeClient(token?: string) {
  return {
    handshake: { auth: token ? { token } : {} },
    data: {} as any,
    join: jest.fn(),
    disconnect: jest.fn(),
    emit: jest.fn(),
    use: jest.fn(),
  };
}

describe('MessengerGateway connections', () => {
  let gateway: MessengerGateway;
  let partnerTokens: any;
  let realtime: any;

  beforeEach(async () => {
    partnerTokens = { verify: jest.fn().mockResolvedValue(null) };
    realtime = { registerDisconnector: jest.fn() };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        { provide: MessengerService, useValue: {} },
        { provide: PrismaService, useValue: { user: { update: jest.fn().mockResolvedValue({}) } } },
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: { registerEmitters: jest.fn() } },
        { provide: AiAnalystService, useValue: {} },
        { provide: AssistantChatService, useValue: {} },
        { provide: FcmService, useValue: {} },
        { provide: ApnsService, useValue: {} },
        {
          provide: ConfigService,
          useValue: { get: (key: string) => (key === 'jwt.publicKeyPath' ? keyPath : undefined) },
        },
        { provide: PartnerTokensService, useValue: partnerTokens },
        { provide: PartnerRealtimeService, useValue: realtime },
        {
          provide: PartnerConversationScope,
          useValue: { assertConversation: jest.fn(), assertMessage: jest.fn() },
        },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
  });
  afterEach(() => jest.useRealTimers());
  afterAll(() => fs.unlinkSync(keyPath));

  it('joins the personal room for a TalerID access token without asking the partner store', async () => {
    const token = jwt.sign({ sub: 'u1', typ: 'access' }, privateKey, { algorithm: 'RS256', expiresIn: 60 });
    const client = fakeClient(token);
    await gateway.handleConnection(client as any);
    expect(client.data.userId).toBe('u1');
    expect(client.data.partner).toBeUndefined();
    expect(client.join).toHaveBeenCalledWith('user:u1');
    expect(client.use).toHaveBeenCalledTimes(1);
    expect(partnerTokens.verify).not.toHaveBeenCalled();
  });

  it('accepts a partner token, joins the link room and drops the socket when the token expires', async () => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    const expiresAt = Math.floor(Date.parse('2026-10-01T10:15:00Z') / 1000);
    partnerTokens.verify.mockResolvedValue({ userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt });
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    expect(client.data.partner).toMatchObject({ partnerId: 'p1', grantId: 'g1' });
    // user:<id> is a firehose (AI, calls, billing, "Избранное") — a partner
    // socket must NOT sit there. It gets its own puser:<id> room instead.
    expect(client.join).not.toHaveBeenCalledWith('user:u1');
    expect(client.join).toHaveBeenCalledWith(partnerUserRoom('u1'));
    expect(client.join).toHaveBeenCalledWith('plink:p1:u1');
    jest.advanceTimersByTime(15 * 60 * 1000 - 1);
    expect(client.disconnect).not.toHaveBeenCalled();
    jest.advanceTimersByTime(1);
    expect(client.disconnect).toHaveBeenCalledWith(true);
  });

  it('disconnects an unknown token', async () => {
    const client = fakeClient('garbage');
    await gateway.handleConnection(client as any);
    expect(client.disconnect).toHaveBeenCalled();
    expect(client.join).not.toHaveBeenCalled();
  });

  it('drops a partner socket whose link was revoked while it was connecting', async () => {
    const principal = { userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt: Math.floor(Date.now() / 1000) + 900 };
    partnerTokens.verify.mockResolvedValueOnce(principal).mockResolvedValueOnce(null);
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    expect(client.join).toHaveBeenCalledWith('plink:p1:u1');
    expect(client.disconnect).toHaveBeenCalled();
  });

  it('clears the expiry timer when the socket goes away first', async () => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    partnerTokens.verify.mockResolvedValue({
      userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1',
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    gateway.handleDisconnect(client as any);
    jest.advanceTimersByTime(120_000);
    expect(client.disconnect).not.toHaveBeenCalled();
  });

  it('registers a disconnector that drops every socket of a link', () => {
    const disconnectSockets = jest.fn();
    const server = { in: jest.fn().mockReturnValue({ disconnectSockets }), to: jest.fn() };
    (gateway as any).server = server;
    gateway.onModuleInit();
    const [disconnector] = realtime.registerDisconnector.mock.calls[0];
    disconnector('p1', 'u1');
    expect(server.in).toHaveBeenCalledWith('plink:p1:u1');
    expect(disconnectSockets).toHaveBeenCalledWith(true);
  });
});
