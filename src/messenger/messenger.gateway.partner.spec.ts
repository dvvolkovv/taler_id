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

/**
 * Минимальный fake, который всё же ведёт себя как настоящий Socket на двух
 * пунктах, важных для этого файла: `connected` реально падает и `once`
 * реально вызывает слушателя, когда сокет "уходит" — иначе тест на очистку
 * таймера по disconnect ничего не проверяет.
 */
function fakeClient(token?: string) {
  const disconnectListeners: Array<() => void> = [];
  const client: any = {
    handshake: { auth: token ? { token } : {} },
    data: {} as any,
    connected: true,
    join: jest.fn(),
    disconnect: jest.fn(() => {
      client.connected = false;
      disconnectListeners.slice().forEach((fn) => fn());
    }),
    emit: jest.fn(),
    use: jest.fn(),
    once: jest.fn((event: string, fn: () => void) => {
      if (event === 'disconnect') disconnectListeners.push(fn);
    }),
  };
  return client;
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

  it('accepts a partner token: joins plink, re-verifies, only then joins puser, and drops the socket when the token expires', async () => {
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
    // Order matters: plink first, re-verify in between, puser last — so a
    // revocation caught by the second verify() never had a window where the
    // socket sat in puser:<id> able to receive mirrored events.
    const joinedRooms = client.join.mock.calls.map((c: any[]) => c[0]);
    expect(joinedRooms.indexOf('plink:p1:u1')).toBeLessThan(joinedRooms.indexOf(partnerUserRoom('u1')));
    expect(partnerTokens.verify).toHaveBeenCalledTimes(2);
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

  it('drops a partner socket whose link was revoked while it was connecting, before it ever joins puser', async () => {
    const principal = { userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt: Math.floor(Date.now() / 1000) + 900 };
    partnerTokens.verify.mockResolvedValueOnce(principal).mockResolvedValueOnce(null);
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    expect(client.join).toHaveBeenCalledWith('plink:p1:u1');
    expect(client.join).not.toHaveBeenCalledWith(partnerUserRoom('u1'));
    expect(client.disconnect).toHaveBeenCalled();
  });

  it('does not arm the expiry timer if the socket disconnected on its own while the checks were running', async () => {
    const principal = { userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt: Math.floor(Date.now() / 1000) + 900 };
    const client = fakeClient('opaque');
    partnerTokens.verify.mockResolvedValueOnce(principal).mockImplementationOnce(async () => {
      client.connected = false; // клиент ушёл сам, пока шла вторая проверка
      return principal;
    });
    const result = await (gateway as any).authenticateSocket(client);
    expect(result).toBe(false);
    expect(client.join).toHaveBeenCalledWith(partnerUserRoom('u1'));
    expect(client.once).not.toHaveBeenCalled(); // не повесили слушатель на мёртвый сокет
    expect(client.disconnect).not.toHaveBeenCalled(); // и не трогали — он уже ушёл
  });

  it('clears the expiry timer when the socket goes away first (never fires a second disconnect)', async () => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    partnerTokens.verify.mockResolvedValue({
      userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1',
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    client.disconnect(); // симулируем, что сокет сам закрылся
    expect(client.disconnect).toHaveBeenCalledTimes(1);
    jest.advanceTimersByTime(120_000);
    // Если бы таймер не очистился при disconnect, он бы вызвал disconnect(true)
    // ещё раз через 60с.
    expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  /**
   * Регрессия (живой two-node review): fetchSockets() с соседней ноды
   * сериализует client.data в JSON через Redis-адаптер. Timeout —
   * циклическая структура → `TypeError: Converting circular structure to
   * JSON` внутри async request-обработчика адаптера → необработанная
   * ошибка → процесс падает. Один DM человеку с открытым nadi убивал ноду,
   * державшую его сокет.
   */
  it('never puts anything non-JSON-safe into client.data (regression: killed the OTHER node via fetchSockets)', async () => {
    // Настоящие таймеры: Jest'овский fake-таймер — простой объект без
    // циклических ссылок и не воспроизводит баг. Настоящий Timeout от
    // Node — воспроизводит (проверено отдельно: JSON.stringify на нём
    // падает с "Converting circular structure to JSON").
    partnerTokens.verify.mockResolvedValue({
      userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1',
      expiresAt: Math.floor(Date.now() / 1000) + 900,
    });
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    expect(() => JSON.stringify(client.data)).not.toThrow();
    expect(client.data.partnerExpiryTimer).toBeUndefined();
    expect(client.data.partnerConversations).toBeUndefined();
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
