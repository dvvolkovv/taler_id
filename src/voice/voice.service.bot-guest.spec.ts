import { VoiceService } from './voice.service';

/**
 * Гость-бот в публичной комнате.
 *
 * Ассистент партнёра (Linkeon: «Роман · ассистент Дмитрия») входит в комнату
 * тем же публичным `join`, что и человек, и получает такую же личность
 * `guest-<hex>`. Веб-комната отличает ботов по закрытому списку личностей
 * (`meeting-recorder`, `ai-assistant`, `voice-translator`) — и ассистента в
 * нём нет. Поэтому 14.09.2026 запись на сервер не началась: у Романа ждали
 * согласия, которого он дать не может, и диалог висел до конца встречи.
 *
 * Признак бота ставится СЕРВЕРОМ в токен, а не заявляется клиентом в data-
 * канале: атрибуты подписаны вместе с остальным токеном, и подделать их в
 * комнате нельзя.
 */
function claimsOf(token: string): any {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

describe('VoiceService.joinPublicRoom — гость-бот', () => {
  let service: VoiceService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      callLog: { findUnique: jest.fn().mockResolvedValue(null) },
      user: { findUnique: jest.fn().mockResolvedValue(null) },
      publicRoom: {
        findUnique: jest.fn().mockResolvedValue({
          code: 'code-1',
          roomName: 'pub-1',
          isActive: true,
          type: 'permanent',
          expiresAt: null,
          passwordHash: null,
        }),
        update: jest.fn(),
      },
    };

    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      { clearFeed: jest.fn().mockResolvedValue(undefined) } as any,
    );
    (service as any).rooms = { createRoom: jest.fn().mockResolvedValue(undefined) };
    (service as any).participantsCheckRooms = {
      listParticipants: jest.fn().mockResolvedValue([]),
    };
  });

  it('обычный гость ботом не помечен', async () => {
    const { token } = await service.joinPublicRoom('code-1', 'Сергей');
    const grants = claimsOf(token);
    expect(grants.attributes?.bot).toBeUndefined();
    expect(grants.sub).toMatch(/^guest-/);
  });

  it('помечает гостя ботом, когда вход заявлен как ассистент', async () => {
    const { token } = await service.joinPublicRoom(
      'code-1',
      'Роман · ассистент Дмитрия',
      undefined,
      true,
    );
    expect(claimsOf(token).attributes.bot).toBe('1');
  });

  it('бот входит обычным гостем: личность и права те же', async () => {
    // Менять их значило бы чинить согласие на запись ценой всего остального —
    // публикации звука, чата комнаты, учёта участников.
    const { token } = await service.joinPublicRoom('code-1', 'Роман', undefined, true);
    const grants = claimsOf(token);
    expect(grants.sub).toMatch(/^guest-/);
    expect(grants.video.canPublish).toBe(true);
    expect(grants.video.canSubscribe).toBe(true);
    expect(grants.video.room).toBe('pub-1');
  });
});
