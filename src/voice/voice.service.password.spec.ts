import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { VoiceService } from './voice.service';

describe('VoiceService — пароль комнаты', () => {
  let service: VoiceService;
  let prisma: any;
  let hash: string;

  const room = (over: Record<string, unknown> = {}) => ({
    code: 'abc123',
    roomName: 'tmp-1',
    type: 'temporary',
    isActive: true,
    expiresAt: null,
    creatorId: 'creator-1',
    passwordHash: hash,
    ...over,
  });

  beforeAll(async () => {
    hash = await bcrypt.hash('верный', 10);
  });

  beforeEach(() => {
    prisma = {
      publicRoom: { findUnique: jest.fn(), update: jest.fn() },
      user: { findUnique: jest.fn().mockResolvedValue(null) },
    };
    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
    // Комнату в LiveKit создавать незачем — проверяем только правила пароля.
    // (ruRooms сюда не входит: оба join-пути зовут this.rooms напрямую, а не
    // через sfuFor, и ни один код комнаты в этом файле не начинается с
    // call-ru- — participantsCheckClient тоже всегда резолвится в
    // participantsCheckRooms ниже, RU-клиенты в этом spec недостижимы.)
    (service as any).rooms = {
      createRoom: jest.fn().mockResolvedValue(undefined),
    };
    // Заглушено, а не оставлено настоящим клиентом: без этого каждый прогон
    // делал реальную попытку соединения к localhost:7880 из
    // clearChatIfNewMeeting (быстрый отказ локально, но негерметично — если
    // у разработчика поднят настоящий LiveKit, тест пойдёт другой веткой и
    // будет проходить совсем по другой причине). Отказ здесь — не имитация
    // успеха: он воспроизводит то же поведение, которое видит
    // clearChatIfNewMeeting при недоступном LiveKit («лента не тронута», см.
    // её докстринг), только детерминированно и без сети.
    (service as any).participantsCheckRooms = {
      listParticipants: jest
        .fn()
        .mockRejectedValue(new Error('LiveKit недоступен в тестах')),
    };
  });

  it('создатель входит в свою комнату, не вводя собственный пароль', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'creator-1', undefined, 'sess-1'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('создатель входит даже с неверным паролем — поле password для него не проверяется вообще, а не просто необязательно', async () => {
    // Это не домысел из отчёта: правило записано как «не вводит собственный
    // пароль», а не «может ввести пустой». Мобилка и веб-форма входа вполне
    // могут прислать устаревшее значение поля (пользователь когда-то
    // вводил пароль как гость, клиент закэшировал его и подставил снова уже
    // будучи создателем) — это не должно запереть создателя из его же
    // комнаты. `isCreator` в коде выключает всю проверку целиком, а не
    // только пустое значение — здесь это закреплено в самой резкой форме.
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'creator-1', 'неверный', 'sess-1'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('создатель в истёкшую комнату не входит: срок раньше пароля', async () => {
    // Освобождение от пароля — это ОДНА проверка внутри метода, а не общий
    // пропуск для создателя. Самая вероятная следующая правка — «создатель
    // должен всегда попадать в свою комнату» — рискует поднять isCreator
    // выше блока истечения срока; тогда истёкшие комнаты открылись бы
    // своим создателям задним числом, а этот тест — единственное, что об
    // этом узнает (expiresAt больше нигде в этом модуле не тестируется как
    // «уже истекло» — только как null-фикстура).
    prisma.publicRoom.findUnique.mockResolvedValue(
      room({ expiresAt: new Date(Date.now() - 1000) }),
    );
    await expect(
      service.joinPublicRoomAuth('abc123', 'creator-1', undefined, 'sess-1'),
    ).rejects.toThrow(NotFoundException);
  });

  it('чужой залогиненный без пароля не входит', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth(
        'abc123',
        'somebody-else',
        undefined,
        'sess-1',
      ),
    ).rejects.toThrow(ForbiddenException);
  });

  it('чужой залогиненный с неверным паролем не входит', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth(
        'abc123',
        'somebody-else',
        'неверный',
        'sess-1',
      ),
    ).rejects.toThrow(ForbiddenException);
  });

  it('чужой залогиненный с верным паролем входит', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'somebody-else', 'верный', 'sess-1'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('гость с верным паролем входит, с неверным — нет', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'верный'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });

    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'неверный'),
    ).rejects.toThrow(ForbiddenException);
  });

  it('гостю освобождение создателя не достаётся: у гостя нет учётной записи', async () => {
    // joinPublicRoom не принимает userId и нигде не читает room.creatorId —
    // освобождения создателя на этом пути нет не потому, что где-то стоит
    // верная проверка, а потому что самого механизма для него не существует.
    // Тест закрепляет именно отсутствие: пароль в гостевом пути проверяется
    // безусловно, без единого исключения.
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', undefined),
    ).rejects.toThrow(ForbiddenException);
  });

  it('комната без создателя (creatorId: null) не открывается по совпадению null === null', async () => {
    // Не выдуманный случай: `createPublicRoom(userId?: string, ...)` пишет
    // `creatorId: userId ?? null` (voice.service.ts) — метод по сигнатуре
    // допускает публичную комнату без владельца, и тогда в базе у неё ровно
    // `creatorId: null`. (Единственный сегодняшний вызывающий — контроллер
    // за JwtAuthGuard — всегда передаёт настоящий userId, так что путь пока
    // не проторен живым трафиком, но метод и хранимые данные его прямо
    // поддерживают — это не гипотетический сценарий для теста.)
    // Защита от другого «упрощения»: если убрать `!!room.creatorId` и
    // оставить только `room.creatorId === userId`, то такая комната
    // «совпадёт» с любым вызовом, где userId тоже окажется null —
    // отсутствие создателя не должно быть преимуществом.
    prisma.publicRoom.findUnique.mockResolvedValue(room({ creatorId: null }));
    await expect(
      service.joinPublicRoomAuth('abc123', null as any, undefined, 'sess-1'),
    ).rejects.toThrow(ForbiddenException);
  });

  it('в комнате без пароля пароль никому не нужен', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(
      room({ passwordHash: null }),
    );
    await expect(
      service.joinPublicRoom('abc123', 'Гость', undefined),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('несуществующая комната — 404, а не отказ по паролю', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(null);
    await expect(
      service.joinPublicRoomAuth('нет-такой', 'creator-1', undefined, 'sess-1'),
    ).rejects.toThrow(NotFoundException);
  });
});

// Нормализация была односторонней: веб при входе и мобилка при создании
// обрезают пароль, а бэкенд при СОЗДАНИИ хешировал ровно то, что пришло.
// Комната, заведённая через API с паролем " секрет ", была из веба
// недостижима навсегда (веб на входе шлёт "секрет", сверка с хешем
// пробела не сходится) — а пароль из одних пробелов бэкенд хешировал как
// настоящий, хотя обрезающий клиент превращает его в пустую строку и
// отказывается её даже отправлять. Отдельный describe и своя фикстура, а
// не расширение блока выше: там createTemporaryRoom/createPublicRoom не
// вызываются вовсе (room() — статичная фикстура для join-тестов), здесь же
// нужно звать настоящие методы создания и проверять, что они реально
// записали в prisma.publicRoom.create.
describe('VoiceService — нормализация пароля при создании', () => {
  let service: VoiceService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      publicRoom: {
        create: jest.fn().mockResolvedValue(undefined),
        findUnique: jest.fn(),
      },
      user: { findUnique: jest.fn().mockResolvedValue(null) },
    };
    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
    (service as any).rooms = {
      createRoom: jest.fn().mockResolvedValue(undefined),
    };
    (service as any).participantsCheckRooms = {
      listParticipants: jest
        .fn()
        .mockRejectedValue(new Error('LiveKit недоступен в тестах')),
    };
  });

  /**
   * Собирает join-фикстуру из того, что реально ушло в
   * prisma.publicRoom.create, а не заново вручную — иначе тест проверял бы
   * собственные предположения о форме данных, а не то, что метод создания
   * действительно записал.
   *
   * Join всегда идёт через joinPublicRoom (гостевой путь), не
   * joinPublicRoomAuth: у создателя есть освобождение от пароля (Задача 1),
   * и сверка через joinPublicRoomAuth с userId создателя прошла бы
   * ЛЮБЫМ паролем — тест бы ничего не доказывал про сам хеш.
   */
  const roomFromWrite = (
    written: Record<string, any>,
    over: Record<string, unknown> = {},
  ) => ({
    code: 'abc123',
    roomName: written.roomName,
    type: written.type ?? 'temporary',
    isActive: true,
    expiresAt: written.expiresAt ?? null,
    creatorId: written.creatorId,
    passwordHash: written.passwordHash ?? null,
    ...over,
  });

  it('краевые пробелы обрезаются до хеширования: комната, созданная с " секрет ", пускает по "секрет"', async () => {
    await service.createTemporaryRoom('creator-1', 'Заголовок', ' секрет ');
    const written = prisma.publicRoom.create.mock.calls[0][0].data;
    expect(written.passwordHash).toBeTruthy();

    prisma.publicRoom.findUnique.mockResolvedValue(roomFromWrite(written));
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'секрет'),
    ).resolves.toMatchObject({ roomName: written.roomName });
  });

  it('пароль из одних пробелов — это «без пароля»: passwordHash не выставляется, вход работает без пароля', async () => {
    await service.createTemporaryRoom('creator-1', 'Заголовок', '    ');
    const written = prisma.publicRoom.create.mock.calls[0][0].data;
    // Не toBeNull/toBeUndefined: ключа не должно быть в объекте вовсе — та
    // же дисциплина, что и у clientMsgId в sendRoomChatMessage (см.
    // voice.service.chat.spec.ts) — `passwordHash: undefined` тоже прошло
    // бы toBeFalsy, но значило бы другой баг: что нормализация хеширует
    // пустую строку, а её результат случайно не попал в объект другим
    // путём.
    expect('passwordHash' in written).toBe(false);

    prisma.publicRoom.findUnique.mockResolvedValue(roomFromWrite(written));
    await expect(
      service.joinPublicRoom('abc123', 'Гость', undefined),
    ).resolves.toMatchObject({ roomName: written.roomName });
  });

  it('пароль ровно 64 символа проходит, 65 — отказ BadRequestException', async () => {
    await expect(
      service.createTemporaryRoom('creator-1', 'Заголовок', 'x'.repeat(64)),
    ).resolves.toBeDefined();
    expect(
      prisma.publicRoom.create.mock.calls[0][0].data.passwordHash,
    ).toBeTruthy();

    await expect(
      service.createTemporaryRoom('creator-1', 'Заголовок', 'x'.repeat(65)),
    ).rejects.toThrow(BadRequestException);
    // Отказ случился ДО создания комнаты в LiveKit — иначе каждый
    // отклонённый запрос оставлял бы мусорную комнату висеть до истечения
    // emptyTimeout. createRoom и запись в БД случились только один раз —
    // от первого (успешного) запроса выше, не от второго (отклонённого).
    expect((service as any).rooms.createRoom).toHaveBeenCalledTimes(1);
    expect(prisma.publicRoom.create).toHaveBeenCalledTimes(1);
  });

  it('обычный пароль без пробелов ведёт себя как раньше', async () => {
    await service.createTemporaryRoom(
      'creator-1',
      'Заголовок',
      'обычныйПароль',
    );
    const written = prisma.publicRoom.create.mock.calls[0][0].data;
    expect(written.passwordHash).toBeTruthy();

    prisma.publicRoom.findUnique.mockResolvedValue(roomFromWrite(written));
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'обычныйПароль'),
    ).resolves.toMatchObject({ roomName: written.roomName });
  });

  it('createPublicRoom нормализует пароль тем же путём, что и createTemporaryRoom — общий helper, а не забытый второй вызывающий', async () => {
    await service.createPublicRoom('creator-1', 'Заголовок', ' секрет ');
    const written = prisma.publicRoom.create.mock.calls[0][0].data;
    expect(written.passwordHash).toBeTruthy();

    prisma.publicRoom.findUnique.mockResolvedValue(roomFromWrite(written));
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'секрет'),
    ).resolves.toMatchObject({ roomName: written.roomName });
  });
});
