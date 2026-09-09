import { ForbiddenException, NotFoundException } from '@nestjs/common';
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
