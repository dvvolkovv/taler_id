import { RequestMethod } from '@nestjs/common';
import {
  GUARDS_METADATA,
  PATH_METADATA,
  METHOD_METADATA,
} from '@nestjs/common/constants';
import { VoiceController } from './voice.controller';
import { RoomAccessGuard } from './guards/room-access.guard';

// Контроллер создаётся напрямую с мок-сервисом — без поднятия настоящего
// Nest-приложения (тот же приём, что в mcp.controller.spec.ts / app.controller.spec.ts).
// Остальные конструкторские зависимости чат-маршрутам не нужны.
describe('VoiceController — чат комнаты', () => {
  let controller: VoiceController;
  let service: { sendRoomChatMessage: jest.Mock; readRoomChat: jest.Mock };

  beforeEach(() => {
    service = {
      sendRoomChatMessage: jest.fn(),
      readRoomChat: jest.fn(),
    };
    controller = new VoiceController(
      service as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
  });

  describe('sendRoomChat', () => {
    it('передаёт в сервис roomName, текст, имя и актора из декоратора', async () => {
      service.sendRoomChatMessage.mockResolvedValue({
        ts: 1,
        seq: 2,
        msgId: 'm1',
      });

      await controller.sendRoomChat(
        'call-42',
        { text: 'Привет', name: 'Гость' },
        'guest-abc123',
      );

      expect(service.sendRoomChatMessage).toHaveBeenCalledTimes(1);
      // 5-й аргумент (clientMsgId) — undefined, тела без него: явный
      // trailing-undefined в ожидании обязателен, toHaveBeenCalledWith
      // различает "аргумента не было" и "аргумент undefined" по длине
      // массива вызова.
      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        'Привет',
        'Гость',
        'guest-abc123',
        undefined,
      );
    });

    it('другой актор из декоратора уходит в сервис как есть, а не теряется', async () => {
      // Отдельная проверка от предыдущего теста намеренно: она ловит и
      // "актор всегда 'guest-abc123'" (захардкоженный литерал), и "актор
      // потерялся" одновременно — сверяем именно ту строку, что передали.
      service.sendRoomChatMessage.mockResolvedValue({
        ts: 1,
        seq: 2,
        msgId: 'm1',
      });

      await controller.sendRoomChat(
        'call-42',
        { text: 'Привет', name: 'Гость' },
        'user-9f8e#device-ab12',
      );

      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        'Привет',
        'Гость',
        'user-9f8e#device-ab12',
        undefined,
      );
    });

    it('undefined-актор (декоратор ничего не вернул) уходит в сервис как undefined', async () => {
      service.sendRoomChatMessage.mockResolvedValue({
        ts: 1,
        seq: 2,
        msgId: 'm1',
      });

      await controller.sendRoomChat('call-42', {
        text: 'Привет',
        name: 'Гость',
      });

      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        'Привет',
        'Гость',
        undefined,
        undefined,
      );
    });

    it('отсутствующие text/name в теле превращаются в пустые строки, а не в undefined', async () => {
      service.sendRoomChatMessage.mockResolvedValue({
        ts: 1,
        seq: 2,
        msgId: 'm1',
      });

      await controller.sendRoomChat('call-42', {}, 'actor-1');

      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        '',
        '',
        'actor-1',
        undefined,
      );
    });

    it('полностью отсутствующее тело тоже превращается в пустые строки', async () => {
      service.sendRoomChatMessage.mockResolvedValue({
        ts: 1,
        seq: 2,
        msgId: 'm1',
      });

      await controller.sendRoomChat('call-42', undefined as any, 'actor-1');

      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        '',
        '',
        'actor-1',
        undefined,
      );
    });

    it('clientMsgId из тела уходит в сервис пятым аргументом', async () => {
      service.sendRoomChatMessage.mockResolvedValue({
        ts: 1,
        seq: 2,
        msgId: 'c_abcd1234_local-1',
      });

      await controller.sendRoomChat(
        'call-42',
        { text: 'Привет', name: 'Гость', clientMsgId: 'local-1' },
        'guest-abc123',
      );

      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        'Привет',
        'Гость',
        'guest-abc123',
        'local-1',
      );
    });

    it('возвращает наружу ровно то, что вернул сервис', async () => {
      const fakeResult = { ts: 555, seq: 9, msgId: 'server_xyz' };
      service.sendRoomChatMessage.mockResolvedValue(fakeResult);

      const result = await controller.sendRoomChat(
        'call-42',
        { text: 'Привет', name: 'Гость' },
        'actor-1',
      );

      expect(result).toBe(fakeResult);
    });
  });

  describe('readRoomChat', () => {
    it('без since зовёт сервис с undefined', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 0,
        truncated: false,
      });

      await controller.readRoomChat('call-42');

      // 3-й аргумент (actor) — тоже undefined: декоратор в этом вызове не
      // участвует (controller дёрнут напрямую), явный trailing-undefined
      // обязателен по той же причине, что и в тестах sendRoomChat выше.
      expect(service.readRoomChat).toHaveBeenCalledWith(
        'call-42',
        undefined,
        undefined,
      );
    });

    it('?since=5 зовёт сервис числом 5, а не строкой "5"', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 5,
        truncated: false,
      });

      await controller.readRoomChat('call-42', '5');

      // toHaveBeenCalledWith сравнивает по значению И типу — если бы разбор
      // курсора не преобразовал строку в число, '5' !== 5 провалил бы тест.
      expect(service.readRoomChat).toHaveBeenCalledWith(
        'call-42',
        5,
        undefined,
      );
    });

    it.each(['abc', '-1'])(
      'мусор в курсоре (%s) превращается в undefined',
      async (bad) => {
        service.readRoomChat.mockResolvedValue({
          messages: [],
          seq: 0,
          truncated: false,
        });

        await controller.readRoomChat('call-42', bad);

        expect(service.readRoomChat).toHaveBeenCalledWith(
          'call-42',
          undefined,
          undefined,
        );
      },
    );

    it('since=0 зовёт сервис с 0, а не с undefined — 0 валидный курсор (граница >= 0)', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 0,
        truncated: false,
      });

      await controller.readRoomChat('call-42', '0');

      expect(service.readRoomChat).toHaveBeenCalledWith(
        'call-42',
        0,
        undefined,
      );
    });

    it('пустая строка since= — намеренно курсор 0 (Number(\'\') === 0), а не "с начала = undefined"', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 0,
        truncated: false,
      });

      await controller.readRoomChat('call-42', '');

      expect(service.readRoomChat).toHaveBeenCalledWith(
        'call-42',
        0,
        undefined,
      );
    });

    it('actor из декоратора уходит в сервис третьим аргументом — read() строит по нему own', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 0,
        truncated: false,
      });

      await controller.readRoomChat('call-42', '0', 'guest-abc123');

      expect(service.readRoomChat).toHaveBeenCalledWith(
        'call-42',
        0,
        'guest-abc123',
      );
    });

    it('возвращает наружу ровно то, что вернул сервис', async () => {
      const fakePage = {
        messages: [
          { msgId: 'm1', text: 'hi', name: 'A', ts: 1, seq: 1, own: true },
        ],
        seq: 1,
        truncated: false,
      };
      service.readRoomChat.mockResolvedValue(fakePage);

      const result = await controller.readRoomChat('call-42', '0');

      expect(result).toBe(fakePage);
    });
  });
});

// C1 (ревью, 4-й круг подряд на этом классе дефектов): ни один тест выше
// не проверяет, что маршрут вообще под guard'ом — они создают контроллер
// напрямую и зовут методы как обычные функции, а HTTP-уровень Nest
// (`@UseGuards`, `@Post`/`@Get` роутинг) в этом обходе не участвует.
// Удаление `@UseGuards(RoomAccessGuard)` со строки объявления метода или
// переименование маршрута оставляли всё выше зелёным — ручка отдаёт
// переписку встречи, и без guard'а отдаёт её любому предъявителю токена.
// Единственное место, где это закреплено, — метаданные, которые кладут на
// сам метод класса декораторы; читаем их напрямую тем же Reflect, которым
// пользуется сам Nest при построении роутов, без поднятия приложения.
describe('маршруты чата закреплены RoomAccessGuard', () => {
  it('sendRoomChat: POST rooms/:roomName/chat под RoomAccessGuard', () => {
    // Метод берётся как значение, чтобы прочитать его метаданные, а не
    // вызвать, — unbound-method здесь ложное срабатывание.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const h = VoiceController.prototype.sendRoomChat;
    expect(Reflect.getMetadata(GUARDS_METADATA, h)).toContain(RoomAccessGuard);
    expect(Reflect.getMetadata(PATH_METADATA, h)).toBe('rooms/:roomName/chat');
    expect(Reflect.getMetadata(METHOD_METADATA, h)).toBe(RequestMethod.POST);
  });

  it('readRoomChat: GET rooms/:roomName/chat под RoomAccessGuard', () => {
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const h = VoiceController.prototype.readRoomChat;
    expect(Reflect.getMetadata(GUARDS_METADATA, h)).toContain(RoomAccessGuard);
    expect(Reflect.getMetadata(PATH_METADATA, h)).toBe('rooms/:roomName/chat');
    expect(Reflect.getMetadata(METHOD_METADATA, h)).toBe(RequestMethod.GET);
  });
});
