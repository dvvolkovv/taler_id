import { VoiceController } from './voice.controller';

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
      expect(service.sendRoomChatMessage).toHaveBeenCalledWith(
        'call-42',
        'Привет',
        'Гость',
        'guest-abc123',
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

      expect(service.readRoomChat).toHaveBeenCalledWith('call-42', undefined);
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
      expect(service.readRoomChat).toHaveBeenCalledWith('call-42', 5);
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

        expect(service.readRoomChat).toHaveBeenCalledWith('call-42', undefined);
      },
    );

    it('since=0 зовёт сервис с 0, а не с undefined — 0 валидный курсор (граница >= 0)', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 0,
        truncated: false,
      });

      await controller.readRoomChat('call-42', '0');

      expect(service.readRoomChat).toHaveBeenCalledWith('call-42', 0);
    });

    it('пустая строка since= — намеренно курсор 0 (Number(\'\') === 0), а не "с начала = undefined"', async () => {
      service.readRoomChat.mockResolvedValue({
        messages: [],
        seq: 0,
        truncated: false,
      });

      await controller.readRoomChat('call-42', '');

      expect(service.readRoomChat).toHaveBeenCalledWith('call-42', 0);
    });

    it('возвращает наружу ровно то, что вернул сервис', async () => {
      const fakePage = {
        messages: [{ msgId: 'm1', text: 'hi', name: 'A', ts: 1, seq: 1 }],
        seq: 1,
        truncated: false,
      };
      service.readRoomChat.mockResolvedValue(fakePage);

      const result = await controller.readRoomChat('call-42', '0');

      expect(result).toBe(fakePage);
    });
  });
});
