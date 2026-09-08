import {
  BadRequestException,
  HttpException,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash } from 'crypto';
import { VoiceService, buildChatMsgId } from './voice.service';

/** Пересчитывает пространство имён независимо от buildChatMsgId — тест не
 *  должен доказывать себя же самим собой. Если бы тест звал buildChatMsgId
 *  и сверял результат с buildChatMsgId, мутант, меняющий алгоритм хеша
 *  (например sha256 → md5) или длину среза (8 → 6 символов), остался бы
 *  незамеченным: обе стороны сравнения изменились бы синхронно. */
const namespacedId = (actor: string, clientMsgId: string) =>
  `c_${createHash('sha256').update(actor).digest('hex').slice(0, 8)}_${clientMsgId}`;

describe('VoiceService.sendRoomChatMessage', () => {
  let service: VoiceService;
  let euSendData: jest.Mock;
  let ruSendData: jest.Mock;

  const decode = (mock: jest.Mock, i = 0) =>
    JSON.parse(Buffer.from(mock.mock.calls[i][1]).toString('utf8'));

  let buffer: {
    append: jest.Mock;
    remove: jest.Mock;
    hitRateLimit: jest.Mock;
  };

  beforeEach(() => {
    buffer = {
      append: jest.fn(async (_room: string, entry: any) => ({
        ...entry,
        seq: 7,
      })),
      remove: jest.fn().mockResolvedValue(1),
      hitRateLimit: jest.fn().mockResolvedValue(false),
    };
    service = new VoiceService(
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      buffer as any,
    );
    euSendData = jest.fn().mockResolvedValue(undefined);
    ruSendData = jest.fn().mockResolvedValue(undefined);
    (service as any).rooms = { sendData: euSendData };
    (service as any).ruRooms = { sendData: ruSendData };
  });

  it('публикует пакет chat_message в комнату', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');

    expect(euSendData).toHaveBeenCalledTimes(1);
    expect(euSendData.mock.calls[0][0]).toBe('call-42');

    const packet = decode(euSendData);
    expect(packet.type).toBe('chat_message');
    expect(packet.text).toBe('Привет');
    expect(packet.name).toBe('Ассистент');
    expect(typeof packet.ts).toBe('number');
    expect(typeof packet.msgId).toBe('string');
  });

  it('шлёт надёжным каналом, а не lossy', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');
    // DataPacket_Kind.RELIABLE === 0 в livekit-server-sdk
    expect(euSendData.mock.calls[0][2]).toBe(0);
  });

  it('передаёт SendDataOptions — иначе вызов уходит в deprecated-перегрузку', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');
    expect(euSendData.mock.calls[0][3]).toEqual({});
  });

  it('CIS-комнату обслуживает российский SFU', async () => {
    await service.sendRoomChatMessage('call-ru-7', 'Привет', 'Ассистент');
    expect(ruSendData).toHaveBeenCalledTimes(1);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('обрезает пробелы по краям', async () => {
    await service.sendRoomChatMessage('call-42', '  Привет  ', 'Ассистент');
    expect(decode(euSendData).text).toBe('Привет');
  });

  it('отказывает на пустом тексте и ничего не шлёт', async () => {
    await expect(
      service.sendRoomChatMessage('call-42', '   ', 'Ассистент'),
    ).rejects.toThrow(BadRequestException);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('отказывает на тексте длиннее 500 символов', async () => {
    await expect(
      service.sendRoomChatMessage('call-42', 'x'.repeat(501), 'Ассистент'),
    ).rejects.toThrow(BadRequestException);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('ровно 500 символов проходит', async () => {
    await service.sendRoomChatMessage('call-42', 'x'.repeat(500), 'Ассистент');
    expect(decode(euSendData).text).toHaveLength(500);
  });

  it('отказывает на не-строковом тексте и ничего не шлёт', async () => {
    await expect(
      service.sendRoomChatMessage('call-42', 42 as any, 'Ассистент'),
    ).rejects.toThrow(BadRequestException);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('обрезает имя до 64 символов', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'и'.repeat(100));
    expect(decode(euSendData).name).toBe('и'.repeat(64));
  });

  it('подставляет дефолтное имя на пустом и не-строковом', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', '   ');
    expect(decode(euSendData).name).toBe('Taler ID');

    await service.sendRoomChatMessage('call-42', 'Привет', undefined as any);
    expect(decode(euSendData, 1).name).toBe('Taler ID');
  });

  it('пробрасывает отказ sendData наружу', async () => {
    euSendData.mockRejectedValue(new Error('lk down'));
    await expect(
      service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент'),
    ).rejects.toThrow('lk down');
  });

  it('каждый пакет получает свой msgId', async () => {
    await service.sendRoomChatMessage('call-42', 'раз', 'Ассистент');
    await service.sendRoomChatMessage('call-42', 'два', 'Ассистент');
    expect(decode(euSendData).msgId).not.toBe(decode(euSendData, 1).msgId);
  });

  it('кладёт сообщение в ленту и возвращает его номер', async () => {
    const res = await service.sendRoomChatMessage(
      'call-42',
      'Привет',
      'Ассистент',
    );

    expect(buffer.append).toHaveBeenCalledTimes(1);
    expect(buffer.append.mock.calls[0][0]).toBe('call-42');
    expect(buffer.append.mock.calls[0][1]).toMatchObject({
      text: 'Привет',
      name: 'Ассистент',
    });
    expect(res.seq).toBe(7);
    expect(res.msgId).toBe(decode(euSendData).msgId);
    expect(typeof res.ts).toBe('number');
  });

  it('номер уезжает в комнату вместе с пакетом', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');
    expect(decode(euSendData).seq).toBe(7);
  });

  it('снимает запись из ленты, если рассылка не удалась', async () => {
    euSendData.mockRejectedValue(new Error('lk down'));
    await expect(
      service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент'),
    ).rejects.toThrow('lk down');
    expect(buffer.remove).toHaveBeenCalledTimes(1);
    expect(buffer.remove.mock.calls[0][0]).toBe('call-42');
    // Тождество, а не toMatchObject: LREM в проде сравнивает строки, поэтому
    // клон с переставленными полями (тот же набор значений, другой JSON.
    // stringify) прошёл бы toMatchObject, но в бою remove() ничего не нашёл
    // бы и откат молча перестал бы работать. append — async-мок, поэтому
    // mock.results[0].value — это Promise; сравнивать нужно с тем, что он
    // резолвит, а не с обёрткой.
    const appended = await buffer.append.mock.results[0].value;
    expect(buffer.remove.mock.calls[0][1]).toBe(appended);
  });

  it('на пустом тексте до ленты не доходит', async () => {
    await expect(
      service.sendRoomChatMessage('call-42', '  ', 'Ассистент'),
    ).rejects.toThrow(BadRequestException);
    expect(buffer.append).not.toHaveBeenCalled();
  });

  it('превышенный потолок — 429, и ничего не отправляется', async () => {
    buffer.hitRateLimit.mockResolvedValue(true);
    await expect(
      service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент', 'guest-1'),
    ).rejects.toThrow(HttpException);
    expect(buffer.append).not.toHaveBeenCalled();
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('без актора потолок не проверяется', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');
    expect(buffer.hitRateLimit).not.toHaveBeenCalled();
  });

  it('пишет в ленту раньше, чем рассылает', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');
    // invocationCallOrder — общий счётчик вызовов по всем мокам в тесте;
    // меньше номер — раньше вызов. Порядок операций — весь смысл этой
    // задачи: если бы рассылка ушла до записи, читающий историю через API
    // не увидел бы то, что уже разослано в комнату.
    expect(buffer.append.mock.invocationCallOrder[0]).toBeLessThan(
      euSendData.mock.invocationCallOrder[0],
    );
  });

  it('лента и рассылка используют одно и то же имя комнаты (включая CIS-маршрут)', async () => {
    await service.sendRoomChatMessage('call-ru-7', 'Привет', 'Ассистент');
    // call-ru-* уходит на отдельный SFU (ruRooms/ruSendData) — самое опасное
    // место для расхождения: запись в буфер под одним именем, рассылка под
    // другим (или не в ту комнату) прошла бы незамеченной, потому что у
    // каждого мока свой собственный набор вызовов.
    expect(buffer.append.mock.calls[0][0]).toBe('call-ru-7');
    expect(ruSendData.mock.calls[0][0]).toBe('call-ru-7');
  });

  it('не рассылает, если запись в ленту отказала, и превращает отказ хранилища в 503', async () => {
    buffer.append.mockRejectedValue(new Error('redis down'));
    await expect(
      service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент'),
    ).rejects.toThrow(ServiceUnavailableException);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('превышенный потолок остаётся 429, а не превращается в отказ хранилища (503)', async () => {
    // ServiceUnavailableException — тоже HttpException, поэтому одного
    // toThrow(HttpException) (как в тесте про 429 выше) недостаточно: он бы
    // не заметил, если бы catch-обёртка вокруг hitRateLimit/append случайно
    // проглотила наш собственный 429 и переупаковала его в 503. Проверяем
    // конкретный класс и код статуса напрямую.
    buffer.hitRateLimit.mockResolvedValue(true);
    let caught: unknown;
    try {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(HttpException);
    expect(caught).not.toBeInstanceOf(ServiceUnavailableException);
    expect((caught as HttpException).getStatus()).toBe(
      HttpStatus.TOO_MANY_REQUESTS,
    );
  });

  it('предупреждает в логе, если remove() вернул 0 после неудачной рассылки', async () => {
    euSendData.mockRejectedValue(new Error('lk down'));
    buffer.remove.mockResolvedValue(0);
    const warnSpy = jest.spyOn((service as any).log, 'warn');
    await expect(
      service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент'),
    ).rejects.toThrow('lk down');
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  // clientMsgId: клиент, знающий msgId ДО отправки, может отрисовать пузырь
  // сразу и пометить id обработанным раньше, чем придёт echo из data-канала
  // — без этого эхо гарантированно обгоняет HTTP-ответ (append/sendData
  // порядок проверен тестом «пишет в ленту раньше, чем рассылает» выше, но
  // sendData всё равно уходит в комнату до того, как этот await вернёт
  // управление контроллеру).
  describe('clientMsgId', () => {
    it('клиентский id принимается и попадает в итоговый msgId — и в ответе, и в пакете', async () => {
      const res = await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
        'abc123',
      );
      const expected = namespacedId('guest-1', 'abc123');
      expect(res.msgId).toBe(expected);
      expect(decode(euSendData).msgId).toBe(expected);
    });

    it('два разных отправителя с одинаковым clientMsgId получают разные итоговые msgId — иначе один участник подавил бы сообщение другого обычной дедупликацией по msgId', async () => {
      const first = await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
        'same-id',
      );
      const second = await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-2',
        'same-id',
      );
      expect(first.msgId).not.toBe(second.msgId);
      expect(first.msgId).toBe(namespacedId('guest-1', 'same-id'));
      expect(second.msgId).toBe(namespacedId('guest-2', 'same-id'));
    });

    it.each([
      ['пустая строка', ''],
      ['длиннее 64 символов', 'x'.repeat(65)],
      ['посторонний символ (пробел)', 'abc def'],
      ['посторонний символ (точка)', 'abc.def'],
      ['не строка — число', 42],
      ['не строка — null', null],
      ['не строка — объект', { id: 'x' }],
      ['не строка — массив', ['x']],
    ])(
      'негодный clientMsgId (%s) молча заменяется серверным uuid, запрос не падает',
      async (_label, bad) => {
        const res = await service.sendRoomChatMessage(
          'call-42',
          'Привет',
          'Ассистент',
          'guest-1',
          bad,
        );
        expect(res.msgId).toMatch(/^server_/);
      },
    );

    it('без actor клиентский id игнорируется — пространство имён строить не из чего', async () => {
      const res = await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        undefined,
        'abc123',
      );
      expect(res.msgId).toMatch(/^server_/);
    });
  });

  // clientMsgId-эхо в пакете: namespaced msgId (c_<hash(actor)>_<id>) решает
  // подделку, но хеш считает сервер — клиент не может предсказать msgId ДО
  // отправки, а значит и не может пометить его обработанным раньше echo.
  // Чтобы разорвать именно эту гонку, пакет несёт clientMsgId ОТДЕЛЬНЫМ
  // полем, ровно тем значением, что прислал клиент (не в пространстве имён):
  // автор сравнивает строки напрямую, остальным участникам поле безразлично.
  describe('clientMsgId-эхо в пакете data-канала', () => {
    it('годный clientMsgId уходит в пакет эхом отдельным полем, msgId остаётся namespaced', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
        'abc123',
      );
      // Каст к Record<string, unknown>, а не голый decode() (тот any) — три
      // новых теста ниже держат декодированный пакет в переменной для
      // нескольких проверок подряд, и без каста каждая такая переменная
      // добавляла бы unsafe-assignment/-member-access поверх уже
      // существующих в файле (decode() как таковой лениво типизирован
      // намеренно, менять его ради четырёх мест не стали).
      const packet = decode(euSendData) as Record<string, unknown>;
      expect(packet.clientMsgId).toBe('abc123');
      expect(packet.msgId).toBe(namespacedId('guest-1', 'abc123'));
    });

    it.each([
      ['посторонний символ', 'bad id with spaces'],
      ['не строка', 42],
    ])(
      'негодный clientMsgId (%s) не попадает в пакет вовсе — ни как undefined, ни как пустая строка',
      async (_label, bad) => {
        await service.sendRoomChatMessage(
          'call-42',
          'Привет',
          'Ассистент',
          'guest-1',
          bad,
        );
        const packet = decode(euSendData) as Record<string, unknown>;
        expect('clientMsgId' in packet).toBe(false);
        // Регрессия по соседству: неудачный clientMsgId не должен тайно
        // испортить и построение msgId — он остаётся обычным server_<uuid>.
        expect(packet.msgId).toMatch(/^server_/);
      },
    );

    it('клиент ничего не прислал — ключа clientMsgId в пакете нет', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
      );
      const packet = decode(euSendData) as Record<string, unknown>;
      expect('clientMsgId' in packet).toBe(false);
    });

    it('без actor валидный clientMsgId тоже не попадает в пакет — та же граница, что и у построения msgId', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        undefined,
        'abc123',
      );
      const packet = decode(euSendData) as Record<string, unknown>;
      expect('clientMsgId' in packet).toBe(false);
      expect(packet.msgId).toMatch(/^server_/);
    });
  });

  // actor: нужен буферу для own (см. RoomChatBufferService.read), но не
  // должен утечь ни в комнату (data-канал видят все участники, включая
  // гостей), ни в HTTP-ответ POST (его тоже мог бы прочитать кто угодно на
  // пути — meeting-recorder делает то же самое от лица бэкенда).
  describe('actor в записи ленты и его отсутствие в исходящих данных', () => {
    it('actor уходит в буфер вместе с записью', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
      );
      expect(buffer.append.mock.calls[0][1]).toMatchObject({
        actor: 'guest-1',
      });
    });

    it('actor не попадает в пакет data-канала — спред по stored не должен разложить его туда', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
      );
      expect(decode(euSendData)).not.toHaveProperty('actor');
    });

    it('actor не попадает в ответ метода — только ts/seq/msgId', async () => {
      const res = await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
      );
      expect(Object.keys(res).sort()).toEqual(['msgId', 'seq', 'ts'].sort());
    });
  });

  // clientMsgId в записи ленты: без этого GET-ответ на историю не может
  // сообщить клиенту, какую строку истории он уже отрисовал оптимистично.
  // Баг воспроизводился так: пока летит первый GET, пользователь отправляет
  // сообщение; сервер дописывает его в ленту раньше, чем приходит echo из
  // data-канала, и ответ на этот GET прилетает с сообщением, для которого
  // own:true, но сопоставить не с чем — клиент рисовал второй пузырь.
  // RoomChatBufferService.read() уже отдаёт clientMsgId насквозь (см. её
  // тесты) — единственное, чего не хватало, это положить его в запись
  // здесь, при отправке.
  describe('clientMsgId в записи ленты', () => {
    it('годный clientMsgId уходит в буфер вместе с записью — ровно то же значение, что и в пакете', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
        'abc123',
      );
      expect(buffer.append.mock.calls[0][1]).toMatchObject({
        clientMsgId: 'abc123',
      });
    });

    it.each([
      ['посторонний символ', 'bad id with spaces'],
      ['не строка', 42],
    ])(
      'негодный clientMsgId (%s) не попадает в запись буфера вовсе — то же правило, что и для пакета',
      async (_label, bad) => {
        await service.sendRoomChatMessage(
          'call-42',
          'Привет',
          'Ассистент',
          'guest-1',
          bad,
        );
        expect(buffer.append.mock.calls[0][1]).not.toHaveProperty(
          'clientMsgId',
        );
      },
    );

    it('без actor валидный clientMsgId тоже не попадает в запись — та же граница, что у пакета и у msgId', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        undefined,
        'abc123',
      );
      expect(buffer.append.mock.calls[0][1]).not.toHaveProperty('clientMsgId');
    });

    it('источник один: clientMsgId в пакете — то же значение, что ушло в запись буфера, не отдельная проверка', async () => {
      await service.sendRoomChatMessage(
        'call-42',
        'Привет',
        'Ассистент',
        'guest-1',
        'abc123',
      );
      const sentToBuffer = buffer.append.mock.calls[0][1] as {
        clientMsgId?: string;
      };
      expect(decode(euSendData).clientMsgId).toBe(sentToBuffer.clientMsgId);
    });
  });
});

describe('buildChatMsgId (пространство имён итогового msgId)', () => {
  it('валидный clientMsgId + actor → id в пространстве имён отправителя', () => {
    expect(buildChatMsgId('guest-1', 'abc123')).toBe(
      namespacedId('guest-1', 'abc123'),
    );
  });

  it('главный тест про подделку: одинаковый clientMsgId у разных отправителей даёт разные id', () => {
    const a = buildChatMsgId('guest-1', 'same-id');
    const b = buildChatMsgId('guest-2', 'same-id');
    expect(a).not.toBe(b);
    expect(a).toBe(namespacedId('guest-1', 'same-id'));
    expect(b).toBe(namespacedId('guest-2', 'same-id'));
  });

  it('тот же actor и тот же clientMsgId — тот же id (детерминированно, без случайной соли)', () => {
    expect(buildChatMsgId('guest-1', 'same-id')).toBe(
      buildChatMsgId('guest-1', 'same-id'),
    );
  });

  it('без actor (undefined) — серверный uuid, даже если clientMsgId валиден', () => {
    expect(buildChatMsgId(undefined, 'abc123')).toMatch(/^server_/);
  });

  it('actor — пустая строка ведёт себя как «без актора»', () => {
    // Настоящий RoomActor никогда не кладёт '' (см. её докстринг), но actor
    // типизирован как string | undefined, и пустая строка технически
    // допустима — пустое пространство имён было бы хуже отсутствующего: оно
    // не идентифицирует никого, но выглядит как валидный namespace.
    expect(buildChatMsgId('', 'abc123')).toMatch(/^server_/);
  });

  it.each([
    ['пустая строка', ''],
    ['длиннее 64 символов', 'x'.repeat(65)],
    ['пробел внутри', 'abc def'],
    ['точка', 'abc.def'],
    ['не строка — число', 42],
    ['не строка — null', null],
    ['не строка — undefined', undefined],
    ['не строка — объект', { id: 'x' }],
  ])('невалидный clientMsgId (%s) → серверный uuid', (_label, bad) => {
    expect(buildChatMsgId('guest-1', bad)).toMatch(/^server_/);
  });

  it('ровно 64 символа — валидная граница', () => {
    const id = 'x'.repeat(64);
    expect(buildChatMsgId('guest-1', id)).toBe(namespacedId('guest-1', id));
  });

  it('ровно 1 символ — валидная граница', () => {
    expect(buildChatMsgId('guest-1', 'x')).toBe(namespacedId('guest-1', 'x'));
  });

  it('подчёркивание и дефис — валидные символы', () => {
    const id = 'abc_123-xyz';
    expect(buildChatMsgId('guest-1', id)).toBe(namespacedId('guest-1', id));
  });

  it('каждый вызов без валидного clientMsgId даёт свой uuid — фолбэк не коллапсирует в общий id для всех', () => {
    const a = buildChatMsgId('guest-1', undefined);
    const b = buildChatMsgId('guest-1', undefined);
    expect(a).not.toBe(b);
  });
});
