import {
  BadRequestException,
  HttpException,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import { VoiceService } from './voice.service';

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
});
