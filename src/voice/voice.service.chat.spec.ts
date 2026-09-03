import { BadRequestException } from '@nestjs/common';
import { VoiceService } from './voice.service';

describe('VoiceService.sendRoomChatMessage', () => {
  let service: VoiceService;
  let euSendData: jest.Mock;
  let ruSendData: jest.Mock;

  const decode = (mock: jest.Mock, i = 0) =>
    JSON.parse(Buffer.from(mock.mock.calls[i][1]).toString('utf8'));

  beforeEach(() => {
    service = new VoiceService(
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
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
});
