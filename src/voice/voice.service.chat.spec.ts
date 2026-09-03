import { BadRequestException } from '@nestjs/common';
import { VoiceService } from './voice.service';

describe('VoiceService.sendRoomChatMessage', () => {
  let service: VoiceService;
  let euSendData: jest.Mock;
  let ruSendData: jest.Mock;

  const decode = (mock: jest.Mock) =>
    JSON.parse(Buffer.from(mock.mock.calls[0][1]).toString('utf8'));

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

  it('каждый пакет получает свой msgId', async () => {
    await service.sendRoomChatMessage('call-42', 'раз', 'Ассистент');
    await service.sendRoomChatMessage('call-42', 'два', 'Ассистент');
    const first = JSON.parse(
      Buffer.from(euSendData.mock.calls[0][1]).toString('utf8'),
    ).msgId;
    const second = JSON.parse(
      Buffer.from(euSendData.mock.calls[1][1]).toString('utf8'),
    ).msgId;
    expect(first).not.toBe(second);
  });
});
