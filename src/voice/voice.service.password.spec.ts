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
    (service as any).rooms = {
      createRoom: jest.fn().mockResolvedValue(undefined),
    };
    (service as any).ruRooms = {
      createRoom: jest.fn().mockResolvedValue(undefined),
    };
  });

  it('создатель входит в свою комнату, не вводя собственный пароль', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'creator-1', undefined, 'sess-1'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
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
    // Защита от «упростим»: если проверку пароля пропускать по совпадению
    // creatorId с чем угодно, гость без пароля начнёт входить в чужую комнату.
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', undefined),
    ).rejects.toThrow(ForbiddenException);
  });

  it('комната без создателя (creatorId: null) не открывается по совпадению null === null', async () => {
    // Защита от другого «упрощения»: если убрать `!!room.creatorId` и
    // оставить только `room.creatorId === userId`, то комната без
    // записанного создателя «совпадёт» с любым вызовом, где userId тоже
    // окажется null — отсутствие создателя не должно быть преимуществом.
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
