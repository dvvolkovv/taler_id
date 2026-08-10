import { MessengerService } from './messenger.service';

/**
 * Упоминания резолвит сервер по участникам беседы. Клиент прислать их не может:
 * иначе «упоминанием» пробивался бы пуш кому угодно, в том числе мимо
 * отключённых уведомлений.
 */
describe('MessengerService mentions on send', () => {
  let service: MessengerService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      conversationParticipant: { findUnique: jest.fn().mockResolvedValue({ role: 'MEMBER' }) },
      message: {
        findFirst: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockImplementation(({ data }: any) => ({ id: 'm-1', ...data })),
      },
      $queryRaw: jest.fn().mockResolvedValue([]),
    };
    service = new MessengerService(prisma, {} as any);
  });

  const lastCreate = () => prisma.message.create.mock.calls.at(-1)[0].data;

  it('stores who was mentioned', async () => {
    prisma.$queryRaw.mockResolvedValue([{ userId: 'u-anna', username: 'anna' }]);

    await service.createMessage('conv-1', 'u-me', 'глянь @anna');

    expect(lastCreate().mentionedUserIds).toEqual(['u-anna']);
  });

  it('does not touch the database when the text has no handle', async () => {
    // Обычная отправка не должна получать лишний запрос на ровном месте.
    await service.createMessage('conv-1', 'u-me', 'просто текст без собак');

    expect(prisma.$queryRaw).not.toHaveBeenCalled();
    expect(lastCreate().mentionedUserIds).toBeUndefined();
  });

  it('does not treat an email as a mention', async () => {
    await service.createMessage('conv-1', 'u-me', 'пиши на anna@taler.test');

    expect(prisma.$queryRaw).not.toHaveBeenCalled();
  });

  it('drops a handle that belongs to nobody in the conversation', async () => {
    prisma.$queryRaw.mockResolvedValue([]); // запрос ограничен участниками

    await service.createMessage('conv-1', 'u-me', 'привет @stranger');

    expect(lastCreate().mentionedUserIds).toBeUndefined();
  });

  it('never mentions the author themselves', async () => {
    prisma.$queryRaw.mockResolvedValue([{ userId: 'u-me', username: 'me' }]);

    await service.createMessage('conv-1', 'u-me', 'пишу сам себе @me');

    expect(lastCreate().mentionedUserIds).toBeUndefined();
  });

  it('does not parse mentions out of system rows', async () => {
    // Служебные сообщения — это JSON, а не человеческий текст.
    await service.createMessage(
      'conv-1', 'u-me', JSON.stringify({ action: 'member_added', target: '@anna' }),
      undefined, undefined, true,
    );

    expect(prisma.$queryRaw).not.toHaveBeenCalled();
  });
});
