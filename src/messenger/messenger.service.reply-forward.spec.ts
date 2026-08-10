import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

describe('MessengerService reply', () => {
  let service: MessengerService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      conversationParticipant: { findUnique: jest.fn(), findMany: jest.fn() },
      message: {
        findUnique: jest.fn(),
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn(),
        create: jest.fn().mockImplementation(({ data }: any) => ({ id: 'new-1', ...data })),
      },
      user: { findUnique: jest.fn() },
    };
    // Отправитель всегда участник целевой беседы, если тест не говорит иначе.
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    service = new MessengerService(prisma, {} as any);
  });

  const target = (over: any = {}) => ({
    id: 'msg-orig',
    conversationId: 'conv-1',
    topicId: null,
    deletedAt: null,
    ...over,
  });

  it('persists replyToId when the target is in the same conversation', async () => {
    prisma.message.findUnique.mockResolvedValue(target());

    await service.createMessage(
      'conv-1', 'u-1', 'ответ', undefined, undefined, undefined, undefined, undefined, undefined,
      { replyToId: 'msg-orig' },
    );

    expect(prisma.message.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ content: 'ответ', replyToId: 'msg-orig' }),
    });
  });

  it('refuses to reply to a message from another conversation', async () => {
    // Иначе через ответ вытаскивается кусок чужой переписки в свою.
    prisma.message.findUnique.mockResolvedValue(target({ conversationId: 'conv-OTHER' }));

    await expect(
      service.createMessage(
        'conv-1', 'u-1', 'ответ', undefined, undefined, undefined, undefined, undefined, undefined,
        { replyToId: 'msg-orig' },
      ),
    ).rejects.toThrow(BadRequestException);
    expect(prisma.message.create).not.toHaveBeenCalled();
  });

  it('refuses to reply to a deleted message', async () => {
    prisma.message.findUnique.mockResolvedValue(target({ deletedAt: new Date() }));

    await expect(
      service.createMessage(
        'conv-1', 'u-1', 'ответ', undefined, undefined, undefined, undefined, undefined, undefined,
        { replyToId: 'msg-orig' },
      ),
    ).rejects.toThrow(BadRequestException);
  });

  it('refuses to reply to a message that does not exist', async () => {
    prisma.message.findUnique.mockResolvedValue(null);

    await expect(
      service.createMessage(
        'conv-1', 'u-1', 'ответ', undefined, undefined, undefined, undefined, undefined, undefined,
        { replyToId: 'ghost' },
      ),
    ).rejects.toThrow(BadRequestException);
  });

  it('refuses to reply across topics', async () => {
    prisma.message.findUnique.mockResolvedValue(target({ topicId: 'topic-A' }));

    await expect(
      service.createMessage(
        'conv-1', 'u-1', 'ответ', undefined, 'topic-B', undefined, undefined, undefined, undefined,
        { replyToId: 'msg-orig' },
      ),
    ).rejects.toThrow(BadRequestException);
  });

  it('leaves ordinary sends untouched', async () => {
    await service.createMessage('conv-1', 'u-1', 'просто текст');

    expect(prisma.message.findUnique).not.toHaveBeenCalled();
    expect(prisma.message.create).toHaveBeenCalledWith({
      data: expect.not.objectContaining({ replyToId: expect.anything() }),
    });
  });
});

describe('MessengerService forwardMessages', () => {
  let service: MessengerService;
  let prisma: any;

  const source = (over: any = {}) => ({
    id: 'src-1',
    conversationId: 'conv-src',
    senderId: 'u-author',
    content: 'исходный текст',
    fileUrl: null,
    fileName: null,
    fileSize: null,
    fileType: null,
    s3Key: null,
    thumbnailSmallUrl: null,
    thumbnailMediumUrl: null,
    thumbnailLargeUrl: null,
    deletedAt: null,
    forwardedFromUserId: null,
    forwardedFromName: null,
    forwardedFromMessageId: null,
    sender: { username: 'author', profile: { firstName: 'Аня', lastName: 'Автор' } },
    ...over,
  });

  beforeEach(() => {
    prisma = {
      conversationParticipant: { findUnique: jest.fn(), findMany: jest.fn() },
      message: {
        findUnique: jest.fn(),
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn(),
        create: jest.fn().mockImplementation(({ data }: any) => ({ id: 'fwd-1', ...data })),
      },
      user: { findUnique: jest.fn() },
    };
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    // По умолчанию пересылающий состоит в исходной беседе.
    prisma.conversationParticipant.findMany.mockResolvedValue([
      { conversationId: 'conv-src' },
    ]);
    service = new MessengerService(prisma, {} as any);
  });

  it('copies the body from the stored original, not from the caller', async () => {
    prisma.message.findMany.mockResolvedValue([source()]);

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1']);

    expect(prisma.message.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        conversationId: 'conv-dst',
        senderId: 'u-fwd',
        content: 'исходный текст',
      }),
    });
  });

  it('attributes the forward to the original author with a name snapshot', async () => {
    prisma.message.findMany.mockResolvedValue([source()]);

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1']);

    expect(prisma.message.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        forwardedFromUserId: 'u-author',
        forwardedFromName: 'Аня Автор',
        forwardedFromMessageId: 'src-1',
      }),
    });
  });

  it('does not stack attribution when forwarding a forward', async () => {
    prisma.message.findMany.mockResolvedValue([
      source({
        senderId: 'u-middle',
        forwardedFromUserId: 'u-author',
        forwardedFromName: 'Аня Автор',
        forwardedFromMessageId: 'src-orig',
      }),
    ]);

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1']);

    expect(prisma.message.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        forwardedFromUserId: 'u-author',
        forwardedFromName: 'Аня Автор',
        forwardedFromMessageId: 'src-orig',
      }),
    });
  });

  it('refuses to forward out of a conversation the user is not in', async () => {
    // Без этой проверки любой аутентифицированный пользователь вытащил бы
    // произвольное сообщение, зная только его id.
    prisma.message.findMany.mockResolvedValue([source()]);
    prisma.conversationParticipant.findMany.mockResolvedValue([]);

    await expect(
      service.forwardMessages('conv-dst', 'u-stranger', ['src-1']),
    ).rejects.toThrow(ForbiddenException);
    expect(prisma.message.create).not.toHaveBeenCalled();
  });

  it('carries file attachments across', async () => {
    prisma.message.findMany.mockResolvedValue([
      source({ fileUrl: 'https://s3/x.png', fileName: 'x.png', fileType: 'image', fileSize: 10 }),
    ]);

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1']);

    expect(prisma.message.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        fileUrl: 'https://s3/x.png',
        fileName: 'x.png',
        fileType: 'image',
      }),
    });
  });

  it('keeps the order the caller asked for', async () => {
    // Prisma возвращает findMany в своём порядке — восстанавливать надо по списку.
    prisma.message.findMany.mockResolvedValue([
      source({ id: 'src-2', content: 'второе' }),
      source({ id: 'src-1', content: 'первое' }),
    ]);

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1', 'src-2']);

    const bodies = prisma.message.create.mock.calls.map((c: any) => c[0].data.content);
    expect(bodies).toEqual(['первое', 'второе']);
  });

  it('skips deleted originals instead of forwarding blanks', async () => {
    prisma.message.findMany.mockResolvedValue([source()]);

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1', 'src-deleted']);

    // findMany фильтрует deletedAt, поэтому до create доезжает только живое
    expect(prisma.message.create).toHaveBeenCalledTimes(1);
  });

  it('rejects an empty list', async () => {
    await expect(service.forwardMessages('conv-dst', 'u-fwd', [])).rejects.toThrow(
      BadRequestException,
    );
  });

  it('rejects a batch over the limit', async () => {
    const ids = Array.from({ length: 51 }, (_, i) => `src-${i}`);

    await expect(service.forwardMessages('conv-dst', 'u-fwd', ids)).rejects.toThrow(
      BadRequestException,
    );
  });

  it('throws when every requested original is gone', async () => {
    prisma.message.findMany.mockResolvedValue([]);

    await expect(
      service.forwardMessages('conv-dst', 'u-fwd', ['src-gone']),
    ).rejects.toThrow(BadRequestException);
  });

  it('is not swallowed by the phantom-resend content dedup', async () => {
    // Пересылка того же текста второй раз — намеренное действие. Защита от
    // фантомных ресендов не должна её глотать (текст длиннее 20 символов и
    // clientTempId нет — ровно условие срабатывания дедупа).
    const long = 'это сообщение заведомо длиннее двадцати символов';
    prisma.message.findMany.mockResolvedValue([source({ content: long })]);
    prisma.message.findFirst.mockResolvedValue({ id: 'old', content: long });

    await service.forwardMessages('conv-dst', 'u-fwd', ['src-1']);

    expect(prisma.message.create).toHaveBeenCalled();
  });
});
