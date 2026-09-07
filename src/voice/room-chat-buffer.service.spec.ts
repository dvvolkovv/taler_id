import { RoomChatBufferService } from './room-chat-buffer.service';

/** Поддельный ioredis: только те команды, которыми пользуется буфер.
 *  Список и счётчик живут в памяти, поэтому тест проверяет поведение
 *  ленты целиком, а не то, какие строки ушли в Redis. */
class FakeRedis {
  lists = new Map<string, string[]>();
  values = new Map<string, string>();
  expires = new Map<string, number>();

  async incr(key: string) {
    const next = Number(this.values.get(key) ?? 0) + 1;
    this.values.set(key, String(next));
    return next;
  }
  async get(key: string) {
    return this.values.get(key) ?? null;
  }
  async rpush(key: string, value: string) {
    const list = this.lists.get(key) ?? [];
    list.push(value);
    this.lists.set(key, list);
    return list.length;
  }
  async ltrim(key: string, start: number, stop: number) {
    const list = this.lists.get(key) ?? [];
    // Буфер зовёт только ltrim(key, -N, -1) — держим последние N.
    const from = start < 0 ? Math.max(list.length + start, 0) : start;
    const to = stop < 0 ? list.length + stop : stop;
    this.lists.set(key, list.slice(from, to + 1));
  }
  async lrange(key: string, start: number, stop: number) {
    const list = this.lists.get(key) ?? [];
    return stop === -1 ? list.slice(start) : list.slice(start, stop + 1);
  }
  async lrem(key: string, count: number, value: string) {
    const list = this.lists.get(key) ?? [];
    const i = list.indexOf(value);
    if (i === -1) return 0;
    list.splice(i, 1);
    void count;
    return 1;
  }
  async expire(key: string, ttl: number) {
    this.expires.set(key, ttl);
  }
}

describe('RoomChatBufferService', () => {
  let redis: FakeRedis;
  let buffer: RoomChatBufferService;

  const entry = (text: string) => ({
    msgId: `m_${text}`,
    text,
    name: 'Ассистент',
    ts: 1788767280107,
  });

  beforeEach(() => {
    redis = new FakeRedis();
    buffer = new RoomChatBufferService({ getClient: () => redis } as any);
  });

  it('нумерует сообщения подряд, начиная с единицы', async () => {
    expect((await buffer.append('call-42', entry('раз'))).seq).toBe(1);
    expect((await buffer.append('call-42', entry('два'))).seq).toBe(2);
  });

  it('нумерация у каждой комнаты своя', async () => {
    await buffer.append('call-42', entry('раз'));
    expect((await buffer.append('call-7', entry('раз'))).seq).toBe(1);
  });

  it('без курсора отдаёт всю ленту по порядку', async () => {
    await buffer.append('call-42', entry('раз'));
    await buffer.append('call-42', entry('два'));

    const page = await buffer.read('call-42');
    expect(page.messages.map((m) => m.text)).toEqual(['раз', 'два']);
    expect(page.seq).toBe(2);
    expect(page.truncated).toBe(false);
  });

  it('с курсором отдаёт только то, что новее', async () => {
    await buffer.append('call-42', entry('раз'));
    await buffer.append('call-42', entry('два'));

    const page = await buffer.read('call-42', 1);
    expect(page.messages.map((m) => m.text)).toEqual(['два']);
    expect(page.seq).toBe(2);
    expect(page.truncated).toBe(false);
  });

  it('на пустой комнате отдаёт пустую ленту, а не падает', async () => {
    const page = await buffer.read('call-empty');
    expect(page.messages).toEqual([]);
    expect(page.seq).toBe(0);
    expect(page.truncated).toBe(false);
  });

  it('держит не больше maxMessages, вытесняя самые старые', async () => {
    for (let i = 0; i < RoomChatBufferService.maxMessages + 5; i++) {
      await buffer.append('call-42', entry(`m${i}`));
    }
    const page = await buffer.read('call-42');
    expect(page.messages).toHaveLength(RoomChatBufferService.maxMessages);
    expect(page.messages[0].text).toBe('m5');
    expect(page.seq).toBe(RoomChatBufferService.maxMessages + 5);
  });

  it('сообщает truncated, если курсор указывает на вытесненное', async () => {
    for (let i = 0; i < RoomChatBufferService.maxMessages + 5; i++) {
      await buffer.append('call-42', entry(`m${i}`));
    }
    const page = await buffer.read('call-42', 1);
    expect(page.truncated).toBe(true);
  });

  it('не сообщает truncated, когда курсор попадает в начало ленты', async () => {
    await buffer.append('call-42', entry('раз'));
    await buffer.append('call-42', entry('два'));
    expect((await buffer.read('call-42', 0)).truncated).toBe(false);
  });

  it('сообщает truncated, если лента истекла, а счётчик ушёл вперёд', async () => {
    await buffer.append('call-42', entry('раз'));
    redis.lists.clear(); // TTL списка вышел, счётчик ещё жив
    const page = await buffer.read('call-42', 0);
    expect(page.messages).toEqual([]);
    expect(page.truncated).toBe(true);
  });

  it('remove снимает запись из ленты', async () => {
    const stored = await buffer.append('call-42', entry('раз'));
    await buffer.remove('call-42', stored);
    expect((await buffer.read('call-42')).messages).toEqual([]);
  });

  it('ставит TTL на список и на счётчик', async () => {
    await buffer.append('call-42', entry('раз'));
    expect(redis.expires.get('roomchat:call-42:log')).toBe(
      RoomChatBufferService.ttlSeconds,
    );
    expect(redis.expires.get('roomchat:call-42:seq')).toBe(
      RoomChatBufferService.ttlSeconds,
    );
  });

  it('битая строка в ленте не роняет чтение целиком', async () => {
    await buffer.append('call-42', entry('раз'));
    redis.lists.get('roomchat:call-42:log')!.push('{не json');
    const page = await buffer.read('call-42');
    expect(page.messages.map((m) => m.text)).toEqual(['раз']);
  });

  it('пропускает до 10 сообщений за окно и режет одиннадцатое', async () => {
    for (let i = 0; i < 10; i++) {
      expect(await buffer.hitRateLimit('call-42', 'guest-1')).toBe(false);
    }
    expect(await buffer.hitRateLimit('call-42', 'guest-1')).toBe(true);
  });

  it('потолок считается отдельно на каждого отправителя', async () => {
    for (let i = 0; i < 11; i++) {
      await buffer.hitRateLimit('call-42', 'guest-1');
    }
    expect(await buffer.hitRateLimit('call-42', 'guest-2')).toBe(false);
  });
});
