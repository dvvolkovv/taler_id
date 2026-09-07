import {
  RoomChatBufferService,
  RoomChatEntry,
} from './room-chat-buffer.service';

/** Минимальная копия ioredis-транзакции для FakeRedis: команды копятся в
 *  очередь и выполняются одним проходом на exec(), возвращая [err, result]
 *  на каждую — этого достаточно для трёх транзакций буфера (append
 *  открывает две: на счётчик и на список; hitRateLimit — одну), большего
 *  фейку тут не нужно. */
interface FakeMulti {
  incr(key: string): FakeMulti;
  expire(key: string, ttl: number, mode?: 'NX'): FakeMulti;
  rpush(key: string, value: string): FakeMulti;
  ltrim(key: string, start: number, stop: number): FakeMulti;
  exec(): Promise<Array<[Error | null, unknown]>>;
}

/** Поддельный ioredis: только те команды, которыми пользуется буфер.
 *  Список и счётчик живут в памяти, поэтому тест проверяет поведение
 *  ленты целиком, а не то, какие строки ушли в Redis. */
class FakeRedis {
  lists = new Map<string, string[]>();
  values = new Map<string, string>();
  expires = new Map<string, number>();
  /** Виртуальные часы: тесты двигают их через advance(), не полагаясь на
   *  реальное время — проверка границы окна не зависит от скорости прогона
   *  тестов. */
  now = 0;
  private expiresAt = new Map<string, number>();
  /** Когда установлено, следующий вызов указанной команды внутри exec()
   *  отдаёт слот с ошибкой вместо результата — эмулирует WRONGTYPE и
   *  подобные отказы транзакции записи в ленту (RPUSH/LTRIM). Настоящий
   *  ioredis в этом случае кладёт в слот одноэлементный массив `[Error]`,
   *  а не `[Error, null]`, как ниже: для всех потребителей (`slot?.[0]`,
   *  `typeof slot[1] !== 'number'`, `?? 0`) это неразличимо, поэтому фейк
   *  всё равно хранит пару. Сбрасывается после первого использования. */
  nextTxError: { command: 'rpush' | 'ltrim'; error: Error } | null = null;

  private armedTxError(command: 'rpush' | 'ltrim'): Error | null {
    if (this.nextTxError?.command !== command) return null;
    const err = this.nextTxError.error;
    this.nextTxError = null;
    return err;
  }

  advance(seconds: number) {
    this.now += seconds;
  }

  private evictIfExpired(key: string) {
    const at = this.expiresAt.get(key);
    if (at !== undefined && at <= this.now) {
      this.values.delete(key);
      this.lists.delete(key);
      this.expires.delete(key);
      this.expiresAt.delete(key);
    }
  }

  incr(key: string) {
    this.evictIfExpired(key);
    const next = Number(this.values.get(key) ?? 0) + 1;
    this.values.set(key, String(next));
    return Promise.resolve(next);
  }
  get(key: string) {
    this.evictIfExpired(key);
    return Promise.resolve(this.values.get(key) ?? null);
  }
  rpush(key: string, value: string) {
    const err = this.armedTxError('rpush');
    if (err) return Promise.reject(err);
    const list = this.lists.get(key) ?? [];
    list.push(value);
    this.lists.set(key, list);
    return Promise.resolve(list.length);
  }
  ltrim(key: string, start: number, stop: number) {
    const err = this.armedTxError('ltrim');
    if (err) return Promise.reject(err);
    const list = this.lists.get(key) ?? [];
    // Буфер зовёт только ltrim(key, -N, -1) — держим последние N.
    const from = start < 0 ? Math.max(list.length + start, 0) : start;
    const to = stop < 0 ? list.length + stop : stop;
    this.lists.set(key, list.slice(from, to + 1));
    return Promise.resolve();
  }
  lrange(key: string, start: number, stop: number) {
    this.evictIfExpired(key);
    const list = this.lists.get(key) ?? [];
    return Promise.resolve(
      stop === -1 ? list.slice(start) : list.slice(start, stop + 1),
    );
  }
  lrem(key: string, count: number, value: string) {
    const list = this.lists.get(key) ?? [];
    const i = list.indexOf(value);
    if (i === -1) return Promise.resolve(0);
    list.splice(i, 1);
    void count;
    return Promise.resolve(1);
  }
  expire(key: string, ttl: number, mode?: 'NX') {
    if (mode === 'NX' && this.expiresAt.has(key)) {
      // NX: TTL уже стоит — не трогаем. Ровно семантика фиксированного
      // окна, которую проверяет тест про границу окна ниже.
      return Promise.resolve(0);
    }
    this.expires.set(key, ttl);
    this.expiresAt.set(key, this.now + ttl);
    return Promise.resolve(1);
  }

  multi(): FakeMulti {
    const ops: Array<() => Promise<unknown>> = [];
    const chain: FakeMulti = {
      incr: (key) => {
        ops.push(() => this.incr(key));
        return chain;
      },
      expire: (key, ttl, mode) => {
        ops.push(() => this.expire(key, ttl, mode));
        return chain;
      },
      rpush: (key, value) => {
        ops.push(() => this.rpush(key, value));
        return chain;
      },
      ltrim: (key, start, stop) => {
        ops.push(() => this.ltrim(key, start, stop));
        return chain;
      },
      exec: async () => {
        // Реальный ioredis не отклоняет exec() из-за отказа одной команды
        // внутри транзакции — он резолвит весь пакет, подставляя в слот
        // упавшей команды одноэлементный массив [Error] (см. комментарий у
        // nextTxError — фейк ниже хранит [Error, null], разница не видна
        // ни одному потребителю). Копируем поведение здесь: без per-op
        // try/catch отказ rpush()/ltrim() (см. nextTxError) улетел бы
        // наружу как отклонённый exec(), чего в проде не бывает, и тест на
        // молчаливую потерю (WRONGTYPE-слот) проверял бы не тот сценарий.
        const results: Array<[Error | null, unknown]> = [];
        for (const op of ops) {
          try {
            results.push([null, await op()]);
          } catch (e) {
            results.push([e as Error, null]);
          }
        }
        return results;
      },
    };
    return chain;
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

  it('громко отказывает, если слот RPUSH транзакции записи в ленту пришёл с ошибкой', async () => {
    // WRONGTYPE и подобное: ioredis не бросает из exec(), он резолвит слот
    // упавшей команды одноэлементным массивом [Error] (фейк ниже хранит
    // [Error, null] — см. комментарий у nextTxError, для append() разницы
    // нет). Молчание здесь означало бы, что append() отдаёт «нормальную на
    // вид» запись с проставленным seq, sendRoomChatMessage разошлёт её в
    // комнату — а в ленте её не будет никогда: ни строки в истории, ни
    // следа в логе.
    redis.nextTxError = {
      command: 'rpush',
      error: new Error(
        'WRONGTYPE Operation against a key holding the wrong kind of value',
      ),
    };
    await expect(buffer.append('call-42', entry('раз'))).rejects.toThrow();
    expect((await buffer.read('call-42')).messages).toEqual([]);
  });

  it('громко отказывает, если слот LTRIM транзакции записи в ленту пришёл с ошибкой', async () => {
    // Тот же риск, что и для слота RPUSH в тесте выше, но для другого слота
    // той же транзакции: append() проверяет все три слота (RPUSH/LTRIM/
    // EXPIRE) через `slots.find(...)`, а тест выше закрывает только RPUSH —
    // мутант «проверять только первый слот» остался бы незамеченным. Тут
    // RPUSH успевает выполниться (список получает запись), поэтому эта
    // проверка не повторяет «лента пуста» из теста выше — только то, что
    // отказ слота LTRIM тоже громко останавливает append().
    redis.nextTxError = {
      command: 'ltrim',
      error: new Error(
        'WRONGTYPE Operation against a key holding the wrong kind of value',
      ),
    };
    await expect(buffer.append('call-42', entry('раз'))).rejects.toThrow();
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

  it('курсор не меньше последнего номера отдаёт пустой список без truncated', async () => {
    await buffer.append('call-42', entry('раз'));
    await buffer.append('call-42', entry('два'));

    const atLatest = await buffer.read('call-42', 2);
    expect(atLatest.messages).toEqual([]);
    expect(atLatest.truncated).toBe(false);

    // Курсор дальше последнего номера — клиент утверждает, что видел то,
    // чего ещё не было. Такое не должно случаться в норме, но не должно и
    // выглядеть как потерянная история.
    const pastLatest = await buffer.read('call-42', 5);
    expect(pastLatest.messages).toEqual([]);
    expect(pastLatest.truncated).toBe(false);
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
    // Список и счётчик — разные ключи; append() выставляет им одинаковый
    // TTL, но в проде они способны разойтись (эвикшн по памяти, частичная
    // потеря данных). Эмулируем это через настоящие часы фейка, а не руками
    // очищая lists, — так тест идёт через тот же evictIfExpired, что и
    // боевое чтение: короткий TTL только списку, потом сдвигаем часы за
    // него, но не за (гораздо более длинный) TTL счётчика.
    await redis.expire('roomchat:call-42:log', 1);
    redis.advance(2);

    const page = await buffer.read('call-42', 0);
    expect(page.messages).toEqual([]);
    expect(page.truncated).toBe(true);
  });

  it('сортирует по seq, даже если RPUSH лёг не по порядку', async () => {
    // Гонка двух писателей: тот, что получил seq=2, кладёт RPUSH раньше,
    // чем обладатель seq=1 — на PROD это норма (две app-ноды на одном
    // Redis), а не редкий случай.
    const first = { ...entry('два'), seq: 2 };
    const second = { ...entry('раз'), seq: 1 };
    redis.lists.set('roomchat:call-42:log', [
      JSON.stringify(first),
      JSON.stringify(second),
    ]);
    redis.values.set('roomchat:call-42:seq', '2');

    const page = await buffer.read('call-42');
    expect(page.messages.map((m) => m.text)).toEqual(['раз', 'два']);
    expect(page.seq).toBe(2);
  });

  it('пропускает запись без числового seq вместо падения сортировки', async () => {
    await buffer.append('call-42', entry('раз'));
    // Синтаксически валидный JSON, но без seq — JSON.parse его пропустит,
    // а вот компаратор сортировки на нечисловом seq уйдёт в NaN, и latest
    // может стать undefined. То же рассуждение, что и для битой строки.
    redis.lists
      .get('roomchat:call-42:log')!
      .push(JSON.stringify({ msgId: 'm_x', text: 'без seq', name: 'X' }));

    const page = await buffer.read('call-42');
    expect(page.messages.map((m) => m.text)).toEqual(['раз']);
    expect(page.seq).toBe(1);
  });

  it('remove снимает запись из ленты', async () => {
    const stored = await buffer.append('call-42', entry('раз'));
    expect(await buffer.remove('call-42', stored)).toBe(1);
    expect((await buffer.read('call-42')).messages).toEqual([]);
  });

  it('remove с другим порядком полей ничего не снимает и сообщает об этом', async () => {
    const stored = await buffer.append('call-42', entry('раз'));
    // Те же значения, но поля собраны в другом порядке — JSON.stringify
    // даёт другую строку, LREM её не найдёт. Ровно тот случай, от которого
    // предостерегает докстринг remove().
    const reordered: RoomChatEntry = {
      seq: stored.seq,
      ts: stored.ts,
      name: stored.name,
      text: stored.text,
      msgId: stored.msgId,
    };
    expect(await buffer.remove('call-42', reordered)).toBe(0);
    expect((await buffer.read('call-42')).messages).toHaveLength(1);
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

  it('потолок считается отдельно для каждой комнаты', async () => {
    for (let i = 0; i < 11; i++) {
      await buffer.hitRateLimit('call-42', 'guest-1');
    }
    expect(await buffer.hitRateLimit('call-7', 'guest-1')).toBe(false);
  });

  it('ставит TTL на ключ потолка', async () => {
    await buffer.hitRateLimit('call-42', 'guest-1');
    expect(redis.expires.get('roomchat:call-42:rate:guest-1')).toBe(
      RoomChatBufferService.rateWindowSeconds,
    );
  });

  it('не блокирует отправителя, укладывающегося в потолок, на границе окна', async () => {
    // Раз в 2 секунды — вдвое медленнее разрешённых 10 за 10 секунд, 11
    // сообщений подряд пересекают границу окна дважды (на 10-й и 20-й
    // секунде). Без NX EXPIRE продлевался на каждом сообщении, ключ никогда
    // не истекал, и счётчик рос без остановки — к 20-й секунде (11-е
    // сообщение) отправитель словил бы блокировку, хотя ни разу не превысил
    // 10 сообщений за настоящее десятисекундное окно.
    for (let i = 0; i < 11; i++) {
      expect(await buffer.hitRateLimit('call-42', 'guest-1')).toBe(false);
      redis.advance(2);
    }
  });
});
