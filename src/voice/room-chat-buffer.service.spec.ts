import {
  RoomChatBufferService,
  RoomChatEntry,
} from './room-chat-buffer.service';

/** Минимальная копия ioredis-транзакции для FakeRedis: команды копятся в
 *  очередь и выполняются одним проходом на exec(), каждая отдаёт [null,
 *  result] при успехе или одноэлементный [error] при отказе (как настоящий
 *  ioredis) — этого достаточно для трёх транзакций буфера (append открывает
 *  две: на счётчик и на список; hitRateLimit — одну), большего фейку тут не
 *  нужно. */
interface FakeMulti {
  incr(key: string): FakeMulti;
  expire(key: string, ttl: number, mode?: 'NX'): FakeMulti;
  rpush(key: string, value: string): FakeMulti;
  ltrim(key: string, start: number, stop: number): FakeMulti;
  exec(): Promise<Array<[Error | null, unknown?]>>;
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
   *  подобные отказы транзакции записи в ленту (RPUSH/LTRIM). Сбрасывается
   *  после первого использования. */
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
  del(key: string) {
    const existed = this.lists.has(key) || this.values.has(key) ? 1 : 0;
    this.lists.delete(key);
    this.values.delete(key);
    this.expires.delete(key);
    this.expiresAt.delete(key);
    return Promise.resolve(existed);
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
        // упавшей команды одноэлементный массив [error]. Копируем это
        // здесь (не только текстом в комментарии — сам фейк отдаёт такой
        // же по форме слот, а не объявленный тип на бумаге): без per-op
        // try/catch отказ rpush()/ltrim() (см. nextTxError) улетел бы
        // наружу как отклонённый exec(), чего в проде не бывает, и тест на
        // молчаливую потерю (WRONGTYPE-слот) проверял бы не тот сценарий.
        const results: Array<[Error | null, unknown?]> = [];
        for (const op of ops) {
          try {
            results.push([null, await op()]);
          } catch (e) {
            results.push([e as Error]);
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
    // упавшей команды одноэлементным массивом [Error]. Молчание здесь
    // означало бы, что append() отдаёт «нормальную на вид» запись с
    // проставленным seq, sendRoomChatMessage разошлёт её в комнату — а в
    // ленте её не будет никогда: ни строки в истории, ни следа в логе.
    redis.nextTxError = {
      command: 'rpush',
      error: new Error(
        'WRONGTYPE Operation against a key holding the wrong kind of value',
      ),
    };
    await expect(buffer.append('call-42', entry('раз'))).rejects.toThrow(
      /WRONGTYPE/,
    );
    expect((await buffer.read('call-42')).messages).toEqual([]);
  });

  it('громко отказывает, если слот LTRIM транзакции записи в ленту пришёл с ошибкой', async () => {
    // Не воспроизведение реального отказа: RPUSH/LTRIM/EXPIRE идут одной
    // атомарной MULTI по одному и тому же ключу, и раз RPUSH (тест выше)
    // уже отработал, ключ точно список — WRONGTYPE на LTRIM сразу за этим
    // невозможен. Это защита самой проверки, а не сценарий из прода:
    // append() читает все три слота через `slots.find(...)`, а один тест
    // на RPUSH этого не показывает — RPUSH и есть slots[0], так что мутант
    // «смотреть только slots[0]» им не ловится. Состояние ленты после
    // отказа здесь не проверяется: RPUSH к этому моменту уже вставил
    // запись, поэтому, в отличие от теста выше, «лента пуста» было бы
    // неправдой.
    redis.nextTxError = {
      command: 'ltrim',
      error: new Error(
        'WRONGTYPE Operation against a key holding the wrong kind of value',
      ),
    };
    await expect(buffer.append('call-42', entry('раз'))).rejects.toThrow(
      /WRONGTYPE/,
    );
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

  it('курсор ровно на последнем номере отдаёт пустой список без truncated', async () => {
    await buffer.append('call-42', entry('раз'));
    await buffer.append('call-42', entry('два'));

    const atLatest = await buffer.read('call-42', 2);
    expect(atLatest.messages).toEqual([]);
    expect(atLatest.truncated).toBe(false);
  });

  // I4 (ревью Task 4b, 4-й круг): курсор строго дальше последнего номера
  // раньше молчал (truncated: false) — то же самое поведение, что и у
  // застрявшего курсора после того, как счётчик seq истёк сам по себе
  // (см. следующий тест и докстринг clearFeed): и там, и там ассистент
  // утверждает, что видел то, чего ещё не было, и ответ должен честно на
  // это указывать, а не выглядеть как «новых сообщений нет». Одна и та же
  // строка (`since > latest`) в read() закрывает оба случая разом — курсор
  // из будущего это лишь частный случай "курсор больше того, что реально
  // есть в комнате".
  it('курсор дальше последнего номера — truncated:true, а не тишина', async () => {
    await buffer.append('call-42', entry('раз'));
    await buffer.append('call-42', entry('два'));

    const pastLatest = await buffer.read('call-42', 5);
    expect(pastLatest.messages).toEqual([]);
    expect(pastLatest.truncated).toBe(true);
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

  // I4: горизонт из докстринга clearFeed — если следующая встреча в комнате
  // случается позже, чем через сутки, счётчик seq истекает сам, и append()
  // после этого стартует нумерацию заново с единицы. До этого теста и до
  // строки `since > latest` в read() застрявший курсор ассистента в этом
  // случае получал бы truncated:false и пустой список — то есть тихую
  // потерю ровно того рода, ради которой clearFeed вообще оставляет
  // счётчик в живых, только добравшуюся сюда другим путём (естественный
  // TTL, а не обнуление при очистке).
  it('счётчик истёк естественным TTL до следующей встречи — застрявший курсор получает truncated, а не тишину', async () => {
    await buffer.append('call-42', entry('раз')); // seq 1
    await buffer.append('call-42', entry('два')); // seq 2
    const staleCursor = 40; // ассистент давно не опрашивал эту комнату

    // Тот же приём, что и в предыдущем тесте, только на ключе счётчика, а
    // не списка: настоящие часы фейка и evictIfExpired, не ручное стирание
    // values — иначе тест проверял бы не ту функцию, что реально стоит на
    // пути чтения.
    await redis.expire('roomchat:call-42:seq', 1);
    redis.advance(2);

    const fresh = await buffer.append('call-42', entry('три'));
    // INCR несуществующего ключа стартует с единицы, не с 3 — вот он,
    // горизонт: append() не виноват, ему просто неоткуда взять старое
    // значение счётчика.
    expect(fresh.seq).toBe(1);

    const page = await buffer.read('call-42', staleCursor);
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

  // clearFeed: вызывается на входе в комнату, когда VoiceService решает, что
  // начинается новая встреча (см. её докстринг). Счётчик seq переживает
  // очистку намеренно — тесты ниже закрепляют именно это, а не просто факт
  // очистки списка.
  describe('clearFeed', () => {
    it('стирает список сообщений', async () => {
      await buffer.append('call-42', entry('раз'));
      await buffer.append('call-42', entry('два'));

      await buffer.clearFeed('call-42');

      expect((await buffer.read('call-42')).messages).toEqual([]);
    });

    it('не трогает счётчик — следующее сообщение продолжает прежнюю нумерацию, а не начинает с единицы', async () => {
      await buffer.append('call-42', entry('раз'));
      await buffer.append('call-42', entry('два'));

      await buffer.clearFeed('call-42');
      const next = await buffer.append('call-42', entry('три'));

      expect(next.seq).toBe(3);
    });

    it('не задевает ленту других комнат', async () => {
      await buffer.append('call-42', entry('раз'));
      await buffer.append('call-7', entry('чужое'));

      await buffer.clearFeed('call-42');

      expect((await buffer.read('call-7')).messages.map((m) => m.text)).toEqual(
        ['чужое'],
      );
    });

    it('повторный вызов на уже пустой ленте не падает', async () => {
      // .resolves само по себе и есть проверка: если бы clearFeed отклонил
      // промис, .resolves провалил бы тест раньше, чем дело дошло бы до
      // .toBeUndefined(). Не .not.toThrow() — на нефункции toThrow ничего
      // не проверяет и всегда проходит, каким бы ни было значение.
      await expect(buffer.clearFeed('call-empty')).resolves.toBeUndefined();
      await expect(buffer.clearFeed('call-empty')).resolves.toBeUndefined();
    });

    // Главный тест: ради чего счётчик вообще оставили в живых. Если бы он
    // обнулялся вместе со списком, у внешнего ассистента с застрявшим
    // курсором прошлой встречи не осталось бы ни одного признака поломки —
    // новые сообщения оказались бы «старее» его курсора и просто исчезли
    // бы из ответа, без единого сигнала, что что-то пошло не так.
    it('застрявший курсор прошлой встречи после очистки получает truncated:true и новые сообщения, а не тишину', async () => {
      // Старая встреча: два сообщения. Ассистент опрашивал ленту и в
      // последний раз видел только первое — его курсор застрял на seq=1
      // (он не досмотрел до seq=2, потому что старая встреча оборвалась
      // прямо тогда: разрыв соединения, крэш агента — неважно что именно).
      await buffer.append('call-42', entry('раз')); // seq 1
      await buffer.append('call-42', entry('два')); // seq 2
      const staleCursor = 1;

      // Новая встреча в той же комнате: VoiceService видит пустую комнату
      // на входе и чистит ленту, не трогая счётчик.
      await buffer.clearFeed('call-42');
      const fresh = await buffer.append('call-42', entry('три')); // seq 3, не 1
      expect(fresh.seq).toBe(3);

      const page = await buffer.read('call-42', staleCursor);
      expect(page.truncated).toBe(true);
      expect(page.messages.map((m) => m.text)).toEqual(['три']);
    });
  });
});
