# Чат комнаты: серверный транспорт и чтение через API — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Единственным отправителем чата комнаты становится бэкенд, лента складывается в Redis, и её можно прочитать ручкой `GET /voice/rooms/:roomName/chat`.

**Architecture:** Веб и приложение перестают публиковать `chat_message` в data-канал сами и шлют `POST /voice/rooms/:roomName/chat`, авторизуясь room-scoped LiveKit-токеном. Сервис `RoomChatBufferService` нумерует сообщения (`INCR`) и держит последние 500 в списке Redis с TTL сутки. `VoiceService.sendRoomChatMessage` кладёт запись в буфер и рассылает пакет через `RoomServiceClient.sendData`; при отказе рассылки запись снимается обратно. Клиенты подтягивают историю один раз при входе в комнату — до того, как придёт первый живой пакет, иначе лента перемешается.

**Tech Stack:** NestJS + ioredis (бэкенд), ванильный JS (`public/room.html`), Flutter/Dart (`taler_id_mobile`), Jest (юнит-тесты бэкенда), `flutter test`, ts-node smoke-тесты в `taler_id_tests`.

**Спека:** `docs/superpowers/specs/2026-09-07-room-chat-links-images-read-api-design.md`

**Порядок относительно других планов:** этот — первый. `2026-09-07-room-chat-clickable-links.md` независим и может идти параллельно. `2026-09-07-room-chat-images.md` опирается на буфер и ручки отсюда — только после.

---

## Структура файлов

**Бэкенд (`taler_id`):**
- Создать `src/voice/room-chat-buffer.service.ts` — лента комнаты в Redis: нумерация, хранение, чтение с курсором, потолок на запись. Единственное место, знающее про ключи Redis.
- Создать `src/voice/room-chat-buffer.service.spec.ts` — юнит-тесты буфера на поддельном клиенте Redis.
- Изменить `src/voice/voice.service.ts` — `sendRoomChatMessage` пишет в буфер и возвращает `{ts, seq, msgId}`; новый `readRoomChat`.
- Изменить `src/voice/voice.service.chat.spec.ts` — конструктор сервиса получает седьмой аргумент, добавляются проверки буфера.
- Изменить `src/voice/voice.controller.ts` — `GET .../chat`, актор в `POST`.
- Изменить `src/voice/guards/room-access.guard.ts` — кладёт в запрос `roomActor`.
- Изменить `src/voice/voice.module.ts` — провайдер буфера.
- Изменить `public/room.html` — отправка через ручку, загрузка истории при входе.

**Мобилка/десктоп (`taler_id_mobile`):**
- Создать `lib/features/voice/data/room_chat_api.dart` — вызовы ручек чата с room-scoped токеном.
- Создать `lib/features/voice/domain/room_chat_history.dart` — чистый разбор ответа истории (то, что тестируется).
- Создать `test/features/voice/room_chat_history_test.dart`.
- Изменить `lib/features/voice/presentation/controllers/room_chat_controller.dart` — `setHistory`.
- Изменить `lib/features/voice/presentation/controllers/room_data_packet_ids.dart` — `remember`.
- Изменить `lib/features/voice/presentation/screens/voice_call_screen.dart` — хранит LiveKit-токен, шлёт через ручку, грузит историю.
- Изменить `lib/core/services/call_state_service.dart` — отдаёт токен активной комнаты отдельному ассистенту.
- Изменить `lib/features/assistant/tools/assistant_tools_schema.dart` и `..._executor.dart` — `read_room_chat`, отправка room-scoped токеном.

**Тесты (`taler_id_tests`):**
- Создать `room_chat_test.ts`, добавить скрипты в `package.json`.

---

## Task 1: Буфер ленты в Redis

**Files:**
- Create: `src/voice/room-chat-buffer.service.ts`
- Test: `src/voice/room-chat-buffer.service.spec.ts`
- Modify: `src/voice/voice.module.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/voice/room-chat-buffer.service.spec.ts`:

```ts
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
    for (let i = 0; i < 11; i++) await buffer.hitRateLimit('call-42', 'guest-1');
    expect(await buffer.hitRateLimit('call-42', 'guest-2')).toBe(false);
  });
});
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/room-chat-buffer.service.spec.ts`
Expected: FAIL — `Cannot find module './room-chat-buffer.service'`.

- [ ] **Step 3: Написать сервис**

Создать `src/voice/room-chat-buffer.service.ts`:

```ts
import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

/** Одно сообщение чата комнаты, как оно лежит в ленте и уходит клиентам. */
export interface RoomChatEntry {
  msgId: string;
  text: string;
  name: string;
  ts: number;
  seq: number;
}

export interface RoomChatPage {
  messages: RoomChatEntry[];
  /** Номер последнего известного сообщения — курсор для следующего запроса. */
  seq: number;
  /** true — между курсором запроса и первым отданным сообщением есть дыра. */
  truncated: boolean;
}

/**
 * Лента чата комнаты в Redis.
 *
 * Чат остаётся эфемерным: ничего не едет в базу, список живёт сутки и режется
 * по последним `maxMessages`. Смысл ленты в том, что до неё дотягивается
 * внешний ассистент через `GET /voice/rooms/:roomName/chat` и вошедший позже
 * участник — раньше и то и другое было невозможно, потому что сообщения
 * летели мимо бэкенда.
 *
 * Единственное место в коде, знающее про ключи Redis для чата.
 */
@Injectable()
export class RoomChatBufferService {
  /** Сутки. Встреча столько не идёт, но отставший клиент дотянется. */
  static readonly ttlSeconds = 86400;
  /** Потолок ленты в одной комнате; дальше вытесняются самые старые. */
  static readonly maxMessages = 500;
  /** Мягкий потолок на запись: `rateLimit` сообщений за `rateWindowSeconds`
   *  с одного отправителя в одну комнату. Ловит зациклившегося бота,
   *  человеку недостижим. */
  static readonly rateLimit = 10;
  static readonly rateWindowSeconds = 10;

  private readonly log = new Logger(RoomChatBufferService.name);

  constructor(private readonly redis: RedisService) {}

  private logKey(roomName: string) {
    return `roomchat:${roomName}:log`;
  }

  private seqKey(roomName: string) {
    return `roomchat:${roomName}:seq`;
  }

  /** Кладёт сообщение в ленту и возвращает его с проставленным `seq`. */
  async append(
    roomName: string,
    entry: Omit<RoomChatEntry, 'seq'>,
  ): Promise<RoomChatEntry> {
    const client = this.redis.getClient();
    const seq = await client.incr(this.seqKey(roomName));
    const stored: RoomChatEntry = { ...entry, seq };
    // Команды идут по одной, без транзакции: писатель на сообщение один, а
    // недоставленный EXPIRE поправит следующая запись.
    await client.rpush(this.logKey(roomName), JSON.stringify(stored));
    await client.ltrim(
      this.logKey(roomName),
      -RoomChatBufferService.maxMessages,
      -1,
    );
    await client.expire(this.logKey(roomName), RoomChatBufferService.ttlSeconds);
    await client.expire(this.seqKey(roomName), RoomChatBufferService.ttlSeconds);
    return stored;
  }

  /**
   * Снимает запись обратно. Нужно, когда рассылка в комнату не удалась:
   * сообщение, которого никто не видел, не должно всплыть у того, кто откроет
   * историю.
   *
   * Сравнение идёт по строке, поэтому передавать сюда нужно ровно тот объект,
   * что вернул `append` — с другим порядком полей `LREM` не найдёт запись.
   */
  async remove(roomName: string, entry: RoomChatEntry): Promise<void> {
    try {
      await this.redis
        .getClient()
        .lrem(this.logKey(roomName), 1, JSON.stringify(entry));
    } catch (e) {
      this.log.warn(`не удалось снять запись ${entry.msgId} из ленты: ${e}`);
    }
  }

  /** Лента комнаты. `since` — номер последнего уже известного сообщения. */
  async read(roomName: string, since?: number): Promise<RoomChatPage> {
    const client = this.redis.getClient();
    const raw = await client.lrange(this.logKey(roomName), 0, -1);

    const entries: RoomChatEntry[] = [];
    for (const line of raw) {
      try {
        entries.push(JSON.parse(line) as RoomChatEntry);
      } catch {
        // Одна испорченная строка не должна уносить всю ленту.
      }
    }

    const counter = Number(await client.get(this.seqKey(roomName))) || 0;
    const latest = entries.length ? entries[entries.length - 1].seq : counter;

    if (since === undefined) {
      return { messages: entries, seq: latest, truncated: false };
    }

    const oldest = entries.length ? entries[0].seq : undefined;
    // Дыра есть, если самое старое сохранённое сообщение новее, чем
    // следующее за курсором. Пустая лента при живом счётчике — тоже дыра.
    const truncated =
      oldest === undefined ? latest > since : oldest > since + 1;

    return {
      messages: entries.filter((e) => e.seq > since),
      seq: latest,
      truncated,
    };
  }

  /** true — отправитель превысил потолок и писать ему сейчас нельзя. */
  async hitRateLimit(roomName: string, actor: string): Promise<boolean> {
    const client = this.redis.getClient();
    const key = `roomchat:${roomName}:rate:${actor}`;
    const n = await client.incr(key);
    if (n === 1) {
      await client.expire(key, RoomChatBufferService.rateWindowSeconds);
    }
    return n > RoomChatBufferService.rateLimit;
  }
}
```

- [ ] **Step 4: Запустить тест и убедиться, что он проходит**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/room-chat-buffer.service.spec.ts`
Expected: PASS, 14 тестов.

- [ ] **Step 5: Зарегистрировать провайдер**

В `src/voice/voice.module.ts` добавить импорт и провайдер:

```ts
import { RoomChatBufferService } from './room-chat-buffer.service';

@Module({
  imports: [BillingModule, forwardRef(() => GroupCallModule)],
  controllers: [VoiceController],
  providers: [VoiceService, FileStorageService, RoomChatBufferService],
  exports: [VoiceService],
})
export class VoiceModule {}
```

`RedisModule` помечен `@Global`, поэтому импортировать его здесь не нужно.

- [ ] **Step 6: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/room-chat-buffer.service.ts src/voice/room-chat-buffer.service.spec.ts src/voice/voice.module.ts
git commit -m "feat(voice): лента чата комнаты в Redis"
```

---

## Task 2: Отправка пишет в ленту

**Files:**
- Modify: `src/voice/voice.service.ts:215-254` (`sendRoomChatMessage`)
- Test: `src/voice/voice.service.chat.spec.ts`

- [ ] **Step 1: Обновить тест под новый конструктор и добавить проверки ленты**

В `src/voice/voice.service.chat.spec.ts` заменить блок `beforeEach` и добавить новые проверки. Полностью новый `beforeEach`:

```ts
  let buffer: {
    append: jest.Mock;
    remove: jest.Mock;
    hitRateLimit: jest.Mock;
  };

  beforeEach(() => {
    buffer = {
      append: jest.fn(async (_room: string, entry: any) => ({ ...entry, seq: 7 })),
      remove: jest.fn().mockResolvedValue(undefined),
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
```

И добавить в конец `describe` новые тесты:

```ts
  it('кладёт сообщение в ленту и возвращает его номер', async () => {
    const res = await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');

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
    expect(buffer.remove.mock.calls[0][1]).toMatchObject({ seq: 7 });
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
```

Дописать импорт в начало файла:

```ts
import { BadRequestException, HttpException } from '@nestjs/common';
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/voice.service.chat.spec.ts`
Expected: FAIL — `buffer.append` не вызывался, `res.seq` undefined.

- [ ] **Step 3: Реализовать**

В `src/voice/voice.service.ts` дописать импорты:

```ts
import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { RoomChatBufferService } from './room-chat-buffer.service';
```

Добавить седьмой параметр конструктора:

```ts
  constructor(
    private readonly prisma: PrismaService,
    private readonly fileStorage: FileStorageService,
    private readonly gating: GatingService,
    private readonly metering: MeteringService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
    private readonly chatBuffer: RoomChatBufferService,
  ) {}
```

Заменить `sendRoomChatMessage` целиком:

```ts
  /**
   * Единственный путь сообщения в чат комнаты: и от людей, и от ассистента.
   * Сначала запись в ленту — иначе читать через API было бы нечего, — потом
   * рассылка в data-канал. Если рассылка не удалась, запись снимается: то,
   * чего никто не видел, не должно всплыть у открывшего историю.
   */
  async sendRoomChatMessage(
    roomName: string,
    text: string,
    name: string,
    actor?: string,
  ): Promise<{ ts: number; seq: number; msgId: string }> {
    const trimmed = typeof text === 'string' ? text.trim() : '';
    if (!trimmed) throw new BadRequestException('text is empty');
    if (trimmed.length > 500) {
      throw new BadRequestException('text is longer than 500 characters');
    }
    const who =
      (typeof name === 'string' ? name.trim() : '').slice(0, 64) || 'Taler ID';

    if (actor && (await this.chatBuffer.hitRateLimit(roomName, actor))) {
      throw new HttpException(
        'too many chat messages, slow down',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const stored = await this.chatBuffer.append(roomName, {
      msgId: `server_${uuidv4()}`,
      text: trimmed,
      name: who,
      ts: Date.now(),
    });

    const packet = { type: 'chat_message', ...stored };

    try {
      await this.sfuFor(roomName).client.sendData(
        roomName,
        new TextEncoder().encode(JSON.stringify(packet)),
        DataPacket_Kind.RELIABLE,
        // SendDataOptions актуальной перегрузки sendData — без этого аргумента
        // вызов уходит в @deprecated-ветку с позиционным списком получателей.
        {},
      );
    } catch (e) {
      await this.chatBuffer.remove(roomName, stored);
      console.error(`Failed to send chat message to room ${roomName}:`, e);
      throw e;
    }

    return { ts: stored.ts, seq: stored.seq, msgId: stored.msgId };
  }

  /** Лента комнаты для клиента и внешнего ассистента. */
  async readRoomChat(roomName: string, since?: number) {
    return this.chatBuffer.read(roomName, since);
  }
```

- [ ] **Step 4: Запустить тесты и убедиться, что они проходят**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/voice.service.chat.spec.ts`
Expected: PASS, все прежние проверки плюс шесть новых.

- [ ] **Step 5: Убедиться, что остальные тесты голоса не сломались**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice`
Expected: PASS. Если падает `voice.service.spec.ts` или `voice.service.join.spec.ts` на числе аргументов конструктора — дописать в их `new VoiceService(...)` седьмой `{} as any`.

- [ ] **Step 6: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/voice.service.ts src/voice/voice.service.chat.spec.ts src/voice/voice.service.spec.ts src/voice/voice.service.join.spec.ts
git commit -m "feat(voice): отправка чата пишет в ленту и отдаёт seq"
```

---

## Task 3: Guard называет отправителя

**Files:**
- Modify: `src/voice/guards/room-access.guard.ts`
- Test: `src/voice/guards/room-access.guard.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Дописать в `src/voice/guards/room-access.guard.spec.ts` внутрь существующего `describe`:

```ts
  // Существующий хелпер `ctxFor` строит запрос внутри себя, поэтому добраться
  // до него после вызова нельзя — здесь запрос нужен снаружи, чтобы прочитать
  // `roomActor`.
  const ctxWithReq = (req: any) =>
    ({ switchToHttp: () => ({ getRequest: () => req }) }) as any;

  it('кладёт в запрос отправителя из LiveKit-токена', async () => {
    const req: any = {
      params: { roomName: 'call-1' },
      headers: { authorization: `Bearer ${livekitToken('call-1')}` },
    };

    await expect(guard.canActivate(ctxWithReq(req))).resolves.toBe(true);
    expect(req.roomActor).toBe('guest-1');
  });

  it('кладёт в запрос отправителя из токена Taler ID', async () => {
    prisma.publicRoom.findFirst.mockResolvedValue({ id: 'pr-1' });
    const req: any = {
      params: { roomName: 'call-1' },
      headers: { authorization: `Bearer ${userToken('user-1')}` },
    };

    await expect(guard.canActivate(ctxWithReq(req))).resolves.toBe(true);
    expect(req.roomActor).toBe('user-1');
  });
```

`livekitToken` и `userToken` — существующие хелперы файла; первый уже подписывает `sub: 'guest-1'`.

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/guards/room-access.guard.spec.ts`
Expected: FAIL — `expect(received).toBe('guest-460c6508')`, получено `undefined`.

- [ ] **Step 3: Реализовать**

В `src/voice/guards/room-access.guard.ts` заменить `canActivate` и `isLivekitTokenForRoom`:

```ts
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const roomName: string | undefined = req.params?.roomName;
    if (!roomName) throw new ForbiddenException('room not specified');

    const auth = req.headers['authorization'];
    const token =
      typeof auth === 'string' && auth.startsWith('Bearer ')
        ? auth.slice(7)
        : undefined;
    if (!token) throw new UnauthorizedException('No token');

    // `roomActor` — кто именно пишет. Нужен потолку на запись в чате: без него
    // один зациклившийся клиент заглушил бы всю комнату.
    const lkSubject = this.livekitSubjectForRoom(token, roomName);
    if (lkSubject) {
      req.roomActor = lkSubject;
      return true;
    }

    const userId = await this.entitledUserId(token, roomName);
    if (userId) {
      req.roomActor = userId;
      return true;
    }

    throw new ForbiddenException('No access to this room');
  }

  /** A LiveKit grant is scoped to one room, so it proves presence in it.
   *  Returns the token subject, which identifies the sender. */
  private livekitSubjectForRoom(
    token: string,
    roomName: string,
  ): string | null {
    try {
      const payload = jwt.verify(token, LK_API_SECRET, {
        algorithms: ['HS256'],
      }) as jwt.JwtPayload & { video?: { room?: string } };
      if (payload?.video?.room !== roomName) return null;
      return typeof payload.sub === 'string' && payload.sub
        ? payload.sub
        : 'livekit';
    } catch {
      return null;
    }
  }
```

Переименовать `isEntitledUser` в `entitledUserId`, поменяв возвращаемое значение с `boolean` на `string | null`: там, где было `return true`, вернуть `userId`; где `return false` — `null`; последняя строка становится
`return log.participantIds.includes(userId) ? userId : null;`.

- [ ] **Step 4: Запустить тесты и убедиться, что они проходят**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/guards/room-access.guard.spec.ts`
Expected: PASS — прежние проверки доступа плюс новая про `roomActor`.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/guards/room-access.guard.ts src/voice/guards/room-access.guard.spec.ts
git commit -m "feat(voice): RoomAccessGuard называет отправителя в roomActor"
```

---

## Task 4: Ручка чтения

**Files:**
- Modify: `src/voice/voice.controller.ts:371-381`

- [ ] **Step 1: Дописать ручки**

Заменить блок `sendRoomChat` на:

```ts
  @Post('rooms/:roomName/chat')
  @UseGuards(RoomAccessGuard)
  sendRoomChat(
    @Param('roomName') roomName: string,
    @Body() body: { text?: string; name?: string },
    @Req() req: any,
  ) {
    return this.service.sendRoomChatMessage(
      roomName,
      body?.text ?? '',
      body?.name ?? '',
      req.roomActor,
    );
  }

  // Лента встречи. Ею пользуются и внешний ассистент (опрос по курсору), и
  // клиент при входе в комнату — вошедший позже видит написанное до него.
  @Get('rooms/:roomName/chat')
  @UseGuards(RoomAccessGuard)
  readRoomChat(
    @Param('roomName') roomName: string,
    @Query('since') since?: string,
  ) {
    // Мусор в курсоре — то же самое, что его отсутствие: отдаём всю ленту,
    // а не 400. Клиент, потерявший курсор, должен уметь начать заново.
    const parsed = Number(since);
    const cursor = Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
    return this.service.readRoomChat(roomName, cursor);
  }
```

Проверить, что `Get`, `Query` и `Req` есть в импорте `@nestjs/common` вверху файла, и дописать недостающие.

- [ ] **Step 2: Собрать и убедиться, что компилируется**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npm run build`
Expected: сборка проходит без ошибок.

- [ ] **Step 3: Прогнать все тесты бэкенда**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice`
Expected: PASS.

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/voice.controller.ts
git commit -m "feat(voice): GET /voice/rooms/:roomName/chat — лента встречи"
```

---

## Task 5: Проверка ручек на живом DEV

**Files:** нет — ручная проверка перед тем, как трогать клиентов.

- [ ] **Step 1: Задеплоить на DEV**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
```

- [ ] **Step 2: Проверить круг «отправил — прочитал»**

```bash
B=https://staging.id.taler.tirol
TOK=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')
CODE=$(curl -s -X POST $B/voice/rooms/temporary -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"title":"chat probe"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
J=$(curl -s -X POST $B/voice/rooms/public/$CODE/join -H 'Content-Type: application/json' -d '{"name":"Linkeon"}')
LK=$(echo "$J" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
RN=$(echo "$J" | python3 -c 'import sys,json;print(json.load(sys.stdin)["roomName"])')
curl -s -X POST "$B/voice/rooms/$RN/chat" -H "Authorization: Bearer $LK" \
  -H 'Content-Type: application/json' -d '{"text":"раз","name":"Linkeon"}'
curl -s -X POST "$B/voice/rooms/$RN/chat" -H "Authorization: Bearer $LK" \
  -H 'Content-Type: application/json' -d '{"text":"два","name":"Linkeon"}'
curl -s "$B/voice/rooms/$RN/chat" -H "Authorization: Bearer $LK"
curl -s "$B/voice/rooms/$RN/chat?since=1" -H "Authorization: Bearer $LK"
curl -s -X DELETE "$B/voice/rooms/temporary/$CODE" -H "Authorization: Bearer $TOK"
```

Expected: обе отправки отдают `{"ts":…,"seq":1,"msgId":"server_…"}` и `seq:2`; полная лента — два сообщения, `truncated:false`; с `since=1` — только «два».

---

## Task 6: Веб шлёт через ручку

**Files:**
- Modify: `public/room.html:3398-3418` (`sendChatMessage`)

- [ ] **Step 1: Заменить отправку**

```js
    async function sendChatMessage() {
      if (!room) return;
      const input = document.getElementById('chat-input');
      const text = input.value.trim();
      if (!text) return;
      input.value = '';

      const name = getDisplayName(room.localParticipant);
      try {
        const res = await fetch(`${API_BASE}/voice/rooms/${room.name}/chat`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${lkToken}`,
          },
          body: JSON.stringify({ text, name }),
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        // Сервер рассылает пакет всем участникам, включая автора. Помечаем id
        // обработанным до отрисовки эха — иначе своё сообщение появится дважды.
        if (data.msgId) _processedMsgIds.add(data.msgId);
        if (typeof data.seq === 'number') chatSeq = Math.max(chatSeq, data.seq);
        appendChatMessage(name, text, data.ts || Date.now(), true);
      } catch (e) {
        // Неотправленное не должно выглядеть отправленным: возвращаем текст
        // в поле, чтобы человек мог повторить, не набирая заново.
        input.value = text;
        showNotification('Сообщение не отправлено', 'error');
      }
    }
```

- [ ] **Step 2: Завести курсор ленты**

Рядом с `let lkToken = '';` (строка ~885) добавить:

```js
    let chatSeq = 0;
```

- [ ] **Step 3: Проверить руками**

Открыть комнату в двух вкладках браузера, написать из первой.
Expected: сообщение появляется в обеих вкладках ровно один раз; в отправившей — как своё (справа).

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add public/room.html
git commit -m "feat(room): веб шлёт чат через бэкенд"
```

---

## Task 7: Веб грузит историю при входе

**Files:**
- Modify: `public/room.html` — функция подключения и обработчик открытия панели

- [ ] **Step 1: Разрешить тихое добавление в ленту**

В `appendChatMessage` добавить пятый параметр — история не должна светить бейджем непрочитанных, человек её не пропускал, он только что вошёл:

```js
    function appendChatMessage(name, text, ts, own, silent) {
```

и в конце функции:

```js
      if (!own && !chatOpen && !silent) {
        chatUnread++;
        updateChatBadge();
      }
```

- [ ] **Step 2: Написать загрузку истории**

Добавить рядом с `sendChatMessage`:

```js
    /** Лента встречи до нашего входа. Грузится один раз сразу после connect —
     *  до первого живого пакета, иначе старые сообщения легли бы ниже новых. */
    async function loadChatHistory() {
      if (!room) return;
      try {
        const res = await fetch(`${API_BASE}/voice/rooms/${room.name}/chat`, {
          headers: { Authorization: `Bearer ${lkToken}` },
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        for (const m of data.messages || []) {
          if (m.msgId) {
            if (_processedMsgIds.has(m.msgId)) continue;
            _processedMsgIds.add(m.msgId);
          }
          appendChatMessage(m.name, m.text, m.ts, false, true);
        }
        chatSeq = Math.max(chatSeq, data.seq || 0);
      } catch (e) {
        // История — приятное дополнение, а не условие работы чата: молча
        // остаёмся без неё, живые сообщения продолжают приходить.
        console.warn('chat history failed', e);
      }
    }
```

- [ ] **Step 3: Позвать её после подключения**

Найти `lkToken = token;` (строка ~1068) — это тело `connectToRoom`. Сразу после того, как `room` подключена и обработчики навешаны (там же, где вызывается первичная отрисовка участников), добавить:

```js
      loadChatHistory();
```

Вызов намеренно без `await`: подключение к комнате не должно ждать ленты.

- [ ] **Step 4: Проверить руками**

Открыть комнату в первой вкладке, написать два сообщения, затем открыть ту же комнату во второй вкладке и раскрыть чат.
Expected: во второй вкладке видны оба сообщения в правильном порядке, бейдж непрочитанных не горит.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add public/room.html
git commit -m "feat(room): веб показывает историю чата встречи"
```

---

## Task 8: Приложение помнит room-scoped токен

**Files:**
- Modify: `lib/features/voice/presentation/screens/voice_call_screen.dart:780`
- Modify: `lib/core/services/call_state_service.dart`

- [ ] **Step 1: Сохранить токен в поле экрана**

В `voice_call_screen.dart` рядом с другими полями состояния добавить:

```dart
  /// LiveKit-токен этой комнаты. Им авторизуются вызовы чата: `RoomAccessGuard`
  /// принимает его всегда, тогда как токен Taler ID проходит только у
  /// участника звонка, владельца персональной комнаты или создателя временной —
  /// в чужой временной комнате он даёт 403.
  String? _lkToken;
```

После `final token = res['token'] as String;` (строка ~780) добавить:

```dart
      _lkToken = token;
```

То же самое после `final token = res['token'] as String;` в `_startManualReconnect` (строка ~1348) — после переподключения токен новый.

- [ ] **Step 2: Отдать токен наружу**

В `call_state_service.dart` рядом с `_activeRoomName` добавить:

```dart
  /// LiveKit-токен активной комнаты. Нужен отдельному ассистенту: он пишет в
  /// чат ручкой, а та ждёт токен, выданный ровно на эту комнату.
  String? _activeRoomToken;
  String? get activeRoomToken => _activeRoomToken;
  void setActiveRoomToken(String? token) => _activeRoomToken = token;
```

В `voice_call_screen.dart` сразу после `_lkToken = token;` добавить:

```dart
      CallStateService.instance.setActiveRoomToken(token);
```

А там, где экран закрывает звонок и чистит состояние (`_cleanupCall` / `dispose` — где сбрасывается активная комната), добавить:

```dart
    CallStateService.instance.setActiveRoomToken(null);
```

- [ ] **Step 3: Проверить, что собирается**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter analyze lib/features/voice/presentation/screens/voice_call_screen.dart lib/core/services/call_state_service.dart`
Expected: новых замечаний по этим файлам нет (старые в репозитории есть — см. память про долг анализатора).

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/presentation/screens/voice_call_screen.dart lib/core/services/call_state_service.dart
git commit -m "feat(voice): экран звонка помнит room-scoped токен"
```

---

## Task 9: Разбор ответа истории

**Files:**
- Create: `lib/features/voice/domain/room_chat_history.dart`
- Test: `test/features/voice/room_chat_history_test.dart`

- [ ] **Step 1: Написать падающий тест**

Создать `test/features/voice/room_chat_history_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/voice/domain/room_chat_history.dart';

void main() {
  group('parseRoomChatHistory', () {
    test('разбирает ленту по порядку', () {
      final page = parseRoomChatHistory({
        'messages': [
          {'seq': 1, 'msgId': 'a', 'text': 'раз', 'name': 'Аня', 'ts': 1000},
          {'seq': 2, 'msgId': 'b', 'text': 'два', 'name': 'Боря', 'ts': 2000},
        ],
        'seq': 2,
        'truncated': false,
      });

      expect(page.messages.map((m) => m.text), ['раз', 'два']);
      expect(page.messages.first.msgId, 'a');
      expect(page.messages.first.sentAt.millisecondsSinceEpoch, 1000);
      expect(page.seq, 2);
      expect(page.truncated, isFalse);
    });

    test('пустая лента — пустой результат', () {
      final page = parseRoomChatHistory({'messages': [], 'seq': 0});
      expect(page.messages, isEmpty);
      expect(page.seq, 0);
    });

    test('сообщение без текста пропускается', () {
      final page = parseRoomChatHistory({
        'messages': [
          {'seq': 1, 'msgId': 'a', 'text': '   ', 'name': 'Аня', 'ts': 1000},
          {'seq': 2, 'msgId': 'b', 'text': 'два', 'name': 'Боря', 'ts': 2000},
        ],
        'seq': 2,
      });
      expect(page.messages.map((m) => m.text), ['два']);
    });

    test('поля не той природы не роняют разбор', () {
      // Сеть отдаёт что угодно: числа вместо строк, null вместо чисел.
      final page = parseRoomChatHistory({
        'messages': [
          {'seq': '3', 'msgId': 7, 'text': 42, 'name': null, 'ts': 'нет'},
          {'seq': 4, 'msgId': 'b', 'text': 'два', 'name': 'Боря', 'ts': 2000},
        ],
        'seq': '4',
        'truncated': 'да',
      });
      expect(page.messages.map((m) => m.text), ['два']);
      expect(page.seq, 4);
      expect(page.truncated, isFalse);
    });

    test('мусор вместо ответа — пустая лента, а не исключение', () {
      final page = parseRoomChatHistory({'messages': 'нет'});
      expect(page.messages, isEmpty);
      expect(page.seq, 0);
    });
  });
}
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/features/voice/room_chat_history_test.dart`
Expected: FAIL — `Target of URI doesn't exist: room_chat_history.dart`.

- [ ] **Step 3: Написать разбор**

Создать `lib/features/voice/domain/room_chat_history.dart`:

```dart
import 'package:flutter/foundation.dart';

import '../presentation/controllers/room_chat_controller.dart';

/// Страница ленты чата комнаты, полученная от `GET /voice/rooms/:room/chat`.
@immutable
class RoomChatHistoryPage {
  /// Сообщения по возрастанию номера.
  final List<RoomChatMessage> messages;

  /// Идентификаторы разобранных сообщений — экран помечает их обработанными,
  /// иначе то же сообщение придёт живым пакетом и нарисуется дважды.
  final List<String> msgIds;

  /// Курсор для следующего запроса.
  final int seq;

  /// Между запрошенным курсором и первым сообщением есть дыра.
  final bool truncated;

  const RoomChatHistoryPage({
    required this.messages,
    required this.msgIds,
    required this.seq,
    required this.truncated,
  });
}

/// Разбирает ответ ленты.
///
/// Устойчив к типам по той же причине, что и `RoomChatController.handlePacket`:
/// данные приходят из `jsonDecode` по сети, приведение вида `m['text'] as
/// String` бросило бы `TypeError` на числе, и вместо одной пропущенной строки
/// пропала бы вся история.
RoomChatHistoryPage parseRoomChatHistory(Map<String, dynamic> body) {
  final raw = body['messages'];
  final messages = <RoomChatMessage>[];
  final msgIds = <String>[];

  if (raw is List) {
    for (final item in raw) {
      if (item is! Map) continue;
      final text = item['text'] is String ? (item['text'] as String).trim() : '';
      if (text.isEmpty) continue;

      final name = item['name'] is String ? (item['name'] as String).trim() : '';
      final ts = item['ts'];
      messages.add(RoomChatMessage(
        name: name.isEmpty ? 'Taler ID' : name,
        text: text,
        sentAt: ts is int
            ? DateTime.fromMillisecondsSinceEpoch(ts)
            : DateTime.now(),
        own: false,
      ));

      final msgId = item['msgId'];
      if (msgId is String && msgId.isNotEmpty) msgIds.add(msgId);
    }
  }

  final seq = body['seq'];
  return RoomChatHistoryPage(
    messages: messages,
    msgIds: msgIds,
    seq: seq is int ? seq : 0,
    truncated: body['truncated'] == true,
  );
}
```

- [ ] **Step 4: Запустить тест и убедиться, что он проходит**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/features/voice/room_chat_history_test.dart`
Expected: PASS, 5 тестов.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/domain/room_chat_history.dart test/features/voice/room_chat_history_test.dart
git commit -m "feat(voice): разбор ленты чата комнаты"
```

---

## Task 10: Клиент ручек чата в приложении

**Files:**
- Create: `lib/features/voice/data/room_chat_api.dart`

- [ ] **Step 1: Написать клиент**

Создать `lib/features/voice/data/room_chat_api.dart`:

```dart
import 'package:dio/dio.dart';

import '../domain/room_chat_history.dart';

/// Результат отправки сообщения в чат комнаты.
class RoomChatSendResult {
  final String msgId;
  final int seq;
  final int ts;

  const RoomChatSendResult({
    required this.msgId,
    required this.seq,
    required this.ts,
  });
}

/// Ручки чата комнаты.
///
/// Ходит **не** обычным путём `DioClient.post`, а прямо через `dio` с
/// `skipAuth`: авторизация здесь room-scoped LiveKit-токеном, а
/// `AuthInterceptor` иначе перепишет заголовок токеном Taler ID, и в чужой
/// временной комнате запрос получит 403.
class RoomChatApi {
  final Dio _dio;

  RoomChatApi(this._dio);

  Options _auth(String lkToken) => Options(
        headers: {'Authorization': 'Bearer $lkToken'},
        extra: const {'skipAuth': true},
      );

  Future<RoomChatSendResult> send({
    required String roomName,
    required String lkToken,
    required String text,
    required String name,
  }) async {
    final res = await _dio.post<dynamic>(
      '/voice/rooms/$roomName/chat',
      data: {'text': text, 'name': name},
      options: _auth(lkToken),
    );
    final data = Map<String, dynamic>.from(res.data as Map);
    return RoomChatSendResult(
      msgId: data['msgId'] is String ? data['msgId'] as String : '',
      seq: data['seq'] is int ? data['seq'] as int : 0,
      ts: data['ts'] is int
          ? data['ts'] as int
          : DateTime.now().millisecondsSinceEpoch,
    );
  }

  Future<RoomChatHistoryPage> history({
    required String roomName,
    required String lkToken,
    int? since,
  }) async {
    final res = await _dio.get<dynamic>(
      '/voice/rooms/$roomName/chat',
      queryParameters: since == null ? null : {'since': since},
      options: _auth(lkToken),
    );
    return parseRoomChatHistory(Map<String, dynamic>.from(res.data as Map));
  }
}
```

- [ ] **Step 2: Проверить, что собирается**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter analyze lib/features/voice/data/room_chat_api.dart`
Expected: `No issues found`.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/data/room_chat_api.dart
git commit -m "feat(voice): клиент ручек чата комнаты"
```

---

## Task 11: Контроллер принимает историю

**Files:**
- Modify: `lib/features/voice/presentation/controllers/room_chat_controller.dart`
- Modify: `lib/features/voice/presentation/controllers/room_data_packet_ids.dart`
- Test: `test/voice/room_chat_controller_test.dart`

- [ ] **Step 1: Написать падающие тесты**

Дописать в `test/voice/room_chat_controller_test.dart` внутрь существующего `group`:

```dart
    test('история ложится в начало ленты', () {
      final c = RoomChatController();
      c.handlePacket({
        'type': 'chat_message',
        'text': 'живое',
        'name': 'Аня',
        'ts': 3000,
      }, fallbackName: '—');

      c.setHistory([
        RoomChatMessage(
          name: 'Боря',
          text: 'старое',
          sentAt: DateTime.fromMillisecondsSinceEpoch(1000),
          own: false,
        ),
      ]);

      expect(c.messages.map((m) => m.text), ['старое', 'живое']);
    });

    test('история не считается непрочитанным', () {
      final c = RoomChatController();
      c.setHistory([
        RoomChatMessage(
          name: 'Боря',
          text: 'старое',
          sentAt: DateTime.fromMillisecondsSinceEpoch(1000),
          own: false,
        ),
      ]);
      expect(c.unread, 0);
    });

    test('пустая история не дёргает слушателей', () {
      final c = RoomChatController();
      var notified = 0;
      c.addListener(() => notified++);
      c.setHistory([]);
      expect(notified, 0);
    });
```

И в `test/voice/room_data_packet_ids_test.dart` (если файла нет — создать с этим содержимым, добавив импорты как в соседних тестах):

```dart
    test('remember помечает чужой id обработанным', () {
      final ids = RoomDataPacketIds(prefix: 'p');
      ids.remember('server_1');
      expect(ids.isDuplicate('server_1'), isTrue);
    });
```

- [ ] **Step 2: Запустить тесты и убедиться, что они падают**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/voice/room_chat_controller_test.dart test/voice/room_data_packet_ids_test.dart`
Expected: FAIL — `setHistory` и `remember` не определены.

- [ ] **Step 3: Реализовать**

В `room_chat_controller.dart` дописать в класс:

```dart
  /// Лента встречи до нашего входа. Кладётся в начало и **не** увеличивает
  /// счётчик непрочитанных: человек её не пропустил, он только что вошёл.
  ///
  /// Зовётся один раз, сразу после подключения к комнате — до первого живого
  /// пакета. Позже вызывать нельзя: старые сообщения встали бы в начало уже
  /// прочитанной ленты и перемешали порядок.
  void setHistory(List<RoomChatMessage> history) {
    if (history.isEmpty) return;
    _messages.insertAll(0, history);
    notifyListeners();
  }
```

В `room_data_packet_ids.dart` дописать:

```dart
  /// Помечает чужой id обработанным, ничего не спрашивая. Нужно для пакетов,
  /// про которые мы узнали не из data-канала: ответ ручки чата отдаёт `msgId`
  /// сообщения, которое сервер сейчас разошлёт всем, включая нас.
  void remember(String msgId) {
    _seen.add(msgId);
    if (_seen.length > maxRemembered) _seen.clear();
  }
```

и переписать `isDuplicate` через него, чтобы правило переполнения было одно:

```dart
  bool isDuplicate(String msgId) {
    if (_seen.contains(msgId)) return true;
    remember(msgId);
    return false;
  }
```

- [ ] **Step 4: Запустить тесты и убедиться, что они проходят**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/voice/`
Expected: PASS — новые тесты и все прежние тесты чата.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/presentation/controllers/ test/voice/
git commit -m "feat(voice): контроллер чата принимает историю встречи"
```

---

## Task 12: Экран звонка шлёт через ручку и грузит историю

**Files:**
- Modify: `lib/features/voice/presentation/screens/voice_call_screen.dart:2874-2903` (`_sendChatMessage`)

- [ ] **Step 1: Переписать отправку**

Заменить `_sendChatMessage` на асинхронную версию:

```dart
  /// Отправляет строку в чат комнаты через бэкенд и рисует её у себя.
  ///
  /// Публикация в data-канал напрямую больше не годится: сервер — единственный
  /// отправитель, иначе сообщение не попадёт в ленту встречи и его не увидит
  /// ни вошедший позже, ни внешний ассистент.
  ///
  /// Возвращает, ушла ли строка. Панель чата результат игнорирует, а вот
  /// ассистенту в звонке он нужен: иначе он доложит об отправке того, чего
  /// никто не увидит.
  Future<bool> _sendChatMessage(String text) async {
    final room = _room;
    final token = _lkToken;
    final roomName = _roomName;
    if (room == null || token == null || roomName == null) return false;

    final me = room.localParticipant;
    // Имя уходит в эфир, поэтому подставлять «Вы» нельзя: это метка от
    // первого лица, остальные увидели бы сообщение от «Вы», а автор бы
    // ничего не заметил — своё имя в пузыре не рисуется.
    final myName = (me?.name.isNotEmpty ?? false)
        ? me!.name
        : ((me?.identity.isNotEmpty ?? false)
            ? me!.identity
            : AppLocalizations.of(context)!.voiceParticipant);

    try {
      final res = await sl<RoomChatApi>().send(
        roomName: roomName,
        lkToken: token,
        text: text,
        name: myName,
      );
      // Сервер разошлёт пакет всем участникам, включая нас. Помечаем его id
      // обработанным до эха — иначе своё сообщение нарисуется дважды.
      if (res.msgId.isNotEmpty) _packetIds.remember(res.msgId);
      if (!mounted) return true;
      _chat.addOwn(myName, text);
      setState(() {});
      return true;
    } catch (e) {
      debugPrint('[VoiceCall] room chat send failed: $e');
      return false;
    }
  }
```

- [ ] **Step 2: Научить панель показывать неудачу**

Панель объявляет `final ValueChanged<String> onSend;` и в `_send()` чистит поле, ничего не проверяя. Раньше это было честно — публикация в data-канал либо срабатывала сразу, либо нет; теперь между нажатием и результатом стоит сеть, и молча потерянный текст — худшее, что тут можно сделать.

В `room_chat_panel.dart` поменять тип поля:

```dart
  /// Возвращает, ушло ли сообщение. Панель на неудаче возвращает текст в поле:
  /// набранное не должно пропадать из-за отвалившейся сети.
  final Future<bool> Function(String text) onSend;
```

и `_send`:

```dart
  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    final sent = await widget.onSend(text);
    if (sent || !mounted) return;
    _input.text = text;
    _input.selection = TextSelection.collapsed(offset: text.length);
    ScaffoldMessenger.maybeOf(context)?.showSnackBar(
      SnackBar(content: Text(AppLocalizations.of(context)!.voiceChatSendFailed)),
    );
  }
```

Строку `voiceChatSendFailed` добавить в `lib/l10n/app_ru.arb` («Сообщение не отправлено») и `app_en.arb` («Message not sent»), затем `flutter gen-l10n`.

В `test/voice/room_chat_panel_test.dart` поправить существующие вызовы `onSend:` — они передают синхронный колбэк, теперь нужен `(_) async => true` — и добавить проверку:

```dart
    testWidgets('неудачная отправка возвращает текст в поле', (tester) async {
      await tester.pumpWidget(_wrap(RoomChatPanel(
        controller: RoomChatController(),
        onSend: (_) async => false,
        onClose: () {},
      )));

      await tester.enterText(find.byType(TextField), 'привет');
      await tester.tap(find.byIcon(Icons.send_rounded));
      await tester.pumpAndSettle();

      expect(find.text('привет'), findsOneWidget);
    });
```

(обёртку `_wrap` взять ту, что уже используется в этом файле).

- [ ] **Step 3: Поправить вызывающие стороны**

В месте подключения панели (строка ~4183) заменить:

```dart
                    onSend: _sendChatMessage,
```

В ветке ассистента `send_room_chat` (строка ~2103) заменить условие на `await`:

```dart
        } else if (!mounted || !await _sendChatMessage(parsed.text!)) {
```

Убедиться, что объемлющая функция уже `async` — она такая (`_handleAssistantFunctionCall`).

Дописать импорты в начало файла:

```dart
import '../../data/room_chat_api.dart';
```

- [ ] **Step 4: Зарегистрировать клиент в DI**

В `lib/core/di/injection_container.dart` рядом с другими регистрациями голоса добавить:

```dart
  sl.registerLazySingleton<RoomChatApi>(() => RoomChatApi(sl<DioClient>().dio));
```

с импортом `import '../../features/voice/data/room_chat_api.dart';`.

- [ ] **Step 5: Написать загрузку истории**

Добавить рядом с `_sendChatMessage`:

```dart
  /// Лента встречи до нашего входа. Грузится один раз сразу после подключения:
  /// позже старые сообщения легли бы в начало уже прочитанной ленты.
  Future<void> _loadChatHistory() async {
    final token = _lkToken;
    final roomName = _roomName;
    if (token == null || roomName == null) return;
    try {
      final page = await sl<RoomChatApi>().history(
        roomName: roomName,
        lkToken: token,
      );
      for (final id in page.msgIds) {
        _packetIds.remember(id);
      }
      if (!mounted) return;
      _chat.setHistory(page.messages);
      setState(() {});
    } catch (e) {
      // История — дополнение, а не условие работы чата: без неё живые
      // сообщения продолжают приходить.
      debugPrint('[VoiceCall] room chat history failed: $e');
    }
  }
```

Позвать её сразу после `await _room!.connect(...)` (строка ~824), не дожидаясь результата:

```dart
      unawaited(_loadChatHistory());
```

`unawaited` — из `dart:async`; проверить, что импорт есть.

- [ ] **Step 6: Прогнать тесты и анализатор**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test && flutter analyze lib/features/voice/`
Expected: тесты зелёные; новых замечаний по тронутым файлам нет.

- [ ] **Step 7: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/ lib/core/di/injection_container.dart
git commit -m "feat(voice): приложение шлёт чат через бэкенд и грузит историю"
```

---

## Task 13: Ассистент читает чат

**Files:**
- Modify: `lib/features/assistant/tools/assistant_tools_schema.dart:77-93`
- Modify: `lib/features/assistant/tools/assistant_tools_executor.dart:111-131`
- Test: `test/features/assistant/send_room_chat_tool_test.dart`

- [ ] **Step 1: Написать падающий тест**

Дописать в `test/features/assistant/send_room_chat_tool_test.dart`:

```dart
    test('read_room_chat объявлен в схеме и параметров не требует', () {
      final tool = assistantToolSchemas(translatorMode: false)
          .firstWhere((t) => t['name'] == 'read_room_chat');

      final params = tool['parameters'] as Map<String, dynamic>;
      expect(params['required'], isEmpty);
    });
```

`assistantToolSchemas({required bool translatorMode})` — существующая функция схемы, она уже импортирована в этом файле.

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/features/assistant/send_room_chat_tool_test.dart`
Expected: FAIL — `Bad state: No element`.

- [ ] **Step 3: Добавить инструмент в схему**

В `assistant_tools_schema.dart` сразу после блока `send_room_chat` добавить:

```dart
          {
            'type': 'function',
            'name': 'read_room_chat',
            'description':
                'Read what has been written in the chat of the voice room the user is '
                'currently in. Only works while a call is active. Use when the user asks '
                'what is in the chat ("что там в чате", "прочитай чат", "what did they write"). '
                'Returns the most recent messages with their authors.',
            'parameters': {
              'type': 'object',
              'properties': {},
              'required': [],
            },
          },
```

- [ ] **Step 4: Реализовать в исполнителе**

В `assistant_tools_executor.dart` заменить ветку `send_room_chat` и добавить рядом `read_room_chat`:

```dart
      } else if (name == 'send_room_chat') {
        // Чат комнаты, в которой человек сейчас говорит. Авторизация —
        // room-scoped LiveKit-токеном: `RoomAccessGuard` принимает его всегда,
        // а токен Taler ID в чужой временной комнате даёт 403.
        final roomName = CallStateService.instance.roomName;
        final roomToken = CallStateService.instance.activeRoomToken;
        if (roomName == null || roomName.isEmpty || roomToken == null) {
          return 'There is no active call, so there is no room chat to write to.';
        }
        // Разбор и потолок длины живут в parseRoomChatText — у ассистента на
        // экране звонка свой независимый список инструментов, и отказывать он
        // обязан ровно на тех же основаниях.
        final parsed = parseRoomChatText(args['text']);
        if (!parsed.isValid) {
          return parsed.refusal!;
        }
        final sent = await sl<RoomChatApi>().send(
          roomName: roomName,
          lkToken: roomToken,
          text: parsed.text!,
          name: _roomChatSenderName(),
        );
        output = jsonEncode({'ok': true, 'seq': sent.seq});
      } else if (name == 'read_room_chat') {
        final roomName = CallStateService.instance.roomName;
        final roomToken = CallStateService.instance.activeRoomToken;
        if (roomName == null || roomName.isEmpty || roomToken == null) {
          return 'There is no active call, so there is no room chat to read.';
        }
        final page = await sl<RoomChatApi>().history(
          roomName: roomName,
          lkToken: roomToken,
        );
        if (page.messages.isEmpty) {
          return 'The room chat is empty — nothing has been written yet.';
        }
        // Последние двадцать: вслух всё равно зачитывается несколько строк, а
        // длинная лента только раздувает контекст модели.
        final tail = page.messages.length > 20
            ? page.messages.sublist(page.messages.length - 20)
            : page.messages;
        output = jsonEncode({
          'messages': [
            for (final m in tail) {'name': m.name, 'text': m.text},
          ],
        });
```

Дописать импорты:

```dart
import '../../voice/data/room_chat_api.dart';
```

- [ ] **Step 5: Запустить тесты**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test && flutter analyze lib/features/assistant/`
Expected: PASS; новых замечаний нет.

- [ ] **Step 6: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/assistant/ test/features/assistant/
git commit -m "feat(assistant): read_room_chat и отправка room-scoped токеном"
```

---

## Task 14: E2E-набор

**Files:**
- Create: `~/Downloads/taler_id_tests/room_chat_test.ts`
- Modify: `~/Downloads/taler_id_tests/package.json`

- [ ] **Step 1: Написать тест**

Создать `room_chat_test.ts`:

```ts
import axios from 'axios';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const USER1 = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true, timeout: 15000 });

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, info?: unknown) {
  if (cond) { passed++; console.log(`  ✅ ${name}`); }
  else { failed++; console.log(`  ❌ ${name}`, info === undefined ? '' : JSON.stringify(info)); }
}

function auth(token: string) { return { headers: { Authorization: `Bearer ${token}` } }; }

async function main() {
  console.log(`Чат комнаты: ${BASE_URL}`);

  const login = await http.post('/auth/login', USER1);
  if (login.status !== 200) throw new Error(`login ${login.status}: ${JSON.stringify(login.data)}`);
  const userToken = login.data.accessToken as string;

  const created = await http.post('/voice/rooms/temporary', { title: 'room chat e2e' }, auth(userToken));
  check('1. создана временная комната', created.status === 200 || created.status === 201, created.data);
  const code = created.data?.code as string;

  const joined = await http.post(`/voice/rooms/public/${code}/join`, { name: 'Linkeon' });
  check('2. гостевой вход отдал LiveKit-токен', typeof joined.data?.token === 'string', joined.data);
  const lkToken = joined.data.token as string;
  const roomName = joined.data.roomName as string;

  try {
    const first = await http.post(`/voice/rooms/${roomName}/chat`, { text: 'раз', name: 'Linkeon' }, auth(lkToken));
    check('3. отправка гостевым токеном → 200/201', first.status === 200 || first.status === 201, first.data);
    check('3b. в ответе есть seq и msgId',
      first.data?.seq === 1 && typeof first.data?.msgId === 'string', first.data);

    const second = await http.post(`/voice/rooms/${roomName}/chat`, { text: 'два', name: 'Linkeon' }, auth(lkToken));
    check('4. номера растут', second.data?.seq === 2, second.data);

    const all = await http.get(`/voice/rooms/${roomName}/chat`, auth(lkToken));
    check('5. лента читается целиком', all.status === 200, all.data);
    check('5b. два сообщения по порядку',
      all.data?.messages?.length === 2 &&
      all.data.messages[0].text === 'раз' &&
      all.data.messages[1].text === 'два', all.data);
    check('5c. курсор и truncated в ответе',
      all.data?.seq === 2 && all.data?.truncated === false, all.data);

    const tail = await http.get(`/voice/rooms/${roomName}/chat?since=1`, auth(lkToken));
    check('6. курсор отдаёт только новое',
      tail.data?.messages?.length === 1 && tail.data.messages[0].text === 'два', tail.data);

    // Владелец комнаты — второй допустимый вид доказательства.
    const byOwner = await http.post(`/voice/rooms/${roomName}/chat`, { text: 'от владельца' }, auth(userToken));
    check('7. владелец комнаты пишет своим токеном', byOwner.data?.seq === 3, byOwner.data);

    const empty = await http.post(`/voice/rooms/${roomName}/chat`, { text: '   ' }, auth(lkToken));
    check('8. пустой текст → 400', empty.status === 400, empty.data);

    const long = await http.post(`/voice/rooms/${roomName}/chat`, { text: 'x'.repeat(501) }, auth(lkToken));
    check('9. длиннее 500 символов → 400', long.status === 400, long.data);

    const foreign = await http.get('/voice/rooms/personal-deadbeef-11111111/chat', auth(lkToken));
    check('10. чужая комната → 403', foreign.status === 403, foreign.data);

    const anon = await http.get(`/voice/rooms/${roomName}/chat`);
    check('11. без токена → 401', anon.status === 401, anon.data);

    // Потолок на запись: 10 за 10 секунд, одиннадцатое режется.
    let throttled = 0;
    for (let i = 0; i < 12; i++) {
      const r = await http.post(`/voice/rooms/${roomName}/chat`, { text: `поток ${i}` }, auth(lkToken));
      if (r.status === 429) throttled++;
    }
    check('12. поток сообщений упирается в потолок', throttled > 0, { throttled });
  } finally {
    await http.delete(`/voice/rooms/temporary/${code}`, auth(userToken));
  }

  console.log(`\nprovided: ${passed} ✅  ${failed} ❌`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 2: Добавить скрипты**

В `package.json` в `scripts`:

```json
    "test:room-chat": "BASE_URL=https://staging.id.taler.tirol npx ts-node room_chat_test.ts",
    "test:room-chat:prod": "BASE_URL=https://id.taler.tirol npx ts-node room_chat_test.ts",
    "test:room-chat:talerid": "BASE_URL=https://api.talerid.io npx ts-node room_chat_test.ts",
```

- [ ] **Step 3: Прогнать против DEV**

Run: `cd ~/Downloads/taler_id_tests && npm run test:room-chat`
Expected: `14 ✅  0 ❌`.

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add room_chat_test.ts package.json
git commit -m "test: e2e чата комнаты — отправка, лента, курсор, права"
```

⚠️ В этом репозитории лежат чужие правки — `git add -A` не делать, добавлять только названные файлы.

---

## Task 15: Раскатка

**Files:** нет — деплой и проверка.

- [ ] **Step 1: Дописать набор в батарею тестов**

В `/Users/dmitry/talerid/CLAUDE.md` в раздел обязательных тестов добавить пункт про `npm run test:room-chat` — рядом с остальными, с теми же пояснениями: что ловит (молчащая лента, разъехавшийся курсор, дырявые права) и почему его нельзя гонять вплотную к другим наборам (логины).

- [ ] **Step 2: Проверить, что чат работает между всеми клиентами**

Веб + телефон + десктоп в одной комнате: сообщение из каждого видно у всех ровно один раз, вошедший последним видит написанное до него.

- [ ] **Step 3: Выкатить на TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && npx prisma migrate status && git pull && npm run build && pm2 restart taler-id'
cd ~/Downloads/taler_id_tests && npm run test:room-chat:prod
```

Expected: миграций нет (эта работа их не добавляет), тесты зелёные.

- [ ] **Step 4: Выкатить на PROD (только по явной команде)**

```bash
ssh do-app-1 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id && sleep 5 && curl -s -o /dev/null -w "health:%{http_code}\n" http://localhost:3000/health'
# дождаться health:200, затем то же на do-app-2
cd ~/Downloads/taler_id_tests && npm run test:room-chat:talerid
```

- [ ] **Step 5: Сообщить о переходном состоянии**

Пока мобильный релиз не собран, установленные приложения продолжают публиковать чат сами: их сообщения не попадают в ленту и не видны ни Linkeon, ни вошедшему позже. Сборки версии в `/app/version` и `APP_RELEASES` не объявлять, пока артефакты не лягут на место.
