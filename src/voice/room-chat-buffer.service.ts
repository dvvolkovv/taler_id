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
    await client.expire(
      this.logKey(roomName),
      RoomChatBufferService.ttlSeconds,
    );
    await client.expire(
      this.seqKey(roomName),
      RoomChatBufferService.ttlSeconds,
    );
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
