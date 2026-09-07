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
  /**
   * true — между курсором запроса и первым отданным сообщением, возможно,
   * есть дыра. Флаг сознательно осторожен: он может сработать вхолостую,
   * например сразу после отката `remove()` первого сообщения ленты, когда
   * курсор формально «упирается» в освободившееся место, хотя на деле
   * ничего не потеряно. Это подсказка «стоит перезагрузить историю», а не
   * гарантия «история потеряна».
   *
   * Без курсора (`since` не передан) флаг не выставляется никогда — даже
   * если `LTRIM` уже выкинул сотни сообщений: сравнивать курсор не с чем,
   * отдаётся вся оставшаяся лента как есть.
   */
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
  // --- Лента: срок жизни и потолок длины ---
  /** Сутки. Встреча столько не идёт, но отставший клиент дотянется. */
  static readonly ttlSeconds = 86400;
  /** Потолок ленты в одной комнате; дальше вытесняются самые старые. */
  static readonly maxMessages = 500;

  // --- Потолок на запись: сколько сообщений и за какое окно ---
  /** `rateLimit` сообщений за `rateWindowSeconds` с одного отправителя в
   *  одну комнату. Ловит зациклившегося бота, человеку недостижим. */
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
    // INCR остаётся вне транзакции не для простоты, а потому что его
    // результат нужен ДО того, как соберутся остальные команды: seq — часть
    // тела сообщения, а очередь MULTI/EXEC в ioredis собирается на клиенте
    // вслепую — результат INCR внутри неё недоступен, пока не выполнится вся
    // пачка. Значит, сериализовать stored для RPUSH можно только после того,
    // как INCR уже отработал сам по себе.
    const seq = await client.incr(this.seqKey(roomName));
    const stored: RoomChatEntry = { ...entry, seq };
    // А вот сама запись сообщения — одной транзакцией: RPUSH, LTRIM и оба
    // EXPIRE. Раньше это были 4 последовательных вызова, и на последнем
    // сообщении комнаты обрыв связи между любыми двумя из них навсегда
    // оставлял список без TTL — чинить было некому, ведь «следующей записи»
    // могло и не случиться.
    await client
      .multi()
      .rpush(this.logKey(roomName), JSON.stringify(stored))
      .ltrim(this.logKey(roomName), -RoomChatBufferService.maxMessages, -1)
      .expire(this.logKey(roomName), RoomChatBufferService.ttlSeconds)
      .expire(this.seqKey(roomName), RoomChatBufferService.ttlSeconds)
      .exec();
    return stored;
  }

  /**
   * Снимает запись обратно. Нужно, когда рассылка в комнату не удалась:
   * сообщение, которого никто не видел, не должно всплыть у того, кто откроет
   * историю.
   *
   * Сравнение идёт по строке, поэтому передавать сюда нужно ровно тот объект,
   * что вернул `append` — с другим порядком полей `LREM` не найдёт запись.
   * Возвращает число снятых записей (0 или 1): 0 не всегда ошибка вызывающей
   * стороны — запись могла уже уйти по `LTRIM`, — но решать, что с этим
   * делать, должна вызывающая сторона, а не эта функция молча.
   */
  async remove(roomName: string, entry: RoomChatEntry): Promise<number> {
    try {
      return await this.redis
        .getClient()
        .lrem(this.logKey(roomName), 1, JSON.stringify(entry));
    } catch (e) {
      this.log.debug(`не удалось снять запись ${entry.msgId} из ленты: ${e}`);
      return 0;
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
    // RPUSH может лечь не в том порядке, в котором писатели получили свои
    // seq: на PROD две app-ноды делят один Redis, а внутри одного процесса
    // `await incr` тоже отпускает event loop между INCR и RPUSH. Двое,
    // печатающих одновременно, — норма встречи, а не редкий случай.
    // Сортируем явно, чтобы oldest/latest и фильтр по since были верны по
    // построению, а не по случайному порядку доставки.
    entries.sort((a, b) => a.seq - b.seq);

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
    // INCR и EXPIRE — одной транзакцией, как в DCR-лимитере (src/main.ts):
    // порознь есть окно, где EXPIRE не долетел (обрыв связи, failover
    // Sentinel, смерть процесса между вызовами) — ключ остаётся без TTL, а
    // отправитель заглушён в этой комнате навсегда. TTL сдвигается на
    // каждом сообщении, а не только на первом: со скользящим окном не нужно
    // отдельно помнить, ставили мы уже TTL или нет, а отправитель, который
    // перестал писать, всё равно остынет через rateWindowSeconds после
    // последнего сообщения.
    const results = await client
      .multi()
      .incr(key)
      .expire(key, RoomChatBufferService.rateWindowSeconds)
      .exec();
    const n = Number(results?.[0]?.[1] ?? 0);
    return n > RoomChatBufferService.rateLimit;
  }
}
