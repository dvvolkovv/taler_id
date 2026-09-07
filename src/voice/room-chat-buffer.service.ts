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
    // INCR и EXPIRE счётчика — одной транзакцией, отдельной от записи самого
    // сообщения. Прочитать результат INCR из середины чужой транзакции
    // нельзя (MULTI/EXEC не отдаёт промежуточные результаты клиенту, пока не
    // выполнится вся пачка), а seq нужен ДО того, как соберётся тело
    // сообщения для RPUSH — поэтому у счётчика своя пара INCR+EXPIRE. Но это
    // не повод оставлять INCR голым: без парного EXPIRE в той же транзакции
    // процесс, умерший между двумя вызовами, оставляет ключ счётчика без TTL
    // навсегда, если в комнату больше никто не напишет, — ровно та дыра,
    // ради которой транзакции и вводили.
    const seqResult = await client
      .multi()
      .incr(this.seqKey(roomName))
      .expire(this.seqKey(roomName), RoomChatBufferService.ttlSeconds)
      .exec();
    // Слот транзакции может прийти с ошибкой (например WRONGTYPE), и ioredis
    // на это не бросает — он резолвит exec() с [Error, null] в нужном слоте.
    // `?? 0` здесь недопустим: INCR никогда не возвращает 0 законно, поэтому
    // 0 — всегда аномалия, и молча писать сообщение под нулевым seq хуже,
    // чем громко отказать: тихая порча нумерации сломает сортировку и
    // truncated для всех, кто читает эту комнату после.
    const seqSlot = seqResult?.[0];
    if (!seqSlot || seqSlot[0] || typeof seqSlot[1] !== 'number') {
      throw new Error(
        `не удалось получить номер сообщения для ${roomName}: ${seqSlot?.[0] ?? 'нет результата'}`,
      );
    }
    const seq = seqSlot[1];
    const stored: RoomChatEntry = { ...entry, seq };
    // Запись самого сообщения — тоже одной транзакцией: RPUSH, LTRIM и
    // EXPIRE. Раньше (до выноса INCR) это были 4 последовательных вызова, и
    // обрыв связи между любыми двумя из них навсегда оставлял список без
    // TTL — чинить было некому, ведь «следующей записи» могло и не
    // случиться. Круговых обходов по-прежнему два: один на счётчик, один на
    // список, — просто внутри каждого больше нет дыры.
    const writeResult = await client
      .multi()
      .rpush(this.logKey(roomName), JSON.stringify(stored))
      .ltrim(this.logKey(roomName), -RoomChatBufferService.maxMessages, -1)
      .expire(this.logKey(roomName), RoomChatBufferService.ttlSeconds)
      .exec();
    // Тот же риск, что и у seqSlot чуть выше, только опаснее по последствиям:
    // если промолчать здесь, append() отдаст «нормальную на вид» запись с
    // проставленным seq, sendRoomChatMessage разошлёт её в комнату — и все
    // участники её увидят, — а в ленте её не будет никогда: ни строки в
    // истории, ни следа в логе. Тихая потеря на пути, который специально
    // существует, чтобы историю не терять. Проверяем все три слота: RPUSH —
    // главный подозреваемый (WRONGTYPE на ключе списка), LTRIM/EXPIRE следом
    // по той же логике, раз уж транзакция уже здесь.
    const slots = writeResult ?? [];
    const failedSlot = slots.find((slot) => slot?.[0]);
    if (!writeResult || failedSlot) {
      throw new Error(
        `не удалось записать сообщение в ленту ${roomName}: ${failedSlot?.[0] ?? 'нет результата транзакции'}`,
      );
    }
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
      // warn, не debug: сюда попадает отказ самого хранилища (обрыв,
      // таймаут). Законное «строка не совпала» (включая уже вытесненную по
      // LTRIM запись) исключения не бросает — оно тихо возвращает 0 веткой
      // выше, и это осознанно не логируется.
      this.log.warn(`не удалось снять запись ${entry.msgId} из ленты: ${e}`);
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
        const parsed = JSON.parse(line) as RoomChatEntry;
        // Синтаксически валидная строка без числового seq — та же угроза
        // ленте, что и битая строка: компаратор сортировки ниже уйдёт в
        // NaN, а latest может стать undefined. Пропускаем так же тихо.
        if (typeof parsed.seq !== 'number') continue;
        entries.push(parsed);
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

  /**
   * Стирает ленту (список сообщений) комнаты, не трогая счётчик `seq`.
   * Зовётся из `VoiceService`, когда вход в комнату оказывается началом
   * новой встречи, а не продолжением старой (см. её докстринг про то, что
   * вебхуков LiveKit не настроено ни на одном окружении, и границу
   * «встреча закончилась» ловить неоткуда, кроме как на следующем входе).
   *
   * Счётчик переживает очистку намеренно. Если бы он тоже обнулялся,
   * застрявший курсор внешнего ассистента (например, `since=40` от старой
   * встречи) замолчал бы навсегда: все сообщения новой встречи получили бы
   * номера 1, 2, 3…, то есть оказались бы *старее* его курсора, а
   * `truncated` при этом не сработал бы — `read()` объявляет дыру только
   * когда `oldest > since + 1`, а `1 > 41` ложно. Пропажа выглядела бы как
   * тишина в комнате, без единого признака поломки. Монотонный счётчик даёт
   * вместо этого честный ответ: `truncated: true` и сообщения с номерами,
   * продолжающими прежний ряд, — «была дыра, вот что в ней есть» вместо
   * молчания. Счётчик не бессмертен: у него свой TTL (см. `seqKey` в
   * `append()`), и он тихо истекает сам, если следующая встреча в этой
   * комнате не случится вовсе или случится позже, чем через сутки, — то
   * самое состояние, которое `read()` и так умеет показывать как дыру.
   *
   * Ничего не бросает специально для отсутствующего ключа — `DEL`
   * несуществующего ключа в Redis не ошибка, а `resolves 0`. Настоящий
   * отказ хранилища (обрыв, таймаут) пробрасывается наружу как есть —
   * вызывающая сторона (`VoiceService`) сама решает, что для неё «слишком
   * дорого упасть» на этом пути, и ловит здесь же.
   */
  async clearFeed(roomName: string): Promise<void> {
    await this.redis.getClient().del(this.logKey(roomName));
  }

  /** true — отправитель превысил потолок и писать ему сейчас нельзя. */
  async hitRateLimit(roomName: string, actor: string): Promise<boolean> {
    const client = this.redis.getClient();
    const key = `roomchat:${roomName}:rate:${actor}`;
    // INCR и EXPIRE — одной транзакцией: порознь есть окно, где EXPIRE не
    // долетел (обрыв связи, failover Sentinel, смерть процесса между
    // вызовами) и ключ остаётся без TTL навсегда. EXPIRE идёт с NX — окно
    // фиксированное, а не скользящее: TTL ставится один раз при первом
    // сообщении окна и не продлевается последующими. Без NX (безусловный
    // EXPIRE на каждом вызове) ключ не истекает, пока отправитель хоть
    // изредка пишет, — тогда счётчик копится бесконечно и в итоге глушит
    // даже человека, который укладывается в лимит, просто пишет короткими
    // репликами («да», «ок», «+1») дольше одного окна.
    const results = await client
      .multi()
      .incr(key)
      .expire(key, RoomChatBufferService.rateWindowSeconds, 'NX')
      .exec();
    // `?? 0` здесь, в отличие от append(), — осознанный выбор, а не
    // недосмотр: цена ошибки другая. В append() нулевой seq портит
    // нумерацию для всех, кто прочитает комнату позже, — это обязано
    // упасть громко. Здесь худшее последствие сбойного слота — пропущенное
    // разовое превышение потолка одним отправителем; блокировать законное
    // сообщение из-за отказа самого лимитера было бы дороже этой ошибки.
    const n = Number(results?.[0]?.[1] ?? 0);
    return n > RoomChatBufferService.rateLimit;
  }
}
