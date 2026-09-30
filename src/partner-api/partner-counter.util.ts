import { HttpException, HttpStatus } from '@nestjs/common';
import type { RedisService } from '../redis/redis.service';

/**
 * Разумный потолок ожидания одной команды Redis. С дефолтными настройками
 * ioredis мёртвый Redis виснет на команде ~10.5с (retry-стратегия), и без
 * собственного таймаута один медленный партнёрский запрос растягивался бы
 * на столько же.
 */
export const PARTNER_COUNTER_TIMEOUT_MS = 250;

/** Текущая минута для ключа счётчика и сколько секунд осталось до её конца (Retry-After). */
export function currentMinute(nowMs: number = Date.now()): { minute: number; retryAfter: number } {
  const nowSec = Math.floor(nowMs / 1000);
  return { minute: Math.floor(nowSec / 60), retryAfter: 60 - (nowSec % 60) };
}

/**
 * Запрос к Redis с потолком ожидания. Никогда не бросает: таймаут, отказ
 * Redis и синхронная ошибка клиента — это null, а что делать без ответа,
 * решает вызывающий.
 */
async function bounded<T>(run: () => Promise<T | null>, timeoutMs: number): Promise<T | null> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
  });
  try {
    return await Promise.race([run().catch((): null => null), timeout]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Атомарный INCR+EXPIRE — тот же приём, что у лимитера DCR-регистрации в
 * main.ts (~строка 600): multi() гарантирует, что процесс не умрёт между
 * INCR и EXPIRE, оставив ключ без TTL навечно. Гонка со своим таймаутом:
 * мёртвый Redis с дефолтными настройками ioredis виснет на команде ~10.5с, а
 * READONLY сразу после failover отклоняется мгновенно — и то, и другое не
 * должно вешать партнёрский запрос на то же время. Никогда не бросает
 * исключение: любая проблема с Redis — это null, а открывать шлюз или не
 * открывать при null решает вызывающий код.
 */
export function incrementCounter(
  redis: RedisService,
  key: string,
  ttlSeconds: number,
  timeoutMs: number = PARTNER_COUNTER_TIMEOUT_MS,
): Promise<number | null> {
  return bounded(async () => {
    const results = await redis.getClient().multi().incr(key).expire(key, ttlSeconds).exec();
    if (!results) return null;
    const [err, value] = results[0];
    return err ? null : Number(value);
  }, timeoutMs);
}

/**
 * Счётчик в окне, которое открывает первый запрос: SET NX EX создаёт ключ
 * сразу со сроком, INCR срок не трогает. Одна транзакция — срок не потеряется
 * между командами, а отказы внутри окна его не продлевают. retryAfter —
 * сколько окну осталось жить. null — Redis не ответил за timeoutMs.
 */
export function countInWindow(
  redis: RedisService,
  key: string,
  windowSeconds: number,
  timeoutMs: number = PARTNER_COUNTER_TIMEOUT_MS,
): Promise<{ count: number; retryAfter: number } | null> {
  return bounded(async () => {
    const results = await redis
      .getClient()
      .multi()
      .set(key, '0', 'EX', windowSeconds, 'NX')
      .incr(key)
      .ttl(key)
      .exec();
    if (!results || results.some(([err]) => err)) return null;
    const count = Number(results[1][1]);
    const ttl = Number(results[2][1]);
    if (ttl < 0) {
      // SET NX EX не мог родить ключ без срока, но кто-то мог позже
      // переписать его вручную (голым SET) — чиним срок сами, а не блокируем
      // окно навсегда.
      redis
        .getClient()
        .expire(key, windowSeconds)
        .catch(() => undefined);
      return { count, retryAfter: windowSeconds };
    }
    return { count, retryAfter: Math.max(1, ttl) };
  }, timeoutMs);
}

/** Ставит Retry-After и бросает 429 с тем же телом, что видит клиент партнёра. */
export function throwTooManyRequests(
  res: { setHeader(name: string, value: string): unknown },
  message: string,
  retryAfter: number,
): never {
  res.setHeader('Retry-After', String(retryAfter));
  throw new HttpException({ message, retryAfter }, HttpStatus.TOO_MANY_REQUESTS);
}
