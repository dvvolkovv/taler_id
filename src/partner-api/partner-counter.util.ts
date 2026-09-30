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
 * Атомарный INCR+EXPIRE — тот же приём, что у лимитера DCR-регистрации в
 * main.ts (~строка 600): multi() гарантирует, что процесс не умрёт между
 * INCR и EXPIRE, оставив ключ без TTL навечно. Гонка со своим таймаутом:
 * мёртвый Redis с дефолтными настройками ioredis виснет на команде ~10.5с, а
 * READONLY сразу после failover отклоняется мгновенно — и то, и другое не
 * должно вешать партнёрский запрос на то же время. Никогда не бросает
 * исключение: любая проблема с Redis — это null, а открывать шлюз или не
 * открывать при null решает вызывающий код.
 */
export async function incrementCounter(
  redis: RedisService,
  key: string,
  ttlSeconds: number,
  timeoutMs: number = PARTNER_COUNTER_TIMEOUT_MS,
): Promise<number | null> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
  });
  try {
    // Строим цепочку и запускаем гонку внутри try: если сам клиент бросает
    // синхронно (например redis.getClient() до готовности соединения), это
    // исключение не должно улететь мимо finally и мимо контракта «никогда
    // не бросает».
    const exec = redis
      .getClient()
      .multi()
      .incr(key)
      .expire(key, ttlSeconds)
      .exec()
      .then((results): number | null => {
        if (!results) return null;
        const [err, value] = results[0];
        return err ? null : Number(value);
      })
      .catch((): null => null);
    return await Promise.race([exec, timeout]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
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
