import { createHmac } from 'crypto';

/**
 * Подпись серверных запросов к welID (схема FR-AUTH, sumsub-совместимая).
 *
 * welID включает проверку, когда у него непустой `SUMSUB_APP_SECRETS`
 * (exchange/common #1227). После этого КАЖДЫЙ запрос к `/resources/*` обязан
 * нести три заголовка, иначе ответ 401.
 *
 * Формула — из `app/utils/hmac_signing.py::sign_request_sha256` в welID:
 *
 *   sig = hex_lower( hmac_sha256(secret, ts + METHOD + pathWithQuery + body) )
 *
 * ⚠️ `pathWithQuery` подписывается РОВНО в том виде, в каком уходит в сеть:
 * welID берёт сырой ASGI `raw_path` и НЕ декодирует проценты. Поэтому путь с
 * `encodeURIComponent` подписывается закодированным — декодировать перед
 * подписью нельзя, подпись не сойдётся.
 *
 * ⚠️ Исключения в welID: `OPTIONS` и partner-decision callback (у него своя
 * SHA-1-схема). Маршруты «своей заявки» дополнительно пускают клиентский
 * `X-Access-Token` (welid !121/!127), но серверные вызовы идут по подписи.
 */
export interface FrAuthHeaders {
  'X-App-Token': string;
  'X-App-Access-Ts': string;
  'X-App-Access-Sig': string;
}

export function buildFrAuthHeaders(params: {
  appToken: string;
  appSecret: string;
  method: string;
  pathWithQuery: string;
  body?: string;
  /** Только для тестов: зафиксировать отметку времени. */
  nowSeconds?: number;
}): FrAuthHeaders {
  const { appToken, appSecret, method, pathWithQuery } = params;
  const body = params.body ?? '';
  const ts = String(params.nowSeconds ?? Math.floor(Date.now() / 1000));
  const message = ts + method.toUpperCase() + pathWithQuery + body;
  const sig = createHmac('sha256', appSecret).update(message, 'utf8').digest('hex');
  return {
    'X-App-Token': appToken,
    'X-App-Access-Ts': ts,
    'X-App-Access-Sig': sig,
  };
}

/**
 * Заголовки подписи или пустой объект, если пара token/secret не настроена.
 *
 * Пустая пара — рабочий режим, а не ошибка: welID с выключенной проверкой
 * принимает неподписанные запросы, и это позволяет выкатить код ДО того, как
 * ключи заведут на стороне welID. Порядок именно такой: сначала код, потом
 * ключи — обратный порядок означает 401 и вставший KYC.
 */
export function frAuthHeadersOrEmpty(params: {
  appToken: string;
  appSecret: string;
  method: string;
  pathWithQuery: string;
  body?: string;
  nowSeconds?: number;
}): Record<string, string> {
  if (!params.appToken || !params.appSecret) return {};
  return buildFrAuthHeaders(params) as unknown as Record<string, string>;
}
