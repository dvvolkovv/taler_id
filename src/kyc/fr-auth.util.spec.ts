import { buildFrAuthHeaders, frAuthHeadersOrEmpty } from './fr-auth.util';

/**
 * Эталонные подписи посчитаны НЕЗАВИСИМО — питоновской формулой самого welID
 * (`app/utils/hmac_signing.py::sign_request_sha256`), а не этим же кодом.
 * Смысл теста именно в кросс-проверке: если наша реализация разойдётся с
 * welID хоть на байт, запросы начнут получать 401, и поймать это внутри
 * одной кодовой базы нечем.
 *
 *   sig = hex_lower( hmac_sha256(secret, ts + METHOD + pathWithQuery + body) )
 */
const SECRET = 's3cr3t-talerid';
const TS = 1761600000;

describe('FR-AUTH подпись запросов к welID', () => {
  it('совпадает с эталоном welID для POST с телом', () => {
    const body =
      '{"userId":"u1","levelName":"talerID","projectId":"taler","ttlInSecs":600}';
    const h = buildFrAuthHeaders({
      appToken: 'tok',
      appSecret: SECRET,
      method: 'POST',
      pathWithQuery: '/resources/accessTokens/sdk',
      body,
      nowSeconds: TS,
    });
    expect(h['X-App-Access-Sig']).toBe(
      'e9f22b8f12c118ceb81091c2a33f259b34ff4e44115a2d81675eac3688888032',
    );
    expect(h['X-App-Access-Ts']).toBe(String(TS));
    expect(h['X-App-Token']).toBe('tok');
  });

  it('совпадает с эталоном для GET без тела', () => {
    const h = buildFrAuthHeaders({
      appToken: 'tok',
      appSecret: SECRET,
      method: 'GET',
      pathWithQuery: '/resources/applicants/abc123/requiredIdDocsStatus',
      nowSeconds: TS,
    });
    expect(h['X-App-Access-Sig']).toBe(
      '683ed51b84c3ea3424aef7f92fe6461c95f6f84988cbf750898c41bc68d4e8b1',
    );
  });

  // ⚠️ Самый хрупкий случай: welID подписывает СЫРОЙ raw_path и не декодирует
  // проценты. Если где-то декодировать путь перед подписью, тест встанет.
  it('подписывает процент-кодированный путь как есть, без декодирования', () => {
    const h = buildFrAuthHeaders({
      appToken: 'tok',
      appSecret: SECRET,
      method: 'GET',
      pathWithQuery:
        '/resources/applicants/-;externalUserId=user%40example.com/one',
      nowSeconds: TS,
    });
    expect(h['X-App-Access-Sig']).toBe(
      'f679853472938f9e028b3f2ae416d7e64238c3656919f4acadda7d9eeb4b3dac',
    );
  });

  it('метод приводится к верхнему регистру', () => {
    const a = buildFrAuthHeaders({
      appToken: 't', appSecret: SECRET, method: 'post',
      pathWithQuery: '/resources/x', nowSeconds: TS,
    });
    const b = buildFrAuthHeaders({
      appToken: 't', appSecret: SECRET, method: 'POST',
      pathWithQuery: '/resources/x', nowSeconds: TS,
    });
    expect(a['X-App-Access-Sig']).toBe(b['X-App-Access-Sig']);
  });

  describe('frAuthHeadersOrEmpty', () => {
    // Пустая пара — рабочий режим, а не ошибка: позволяет выкатить код ДО
    // того, как ключи заведут в welID. Если бы здесь бросалось исключение,
    // выкатка кода сама по себе положила бы KYC.
    it.each([
      ['оба пусты', '', ''],
      ['нет токена', '', SECRET],
      ['нет секрета', 'tok', ''],
    ])('без настроенной пары (%s) заголовков нет', (_n, token, secret) => {
      expect(
        frAuthHeadersOrEmpty({
          appToken: token, appSecret: secret,
          method: 'GET', pathWithQuery: '/resources/x',
        }),
      ).toEqual({});
    });

    it('с настроенной парой отдаёт все три заголовка', () => {
      const h = frAuthHeadersOrEmpty({
        appToken: 'tok', appSecret: SECRET,
        method: 'GET', pathWithQuery: '/resources/x', nowSeconds: TS,
      });
      expect(Object.keys(h).sort()).toEqual(
        ['X-App-Access-Sig', 'X-App-Access-Ts', 'X-App-Token'],
      );
    });
  });
});
