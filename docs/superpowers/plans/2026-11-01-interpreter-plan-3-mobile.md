# Разговор с переводом — план 3: мобильное приложение

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Раздел «Разговор с переводом» в мобильном приложении. Двое рядом, у каждого свой телефон: один показывает QR, второй сканирует, и дальше каждый слышит в трубке только перевод речи собеседника. Плюс две небольшие правки бэкенда под экран: стоимость для хоста и инструмент ассистента в промптах.

**Architecture:** Новая фича `lib/features/interpreter/` по обычной схеме приложения: domain, data, presentation (BLoC, GetIt). Логика комнаты LiveKit отделена от `livekit_client` портом `InterpreterRoomPort`, поэтому правила изоляции проверены модульными тестами:
- микрофон доступен только агенту и закрыт до публикации;
- подписка идёт только на дорожку `interp-for-<я>`;
- при полном переподключении микрофон глушится.

Звук идёт в трубку, экран гаснет по датчику приближения, на Android микрофон в фоне держит foreground-сервис. Для этого есть канал `taler_id/interpreter_device` с нативной частью для Android и iOS. Экран один, вид выбирается по состоянию BLoC. Вход в раздел:
- кнопка на вкладке «Звонки»;
- ссылка `talerid://interp/<код>` из системной камеры и из сканера профиля;
- инструмент ассистента `open_interpreter`.

**Tech Stack:**
- Мобилка: Flutter 3.38.9, Dart ≥ 3.6, flutter_bloc 8.1.6, equatable, go_router 14, get_it 8, dio 5, livekit_client 2.4.1, mobile_scanner 6, qr_flutter 4.1, wakelock_plus, bloc_test + mocktail.
- Нативная часть: Kotlin (Android) и Swift (iOS).
- Бэкенд: NestJS + Jest. Сквозной набор: `taler_id_tests` (TypeScript).

**Спека:** `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md` в репозитории бэкенда — разделы «Пользовательский сценарий», «Мобильное приложение», «Сбои и крайние случаи».

**Это план 3 из 3.** План 1 (агент и стенд) и план 2 (бэкенд, биллинг, сквозные наборы) выполнены. Бэкенд разговора работает на DEV с 01.11.2026, мониторинг видит строки `FATAL interpreter:`.

**Правила для исполнителя:**
- Задачи 1–2 делаются в бэкенде: worktree `/Users/dmitry/taler-id/.worktrees/interpreter`, ветка `feat/interpreter`. Задача 3 — в `~/Downloads/taler_id_tests`, ветка `main`; там лежат чужие правки, поэтому только `git add` перечисленных файлов, никогда `git add -A`.
- Задачи 4–24 делаются в мобилке: worktree `~/Downloads/taler_id_mobile/.worktrees/interpreter`, ветка `feat/interpreter` от `origin/dev` (`745679d`). Команды запускаются из корня worktree. Перед задачей 4 там нужен `flutter pub get`.
- Блок `diff` — это патч от корня репозитория. Его надо сохранить в файл программно, не перепечатывая, и применить `git apply <файл>`. Если патч не применился — стоп и отчёт.
- Блок «целиком» переносится в файл слово в слово.
- Тесты мобилки: `flutter test <пути>`. Базовая точка до плана — `+1672: All tests passed!` на весь набор.
- Анализатор: у репозитория сотни давних замечаний. Новые файлы фичи должны давать `No issues found!`, на изменённых старых файлах число замечаний не должно расти — в задаче указано, сколько их ожидается.
- Локализация: ключи добавляются в `lib/l10n/app_en.arb` и `lib/l10n/app_ru.arb`. Настоящий шаблон gen-l10n — `app_en.arb`: строка `template-arb-locale` в `l10n.yaml` не опция и ни на что не влияет. После правки ARB запускается `flutter gen-l10n`, сгенерированные `app_localizations*.dart` коммитятся.
- Каждый коммит — с двумя `-m`: сообщение и `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- Ничего не пушить, не деплоить и не собирать для раздачи без явного «да» пользователя (задача 25).
- Токены, секреты и коды не печатать.

## Карта файлов

**Бэкенд:** `src/interpreter/interpreter.service.ts` (+ спека) — `spentPlanck`; `src/assistant/prompts/{ru,en}.md`.

**Сквозной набор:** `interpreter_test.ts` — проверки 14d и 14e.

**Мобилка, новое — `lib/features/interpreter/`:**

| Файл | Что делает |
|---|---|
| `domain/interpreter_models.dart` | ответы `/interpreter/*` |
| `domain/interpreter_error.dart` | коды ошибок сервера → `InterpreterErrorKind` |
| `domain/interpreter_code.dart` | ссылка `talerid://interp/<код>` |
| `domain/interpreter_repository.dart`, `data/*` | источник данных, репозиторий, язык |
| `room/interpreter_signal.dart`, `room/caption_lines.dart` | сигналы агента, строки субтитров |
| `room/interpreter_room_port.dart`, `room/interpreter_room_controller.dart` | правила комнаты |
| `room/livekit_interpreter_room.dart` | адаптер LiveKit, адрес комнаты |
| `room/interpreter_device.dart` | трубка, датчик приближения, фон |
| `presentation/bloc/*` | состояния и переходы |
| `presentation/screens/interpreter_screen.dart`, `presentation/widgets/*` | экраны |

**Мобилка, правки:**
- `lib/core/api/dio_client.dart` — `kNoResendAfterTimeout`;
- `lib/core/di/service_locator.dart`, `lib/core/router/{app_router,deep_link_handler}.dart`, `lib/core/utils/constants.dart`;
- вкладка «Звонки», сканер профиля, ассистент (схема, промпты, экран);
- `lib/l10n/app_{en,ru}.arb`;
- Android: манифест, `MainActivity.kt`, новый `InterpreterForegroundService.kt`; iOS: `AppDelegate.swift`.

---

### Task 1: Бэкенд — `spentPlanck` в ответе о сессии для хоста

Экран разговора у хоста показывает таймер и стоимость (спека, «Разговор»). Стоимость берётся из биллинга: `AiSession.totalSpentPlanck` той сессии, что открыл вход гостя. Гостю поле не показывается (`null`), до входа гостя — тоже `null`. Приложение опрашивает `GET /interpreter/sessions/:id` раз в 15 с, так что отдельная ручка не нужна.

**Репозиторий:** бэкенд, worktree `/Users/dmitry/taler-id/.worktrees/interpreter`, ветка `feat/interpreter`.

**Files:**
- Modify: `src/interpreter/interpreter.service.ts`, `src/interpreter/interpreter.service.spec.ts`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/interpreter/interpreter.service.spec.ts`:

```diff
--- a/src/interpreter/interpreter.service.spec.ts
+++ b/src/interpreter/interpreter.service.spec.ts
@@ -98,7 +98,9 @@
       findUnique: jest.fn(async ({ where }: any) => profiles[where.userId]),
     },
     aiSession: {
-      findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
+      findUnique: jest
+        .fn()
+        .mockResolvedValue({ status: 'active', totalSpentPlanck: 0n }),
     },
   };
   const gating = {
@@ -669,12 +671,16 @@
       partner: null,
       directions: null,
       startedAt: null,
+      spentPlanck: null,
     });
   });
 
   it('shows each side the other one', async () => {
-    const { service, rows } = setup();
+    const { service, rows, prisma } = setup();
     rows.push(activeRow({ guestLang: 'sk' }));
+    prisma.aiSession.findUnique.mockResolvedValue({
+      totalSpentPlanck: 1_234_567n,
+    });
 
     await expect(service.get(HOST, 'sess-1')).resolves.toEqual({
       status: 'active',
@@ -682,6 +688,11 @@
       partner: { firstName: 'Boris', avatarUrl: null, lang: 'sk' },
       directions: { toMe: 'simultaneous', fromMe: 'phrase' },
       startedAt: NOW,
+      spentPlanck: '1234567',
+    });
+    expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
+      where: { id: 'bill-1' },
+      select: { totalSpentPlanck: true },
     });
     await expect(service.get(GUEST, 'sess-1')).resolves.toEqual(
       expect.objectContaining({
@@ -691,6 +702,8 @@
           lang: 'ru',
         },
         directions: { toMe: 'phrase', fromMe: 'simultaneous' },
+        // The guest pays nothing and is not shown the host's spending.
+        spentPlanck: null,
       }),
     );
   });
```

Run: `npx jest src/interpreter/interpreter.service`
Expected: падают 2 теста в `interpreter.service.spec.ts` (ждут `spentPlanck`).

- [ ] **Step 2: Код**

Патч к `src/interpreter/interpreter.service.ts`:

```diff
--- a/src/interpreter/interpreter.service.ts
+++ b/src/interpreter/interpreter.service.ts
@@ -386,10 +386,12 @@
     partner: Partner | null;
     directions: Directions | null;
     startedAt: Date | null;
+    spentPlanck: string | null;
   }> {
     const s = await this.participantSession(userId, sessionId);
     const status = s.status.toLowerCase();
     const endReason = s.endReason?.toLowerCase() ?? null;
+    const spentPlanck = await this.spentPlanck(s, userId);
     if (!s.guestId || !s.guestLang) {
       return {
         status,
@@ -397,6 +399,7 @@
         partner: null,
         directions: null,
         startedAt: s.startedAt,
+        spentPlanck,
       };
     }
     const iAmHost = s.hostId === userId;
@@ -419,7 +422,21 @@
         fromMe: engineFor(myLang, partnerLang),
       },
       startedAt: s.startedAt,
+      spentPlanck,
     };
+  }
+
+  /** What the host has paid so far, for the app's cost line; the guest pays nothing. */
+  private async spentPlanck(
+    s: InterpreterSession,
+    userId: string,
+  ): Promise<string | null> {
+    if (s.hostId !== userId || !s.billingSessionId) return null;
+    const billing = await this.prisma.aiSession.findUnique({
+      where: { id: s.billingSessionId },
+      select: { totalSpentPlanck: true },
+    });
+    return billing ? billing.totalSpentPlanck.toString() : null;
   }
 
   /**
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards src/assistant 2>&1 | tail -5
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 213 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter.service.ts src/interpreter/interpreter.service.spec.ts
git commit -m "feat(interpreter): spentPlanck в ответе о сессии — стоимость для экрана хоста" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Бэкенд — инструмент `open_interpreter` в промптах ассистента

Промпты ассистента приходят с сервера (`GET /assistant/instructions`). Новый раздел отличает разговор с переводом (у каждого свой телефон, QR) от прежнего режима переводчика (один телефон между двумя людьми) и говорит, когда вызывать `open_interpreter` с `host` и с `join`. Сам инструмент объявляет приложение (задача 23).

**Files:**
- Modify: `src/assistant/prompts/ru.md`, `src/assistant/prompts/en.md`

- [ ] **Step 1: Текст**

Патч к `src/assistant/prompts/ru.md`:

```diff
--- a/src/assistant/prompts/ru.md
+++ b/src/assistant/prompts/ru.md
@@ -42,6 +42,12 @@
 → Если пользователь назвал язык («включи переводчик на словацкий», «переводи с русского на немецкий») — сразу вызови enter_translator_mode с lang_a и lang_b. Ничего не говори — просто вызови tool.
 → Если язык собеседника НЕ назван — коротко спроси «На какой язык переводить?» и вызови enter_translator_mode после ответа. Не угадывай язык.
 → Внутри переводчика язык меняют командой «выбери язык X» / «переводи на X», выходят — «Ассистент, стоп» / «хватит переводить».
+
+РАЗГОВОР С ПЕРЕВОДОМ (у каждого свой телефон):
+Это не режим переводчика выше. Двое рядом, у обоих TalerID: каждый говорит в свой телефон и слышит в трубке только перевод речи собеседника. Соединяются по QR-коду.
+→ «начни разговор с переводом», «покажи QR для перевода», «хочу поговорить с переводом с ним» → open_interpreter с action 'host': откроется экран, где пользователь выберет свой язык и покажет QR.
+→ «отсканируй его код», «войди в разговор с переводом», «у собеседника QR» → open_interpreter с action 'join': откроется сканер.
+→ Платит тот, кто показал QR, поминутно. Скажи это одной фразой, если спрашивают о цене. Если у собеседника нет TalerID — предложи режим переводчика выше.
 
 ПЕРЕКЛЮЧЕНИЕ РЕЖИМОВ:
 - При входе в режим — подтверди голосом какой режим активирован
```

Патч к `src/assistant/prompts/en.md`:

```diff
--- a/src/assistant/prompts/en.md
+++ b/src/assistant/prompts/en.md
@@ -42,6 +42,12 @@
 → If the user named the language ("translator into Slovak", "translate between English and German") — call enter_translator_mode with lang_a and lang_b right away. Do not say anything — just call the tool.
 → If the other person's language was NOT named — briefly ask "Which language should I translate into?" and call enter_translator_mode after the answer. Do not guess the language.
 → Inside the translator the language is changed with "choose language X" / "translate into X"; exit with "stop translator".
+
+CONVERSATION WITH TRANSLATION (each on their own phone):
+This is not the translator mode above. Two people side by side, both with TalerID: each speaks into their own phone and hears only the translation of the other person in the earpiece. The phones connect by QR code.
+→ "start a conversation with translation", "show the QR for translation", "I want to talk to him with translation" → call open_interpreter with action 'host': a screen opens where the user picks their language and shows the QR.
+→ "scan their code", "join the conversation with translation", "they have a QR" → call open_interpreter with action 'join': the scanner opens.
+→ Whoever shows the QR pays, per minute. Say so in one sentence if asked about the price. If the other person has no TalerID, suggest the translator mode above.
 
 MODE SWITCHING:
 - When entering a mode — confirm by voice which mode is activated
```

- [ ] **Step 2: Проверить**

```bash
npx jest src/assistant 2>&1 | tail -4
```

Ожидается: наборы `src/assistant` зелёные (промпт читается из файла, плейсхолдеры не тронуты).

- [ ] **Step 3: Коммит**

```bash
git add src/assistant/prompts/ru.md src/assistant/prompts/en.md
git commit -m "feat(assistant): open_interpreter в промптах — разговор с переводом не путать с режимом переводчика" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Сквозной набор — `spentPlanck` у хоста и у гостя

Две проверки после списания (14): хост видит в `GET /interpreter/sessions/:id` не меньше, чем уже списано транзакциями, гость — `null`.

**Репозиторий:** `~/Downloads/taler_id_tests`, ветка `main`. Только `git add` перечисленного файла.

**Files:**
- Modify: `interpreter_test.ts`

- [ ] **Step 1: Проверки**

Патч к `interpreter_test.ts`:

```diff
--- a/interpreter_test.ts
+++ b/interpreter_test.ts
@@ -15,7 +15,7 @@
  *   POST /interpreter/sessions          {lang}        → {sessionId, code, expiresAt, roomName, token, livekitWsUrl}
  *   POST /interpreter/sessions/:id/code               → {code, expiresAt}
  *   POST /interpreter/sessions/join     {code, lang}  → {sessionId, roomName, token, livekitWsUrl, partner, directions}
- *   GET  /interpreter/sessions/:id                    → {status, endReason, partner, directions, startedAt}
+ *   GET  /interpreter/sessions/:id                    → {status, endReason, partner, directions, startedAt, spentPlanck}
  *   POST /interpreter/sessions/:id/end                → {status: 'ended'}
  *
  * The bots take their LiveKit token and URL from those responses, so the
@@ -948,6 +948,16 @@
     const guestCharged = guestTx?.filter((t) => !txBefore.b.has(t.id));
     check('14c. B, the guest, is not charged', !!guestCharged && guestCharged.length === 0,
       guestCharged ?? 'GET /billing/transactions failed for B');
+    // The app's cost line. Read after the debits above, so at least their sum.
+    const paid = (charged ?? []).reduce((sum, t) => sum + BigInt(t.amountPlanck), 0n);
+    const hostPaid = await view(A, sessionId);
+    const spent = hostPaid.data?.spentPlanck;
+    check('14d. GET as A shows what A has paid so far: spentPlanck is at least the debits above',
+      hostPaid.status === 200 && paid > 0n && typeof spent === 'string' && /^\d+$/.test(spent) && BigInt(spent) >= paid,
+      { spentPlanck: spent, debits: String(paid) });
+    const guestPaid = await view(B, sessionId);
+    check('14e. ...and B, the guest, is shown no spending', guestPaid.status === 200 && guestPaid.data?.spentPlanck === null,
+      seen(guestPaid));
 
     // ── 15. The agent's callback is closed to everybody else ─────────────
     // Run while the conversation is active: a callback that got through
```

- [ ] **Step 2: Типы**

```bash
cd ~/Downloads/taler_id_tests
npx tsc --noEmit -p tsconfig.json 2>&1 | grep -c interpreter_test ; true
```

Ожидается: `0`. Прогон против DEV — в задаче 25, после выкатки задачи 1.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add interpreter_test.ts
git commit -m "test: test:interpreter — spentPlanck у хоста и у гостя" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Модели и ошибки

- Ответы `/interpreter/*` — обычные неизменяемые классы с `fromJson` и Equatable, без freezed: кодогенерация ради десятка полей не окупается. Неизвестная строка движка — `phrase` (не обещать потоковые субтитры), неизвестный статус — `ended` (не зависнуть посреди сценария), неизвестная причина — `null`.
- Ошибки сервера — код в `message` (строка или первый элемент списка). `DioClient` уже превращает `DioException` в `ApiException` с телом ответа; `InterpreterException.from` достаёт из него код. Уже готовый `InterpreterException` проходит насквозь — иначе повторное преобразование превратило бы любой код в `unknown`.

**Files:**
- Create: `test/features/interpreter/domain/interpreter_models_test.dart`, `test/features/interpreter/domain/interpreter_error_test.dart`, `lib/features/interpreter/domain/interpreter_models.dart`, `lib/features/interpreter/domain/interpreter_error.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/domain/interpreter_models_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';

void main() {
  group('InterpreterLanguage', () {
    test('parses from json', () {
      final lang =
          InterpreterLanguage.fromJson({'code': 'ru', 'name': 'Русский'});
      expect(lang.code, 'ru');
      expect(lang.name, 'Русский');
    });

    test('equality by value', () {
      expect(
        InterpreterLanguage(code: 'ru', name: 'Русский'),
        InterpreterLanguage(code: 'ru', name: 'Русский'),
      );
    });
  });

  group('InterpreterCatalog', () {
    test('parses enabled + languages', () {
      final catalog = InterpreterCatalog.fromJson({
        'enabled': true,
        'languages': [
          {'code': 'ru', 'name': 'Русский'},
          {'code': 'en', 'name': 'English'},
        ],
      });
      expect(catalog.enabled, isTrue);
      expect(catalog.languages, hasLength(2));
      expect(catalog.languages.first.code, 'ru');
    });

    test('parses disabled with empty list', () {
      final catalog =
          InterpreterCatalog.fromJson({'enabled': false, 'languages': []});
      expect(catalog.enabled, isFalse);
      expect(catalog.languages, isEmpty);
    });
  });

  group('interpreterEngineFromJson', () {
    test('simultaneous', () {
      expect(interpreterEngineFromJson('simultaneous'),
          InterpreterEngine.simultaneous);
    });

    test('phrase', () {
      expect(interpreterEngineFromJson('phrase'), InterpreterEngine.phrase);
    });

    test('unknown falls back to phrase (the conservative UI)', () {
      expect(
          interpreterEngineFromJson('something_new'), InterpreterEngine.phrase);
    });
  });

  group('InterpreterDirections', () {
    test('parses both directions independently', () {
      final directions = InterpreterDirections.fromJson({
        'toMe': 'simultaneous',
        'fromMe': 'phrase',
      });
      expect(directions.toMe, InterpreterEngine.simultaneous);
      expect(directions.fromMe, InterpreterEngine.phrase);
    });
  });

  group('InterpreterPartner', () {
    test('parses with nulls', () {
      final partner = InterpreterPartner.fromJson({
        'firstName': null,
        'avatarUrl': null,
        'lang': 'de',
      });
      expect(partner.firstName, isNull);
      expect(partner.avatarUrl, isNull);
      expect(partner.lang, 'de');
    });

    test('parses full', () {
      final partner = InterpreterPartner.fromJson({
        'firstName': 'Anna',
        'avatarUrl': 'https://x/y.png',
        'lang': 'de',
      });
      expect(partner.firstName, 'Anna');
      expect(partner.avatarUrl, 'https://x/y.png');
    });
  });

  group('HostedSession', () {
    test('parses host session', () {
      final session = HostedSession.fromJson({
        'sessionId': 's1',
        'code': 'ABC123',
        'expiresAt': '2026-11-01T12:05:00Z',
        'roomName': 'interp-s1',
        'token': 'tok',
        'livekitWsUrl': 'wss://lk/',
      });
      expect(session.sessionId, 's1');
      expect(session.code, 'ABC123');
      expect(session.expiresAt, DateTime.parse('2026-11-01T12:05:00Z'));
      expect(session.roomName, 'interp-s1');
      expect(session.token, 'tok');
      expect(session.livekitWsUrl, 'wss://lk/');
    });
  });

  group('NewCode', () {
    test('parses new code', () {
      final code = NewCode.fromJson({
        'code': 'XYZ789',
        'expiresAt': '2026-11-01T12:10:00Z',
      });
      expect(code.code, 'XYZ789');
      expect(code.expiresAt, DateTime.parse('2026-11-01T12:10:00Z'));
    });
  });

  group('JoinedSession', () {
    test('parses guest join response', () {
      final joined = JoinedSession.fromJson({
        'sessionId': 's1',
        'roomName': 'interp-s1',
        'token': 'tok',
        'livekitWsUrl': 'wss://lk/',
        'partner': {'firstName': 'Dmitry', 'avatarUrl': null, 'lang': 'ru'},
        'directions': {'toMe': 'simultaneous', 'fromMe': 'simultaneous'},
      });
      expect(joined.sessionId, 's1');
      expect(joined.partner.firstName, 'Dmitry');
      expect(joined.partner.lang, 'ru');
      expect(joined.directions.toMe, InterpreterEngine.simultaneous);
    });
  });

  group('interpreterStatusFromJson', () {
    test(
        'waiting',
        () => expect(
            interpreterStatusFromJson('waiting'), InterpreterStatus.waiting));
    test(
        'active',
        () => expect(
            interpreterStatusFromJson('active'), InterpreterStatus.active));
    test(
        'ended',
        () => expect(
            interpreterStatusFromJson('ended'), InterpreterStatus.ended));
    test('unknown falls back to ended', () {
      expect(interpreterStatusFromJson('whatever'), InterpreterStatus.ended);
    });
  });

  group('interpreterEndReasonFromJson', () {
    const cases = {
      'hangup': InterpreterEndReason.hangup,
      'partner_left': InterpreterEndReason.partnerLeft,
      'expired': InterpreterEndReason.expired,
      'translation_failed': InterpreterEndReason.translationFailed,
      'agent_lost': InterpreterEndReason.agentLost,
      'no_funds': InterpreterEndReason.noFunds,
      'max_duration': InterpreterEndReason.maxDuration,
    };

    cases.forEach((raw, expected) {
      test('maps $raw', () {
        expect(interpreterEndReasonFromJson(raw), expected);
      });
    });

    test('null stays null', () {
      expect(interpreterEndReasonFromJson(null), isNull);
    });

    test('unknown code maps to null, not a guess', () {
      expect(interpreterEndReasonFromJson('something_new'), isNull);
    });
  });

  group('SessionView', () {
    test('parses a full host view', () {
      final view = SessionView.fromJson({
        'status': 'active',
        'endReason': null,
        'partner': {'firstName': 'B', 'avatarUrl': null, 'lang': 'en'},
        'directions': {'toMe': 'phrase', 'fromMe': 'simultaneous'},
        'startedAt': '2026-11-01T12:00:00Z',
        'spentPlanck': '12345',
      });
      expect(view.status, InterpreterStatus.active);
      expect(view.endReason, isNull);
      expect(view.partner!.firstName, 'B');
      expect(view.directions!.fromMe, InterpreterEngine.simultaneous);
      expect(view.startedAt, DateTime.parse('2026-11-01T12:00:00Z'));
      expect(view.spentPlanck, '12345');
    });

    test('parses a minimal waiting view (guest, before billing opens)', () {
      final view = SessionView.fromJson({
        'status': 'waiting',
        'endReason': null,
        'partner': null,
        'directions': null,
        'startedAt': null,
        'spentPlanck': null,
      });
      expect(view.status, InterpreterStatus.waiting);
      expect(view.partner, isNull);
      expect(view.directions, isNull);
      expect(view.startedAt, isNull);
      expect(view.spentPlanck, isNull);
    });

    test('parses an ended view with a reason', () {
      final view = SessionView.fromJson({
        'status': 'ended',
        'endReason': 'partner_left',
        'partner': null,
        'directions': null,
        'startedAt': '2026-11-01T12:00:00Z',
        'spentPlanck': '500',
      });
      expect(view.status, InterpreterStatus.ended);
      expect(view.endReason, InterpreterEndReason.partnerLeft);
    });
  });
}
```

`test/features/interpreter/domain/interpreter_error_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/core/api/api_exception.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_error.dart';

ApiException _apiError(int statusCode, String code) => ApiException(
      statusCode: statusCode,
      message: code,
      data: {'statusCode': statusCode, 'message': code},
    );

void main() {
  group('InterpreterException.from — every backend code', () {
    const codes = {
      'interpreter_disabled': InterpreterErrorKind.interpreterDisabled,
      'unsupported_language': InterpreterErrorKind.unsupportedLanguage,
      'same_language': InterpreterErrorKind.sameLanguage,
      'voice_print_required': InterpreterErrorKind.voicePrintRequired,
      'host_voice_print_required': InterpreterErrorKind.hostVoicePrintRequired,
      'already_in_session': InterpreterErrorKind.alreadyInSession,
      'same_voice_print': InterpreterErrorKind.sameVoicePrint,
      'own_code': InterpreterErrorKind.ownCode,
      'code_used': InterpreterErrorKind.codeUsed,
      'not_waiting': InterpreterErrorKind.notWaiting,
      'insufficient_funds': InterpreterErrorKind.insufficientFunds,
      'host_insufficient_funds': InterpreterErrorKind.hostInsufficientFunds,
      'feature_disabled': InterpreterErrorKind.featureDisabled,
      'host_feature_disabled': InterpreterErrorKind.hostFeatureDisabled,
      'code_not_found': InterpreterErrorKind.codeNotFound,
      'session_not_found': InterpreterErrorKind.sessionNotFound,
      'code_expired': InterpreterErrorKind.codeExpired,
      'too_many_attempts': InterpreterErrorKind.tooManyAttempts,
      'interpreter_unavailable': InterpreterErrorKind.interpreterUnavailable,
    };

    codes.forEach((code, expectedKind) {
      test('maps "$code"', () {
        final exception = InterpreterException.from(_apiError(409, code));
        expect(exception.kind, expectedKind);
        expect(exception.statusCode, 409);
      });
    });
  });

  test('message as the first string of a list maps the same way', () {
    final exception = InterpreterException.from(ApiException(
      statusCode: 400,
      message: 'ignored',
      data: {
        'message': ['same_language', 'extra context']
      },
    ));
    expect(exception.kind, InterpreterErrorKind.sameLanguage);
  });

  test('a code the client does not recognise maps to unknown', () {
    final exception =
        InterpreterException.from(_apiError(400, 'brand_new_code'));
    expect(exception.kind, InterpreterErrorKind.unknown);
    expect(exception.statusCode, 400);
  });

  test('missing data map maps to unknown', () {
    final exception = InterpreterException.from(
      const ApiException(statusCode: 500, message: 'boom'),
    );
    expect(exception.kind, InterpreterErrorKind.unknown);
    expect(exception.statusCode, 500);
  });

  test('null statusCode (no response reached the server) maps to network', () {
    final exception = InterpreterException.from(
      const ApiException(message: 'timeout'),
    );
    expect(exception.kind, InterpreterErrorKind.network);
    expect(exception.statusCode, isNull);
  });

  test('an InterpreterException passes through with its kind', () {
    const original =
        InterpreterException(InterpreterErrorKind.codeUsed, statusCode: 409);
    expect(InterpreterException.from(original), same(original));
  });

  test('a non-ApiException error maps to unknown', () {
    final exception = InterpreterException.from(Exception('boom'));
    expect(exception.kind, InterpreterErrorKind.unknown);
    expect(exception.statusCode, isNull);
  });
}
```

Run: `flutter test test/features/interpreter/domain/interpreter_models_test.dart test/features/interpreter/domain/interpreter_error_test.dart`
Expected: `test/features/interpreter/domain/interpreter_error_test.dart` — не запускается (нет ещё кода, который он импортирует); `test/features/interpreter/domain/interpreter_models_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 2.

- [ ] **Step 2: Код**

`lib/features/interpreter/domain/interpreter_models.dart` целиком:

```dart
import 'package:equatable/equatable.dart';

/// One entry of `GET /interpreter/languages`.
class InterpreterLanguage extends Equatable {
  final String code;
  final String name;

  const InterpreterLanguage({required this.code, required this.name});

  factory InterpreterLanguage.fromJson(Map<String, dynamic> json) =>
      InterpreterLanguage(
        code: json['code'] as String,
        name: json['name'] as String,
      );

  @override
  List<Object?> get props => [code, name];
}

/// `GET /interpreter/languages` response — the feature switch plus the
/// supported language list.
class InterpreterCatalog extends Equatable {
  final bool enabled;
  final List<InterpreterLanguage> languages;

  const InterpreterCatalog({required this.enabled, required this.languages});

  factory InterpreterCatalog.fromJson(Map<String, dynamic> json) =>
      InterpreterCatalog(
        enabled: json['enabled'] as bool,
        languages: (json['languages'] as List)
            .map((e) => InterpreterLanguage.fromJson(
                  Map<String, dynamic>.from(e as Map),
                ))
            .toList(),
      );

  @override
  List<Object?> get props => [enabled, languages];
}

/// Which translation engine a direction runs on, per the join answer's
/// `directions`.
enum InterpreterEngine { simultaneous, phrase }

/// Unknown engine strings fall back to [InterpreterEngine.phrase]: it is the
/// more conservative UI (a "phrase" badge, no streamed captions) rather than
/// silently promising simultaneous translation the server didn't commit to.
InterpreterEngine interpreterEngineFromJson(String raw) => switch (raw) {
      'simultaneous' => InterpreterEngine.simultaneous,
      'phrase' => InterpreterEngine.phrase,
      _ => InterpreterEngine.phrase,
    };

class InterpreterDirections extends Equatable {
  final InterpreterEngine toMe;
  final InterpreterEngine fromMe;

  const InterpreterDirections({required this.toMe, required this.fromMe});

  factory InterpreterDirections.fromJson(Map<String, dynamic> json) =>
      InterpreterDirections(
        toMe: interpreterEngineFromJson(json['toMe'] as String),
        fromMe: interpreterEngineFromJson(json['fromMe'] as String),
      );

  @override
  List<Object?> get props => [toMe, fromMe];
}

class InterpreterPartner extends Equatable {
  final String? firstName;
  final String? avatarUrl;
  final String lang;

  const InterpreterPartner(
      {this.firstName, this.avatarUrl, required this.lang});

  factory InterpreterPartner.fromJson(Map<String, dynamic> json) =>
      InterpreterPartner(
        firstName: json['firstName'] as String?,
        avatarUrl: json['avatarUrl'] as String?,
        lang: json['lang'] as String,
      );

  @override
  List<Object?> get props => [firstName, avatarUrl, lang];
}

/// `POST /interpreter/sessions` response — host (A) side of a fresh session.
class HostedSession extends Equatable {
  final String sessionId;
  final String code;
  final DateTime expiresAt;
  final String roomName;
  final String token;
  final String livekitWsUrl;

  const HostedSession({
    required this.sessionId,
    required this.code,
    required this.expiresAt,
    required this.roomName,
    required this.token,
    required this.livekitWsUrl,
  });

  factory HostedSession.fromJson(Map<String, dynamic> json) => HostedSession(
        sessionId: json['sessionId'] as String,
        code: json['code'] as String,
        expiresAt: DateTime.parse(json['expiresAt'] as String),
        roomName: json['roomName'] as String,
        token: json['token'] as String,
        livekitWsUrl: json['livekitWsUrl'] as String,
      );

  @override
  List<Object?> get props =>
      [sessionId, code, expiresAt, roomName, token, livekitWsUrl];
}

/// `POST /interpreter/sessions/:id/code` response — a replacement QR code
/// for a still-waiting session.
class NewCode extends Equatable {
  final String code;
  final DateTime expiresAt;

  const NewCode({required this.code, required this.expiresAt});

  factory NewCode.fromJson(Map<String, dynamic> json) => NewCode(
        code: json['code'] as String,
        expiresAt: DateTime.parse(json['expiresAt'] as String),
      );

  @override
  List<Object?> get props => [code, expiresAt];
}

/// `POST /interpreter/sessions/join` response — guest (B) side.
class JoinedSession extends Equatable {
  final String sessionId;
  final String roomName;
  final String token;
  final String livekitWsUrl;
  final InterpreterPartner partner;
  final InterpreterDirections directions;

  const JoinedSession({
    required this.sessionId,
    required this.roomName,
    required this.token,
    required this.livekitWsUrl,
    required this.partner,
    required this.directions,
  });

  factory JoinedSession.fromJson(Map<String, dynamic> json) => JoinedSession(
        sessionId: json['sessionId'] as String,
        roomName: json['roomName'] as String,
        token: json['token'] as String,
        livekitWsUrl: json['livekitWsUrl'] as String,
        partner: InterpreterPartner.fromJson(
          Map<String, dynamic>.from(json['partner'] as Map),
        ),
        directions: InterpreterDirections.fromJson(
          Map<String, dynamic>.from(json['directions'] as Map),
        ),
      );

  @override
  List<Object?> get props =>
      [sessionId, roomName, token, livekitWsUrl, partner, directions];
}

enum InterpreterStatus { waiting, active, ended }

/// An unrecognised status is treated as [InterpreterStatus.ended]: a session
/// the client can't name a known state for is safer shown as "over" than
/// left spinning in a state the UI doesn't know how to render.
InterpreterStatus interpreterStatusFromJson(String raw) => switch (raw) {
      'waiting' => InterpreterStatus.waiting,
      'active' => InterpreterStatus.active,
      'ended' => InterpreterStatus.ended,
      _ => InterpreterStatus.ended,
    };

enum InterpreterEndReason {
  hangup,
  partnerLeft,
  expired,
  translationFailed,
  agentLost,
  noFunds,
  maxDuration,
}

/// `endReason` is optional on the wire; an unrecognised non-null value maps
/// to `null` rather than throwing or guessing — the ended screen already
/// handles a missing reason with generic wording.
InterpreterEndReason? interpreterEndReasonFromJson(String? raw) {
  switch (raw) {
    case 'hangup':
      return InterpreterEndReason.hangup;
    case 'partner_left':
      return InterpreterEndReason.partnerLeft;
    case 'expired':
      return InterpreterEndReason.expired;
    case 'translation_failed':
      return InterpreterEndReason.translationFailed;
    case 'agent_lost':
      return InterpreterEndReason.agentLost;
    case 'no_funds':
      return InterpreterEndReason.noFunds;
    case 'max_duration':
      return InterpreterEndReason.maxDuration;
    default:
      return null;
  }
}

/// `GET /interpreter/sessions/:id` response.
class SessionView extends Equatable {
  final InterpreterStatus status;
  final InterpreterEndReason? endReason;
  final InterpreterPartner? partner;
  final InterpreterDirections? directions;
  final DateTime? startedAt;
  final String? spentPlanck;

  const SessionView({
    required this.status,
    this.endReason,
    this.partner,
    this.directions,
    this.startedAt,
    this.spentPlanck,
  });

  factory SessionView.fromJson(Map<String, dynamic> json) {
    final partnerJson = json['partner'];
    final directionsJson = json['directions'];
    final startedAtRaw = json['startedAt'] as String?;
    return SessionView(
      status: interpreterStatusFromJson(json['status'] as String),
      endReason: interpreterEndReasonFromJson(json['endReason'] as String?),
      partner: partnerJson == null
          ? null
          : InterpreterPartner.fromJson(
              Map<String, dynamic>.from(partnerJson as Map),
            ),
      directions: directionsJson == null
          ? null
          : InterpreterDirections.fromJson(
              Map<String, dynamic>.from(directionsJson as Map),
            ),
      startedAt: startedAtRaw == null ? null : DateTime.parse(startedAtRaw),
      spentPlanck: json['spentPlanck'] as String?,
    );
  }

  @override
  List<Object?> get props =>
      [status, endReason, partner, directions, startedAt, spentPlanck];
}
```

`lib/features/interpreter/domain/interpreter_error.dart` целиком:

```dart
import '../../../core/api/api_exception.dart';

/// One value per backend error code (spec table in the interpreter design),
/// plus [network] for a failed call that never reached the server and
/// [unknown] for anything else (non-API errors, or a code the client
/// doesn't recognise yet).
enum InterpreterErrorKind {
  interpreterDisabled,
  unsupportedLanguage,
  sameLanguage,
  voicePrintRequired,
  hostVoicePrintRequired,
  alreadyInSession,
  sameVoicePrint,
  ownCode,
  codeUsed,
  notWaiting,
  insufficientFunds,
  hostInsufficientFunds,
  featureDisabled,
  hostFeatureDisabled,
  codeNotFound,
  sessionNotFound,
  codeExpired,
  tooManyAttempts,
  interpreterUnavailable,
  network,
  unknown,
}

const Map<String, InterpreterErrorKind> _kindByCode = {
  'interpreter_disabled': InterpreterErrorKind.interpreterDisabled,
  'unsupported_language': InterpreterErrorKind.unsupportedLanguage,
  'same_language': InterpreterErrorKind.sameLanguage,
  'voice_print_required': InterpreterErrorKind.voicePrintRequired,
  'host_voice_print_required': InterpreterErrorKind.hostVoicePrintRequired,
  'already_in_session': InterpreterErrorKind.alreadyInSession,
  'same_voice_print': InterpreterErrorKind.sameVoicePrint,
  'own_code': InterpreterErrorKind.ownCode,
  'code_used': InterpreterErrorKind.codeUsed,
  'not_waiting': InterpreterErrorKind.notWaiting,
  'insufficient_funds': InterpreterErrorKind.insufficientFunds,
  'host_insufficient_funds': InterpreterErrorKind.hostInsufficientFunds,
  'feature_disabled': InterpreterErrorKind.featureDisabled,
  'host_feature_disabled': InterpreterErrorKind.hostFeatureDisabled,
  'code_not_found': InterpreterErrorKind.codeNotFound,
  'session_not_found': InterpreterErrorKind.sessionNotFound,
  'code_expired': InterpreterErrorKind.codeExpired,
  'too_many_attempts': InterpreterErrorKind.tooManyAttempts,
  'interpreter_unavailable': InterpreterErrorKind.interpreterUnavailable,
};

/// Thrown by every [InterpreterRepository] method. Screens switch on [kind]
/// to show the per-code text the spec calls for, instead of a generic error.
class InterpreterException implements Exception {
  final InterpreterErrorKind kind;
  final int? statusCode;

  const InterpreterException(this.kind, {this.statusCode});

  /// [error] is normally the [ApiException] a datasource call raised (or, for
  /// the `join` call, one built by hand from [ApiErrorHandler.handle] since
  /// that call bypasses `DioClient`'s own try/catch to set a longer timeout).
  /// A `statusCode == null` means the request never got a response — no
  /// point reading a body that isn't there, so that maps straight to
  /// [InterpreterErrorKind.network]. Anything that isn't an [ApiException] at
  /// all (a parsing bug, a plain [Exception]) maps to [unknown] rather than
  /// pretending to know its status code.
  factory InterpreterException.from(Object error) {
    // Already mapped (the repository throws these): keep its kind.
    if (error is InterpreterException) return error;
    if (error is ApiException) {
      if (error.statusCode == null) {
        return const InterpreterException(InterpreterErrorKind.network);
      }
      final code = _codeOf(error.data);
      final kind = code == null
          ? InterpreterErrorKind.unknown
          : _kindByCode[code] ?? InterpreterErrorKind.unknown;
      return InterpreterException(kind, statusCode: error.statusCode);
    }
    return const InterpreterException(InterpreterErrorKind.unknown);
  }

  /// The backend's error body is `{statusCode, message: '<code>' | ['<code>']}`
  /// — `message` is a bare string on most errors but a validation pipe can
  /// turn it into a list; either shape names the code in the same place.
  static String? _codeOf(Map<String, dynamic>? data) {
    final raw = data?['message'];
    if (raw is String) return raw;
    if (raw is List && raw.isNotEmpty && raw.first is String) {
      return raw.first as String;
    }
    return null;
  }

  @override
  String toString() =>
      'InterpreterException(${kind.name}, statusCode: $statusCode)';
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/domain/interpreter_models_test.dart test/features/interpreter/domain/interpreter_error_test.dart lib/features/interpreter/domain/interpreter_models.dart lib/features/interpreter/domain/interpreter_error.dart
```

Ожидается: `+54: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/domain/interpreter_models_test.dart test/features/interpreter/domain/interpreter_error_test.dart lib/features/interpreter/domain/interpreter_models.dart lib/features/interpreter/domain/interpreter_error.dart
git commit -m "feat(interpreter): модели ответов и коды ошибок разговора с переводом" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Ссылка в QR

- В QR — `talerid://interp/<код>`. Сканер приложения, системная камера (через ссылку) и сканер профиля принимают только её; код возвращается как есть — нормализует сервер.

**Files:**
- Create: `test/features/interpreter/domain/interpreter_code_test.dart`, `lib/features/interpreter/domain/interpreter_code.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/domain/interpreter_code_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_code.dart';

void main() {
  group('codeFromScan', () {
    test('accepts a valid link', () {
      expect(codeFromScan('talerid://interp/ABC123'), 'ABC123');
    });

    test('tolerates a trailing slash', () {
      expect(codeFromScan('talerid://interp/ABC123/'), 'ABC123');
    });

    test('accepts an uppercase scheme/host, preserving the code case', () {
      expect(codeFromScan('TALERID://INTERP/AbC123'), 'AbC123');
    });

    test('mixed-case scheme/host also accepted', () {
      expect(codeFromScan('TalerId://Interp/code1'), 'code1');
    });

    test('rejects a different talerid:// path', () {
      expect(codeFromScan('talerid://user/x'), isNull);
    });

    test('rejects an https URL', () {
      expect(codeFromScan('https://talerid.io/interp/ABC123'), isNull);
    });

    test('rejects an empty string', () {
      expect(codeFromScan(''), isNull);
    });

    test('rejects a non-URI string', () {
      expect(codeFromScan('not a uri at all'), isNull);
    });

    test('rejects a link with no code segment', () {
      expect(codeFromScan('talerid://interp/'), isNull);
    });

    test('rejects a link with extra path segments', () {
      expect(codeFromScan('talerid://interp/ABC123/extra'), isNull);
    });
  });

  group('interpreterLink', () {
    test('builds the deep link for a code', () {
      expect(interpreterLink('ABC123'), 'talerid://interp/ABC123');
    });
  });
}
```

Run: `flutter test test/features/interpreter/domain/interpreter_code_test.dart`
Expected: `test/features/interpreter/domain/interpreter_code_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/domain/interpreter_code.dart` целиком:

```dart
/// Extracts the session code from a scanned `talerid://interp/<code>` link.
///
/// Scheme and host are matched case-insensitively (a system camera or a
/// third-party QR reader may hand back the link with whatever casing it
/// decided to normalize to), but the code segment itself is returned exactly
/// as scanned — the backend is the one that normalizes it, not the client.
/// A trailing slash after the code is tolerated. Anything else — a bare
/// `https://` link, a different `talerid://` path (e.g. `talerid://user/x`),
/// not a URI at all, or an empty string — returns `null`.
String? codeFromScan(String raw) {
  final uri = Uri.tryParse(raw.trim());
  if (uri == null) return null;
  if (uri.scheme.toLowerCase() != 'talerid') return null;
  if (uri.host.toLowerCase() != 'interp') return null;

  final segments = uri.pathSegments.where((s) => s.isNotEmpty).toList();
  if (segments.length != 1) return null;
  return segments.first;
}

/// Builds the deep link a host's QR code encodes.
String interpreterLink(String code) => 'talerid://interp/$code';
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/domain/interpreter_code_test.dart lib/features/interpreter/domain/interpreter_code.dart
```

Ожидается: `+65: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/domain/interpreter_code_test.dart lib/features/interpreter/domain/interpreter_code.dart
git commit -m "feat(interpreter): ссылка talerid://interp/<код> и её разбор" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Запрос, который нельзя отправить дважды

- `_RetryInterceptor` повторяет запрос после `receiveTimeout` и переключает его на другой edge. Для входа по коду это опасно: первый запрос мог уже занять одноразовый код и открыть биллинг хоста, повтор получит `409 code_used`, перехватчик вернёт исходный таймаут — и приложение покажет «нет сети», хотя гость уже в разговоре, а хост платит. Новый ключ `kNoResendAfterTimeout` в `extra` запрещает повтор после таймаута ответа; ошибки соединения повторяются как раньше — тот запрос никуда не ушёл. `DioClient.post` получает необязательный `options`.

**Files:**
- Modify: `test/core/retry_interceptor_test.dart`, `lib/core/api/dio_client.dart`

- [ ] **Step 1: Тесты (падают)**

Патч к `test/core/retry_interceptor_test.dart`:

```diff
--- a/test/core/retry_interceptor_test.dart
+++ b/test/core/retry_interceptor_test.dart
@@ -1,3 +1,5 @@
+import 'dart:typed_data';
+
 import 'package:dio/dio.dart';
 import 'package:flutter_test/flutter_test.dart';
 import 'package:mocktail/mocktail.dart';
@@ -9,6 +11,28 @@
 // An alternative: we create a Dio with interceptors and test error handling.
 
 class MockSecureStorageService extends Mock implements SecureStorageService {}
+
+/// Records every attempt and always fails the same way — enough to tell
+/// "sent once" from "retried" without a real socket.
+class _ScriptedAdapter implements HttpClientAdapter {
+  _ScriptedAdapter(this._makeError);
+
+  final DioException Function(RequestOptions options) _makeError;
+  final List<RequestOptions> requests = [];
+
+  @override
+  Future<ResponseBody> fetch(
+    RequestOptions options,
+    Stream<Uint8List>? requestStream,
+    Future<void>? cancelFuture,
+  ) async {
+    requests.add(options);
+    throw _makeError(options);
+  }
+
+  @override
+  void close({bool force = false}) {}
+}
 
 void main() {
   // Test ApiErrorHandler integration — retry is private, so we test the
@@ -78,8 +102,8 @@
     test('retry interceptor logic: retries on connectionTimeout', () async {
       // Simulate what _RetryInterceptor does: check error type and retry count
       final requestOptions = RequestOptions(path: '/test');
-      final isConnectionTimeout =
-          DioExceptionType.connectionTimeout == DioExceptionType.connectionTimeout;
+      final isConnectionTimeout = DioExceptionType.connectionTimeout ==
+          DioExceptionType.connectionTimeout;
       final isReceiveTimeout =
           DioExceptionType.receiveTimeout == DioExceptionType.receiveTimeout;
       final isConnectionError =
@@ -118,4 +142,90 @@
       expect(500 * (1 + 1), 1000); // Second retry: 1000ms
     });
   });
+
+  // Exercises the real interceptor chain registered by `DioClient.create`
+  // against a scripted `HttpClientAdapter` — unlike the groups above, these
+  // assert actual request counts rather than just the retry formula.
+  group('kNoResendAfterTimeout', () {
+    DioClient buildClient(DioException Function(RequestOptions) makeError) {
+      final storage = MockSecureStorageService();
+      when(() => storage.getAccessToken()).thenAnswer((_) async => null);
+      final authInterceptor = AuthInterceptor(dio: Dio(), storage: storage);
+      final client = DioClient.create(authInterceptor: authInterceptor);
+      client.dio.httpClientAdapter = _ScriptedAdapter(makeError);
+      return client;
+    }
+
+    List<RequestOptions> requestsOf(DioClient client) =>
+        (client.dio.httpClientAdapter as _ScriptedAdapter).requests;
+
+    test('receiveTimeout with the flag is sent exactly once', () async {
+      final client = buildClient((o) => DioException(
+            requestOptions: o,
+            type: DioExceptionType.receiveTimeout,
+          ));
+
+      await expectLater(
+        client.dio.post<dynamic>(
+          '/interpreter/sessions/join',
+          options: Options(extra: {kNoResendAfterTimeout: true}),
+        ),
+        throwsA(isA<DioException>()
+            .having((e) => e.type, 'type', DioExceptionType.receiveTimeout)),
+      );
+
+      expect(requestsOf(client), hasLength(1));
+    });
+
+    test('receiveTimeout without the flag is retried as before', () async {
+      final client = buildClient((o) => DioException(
+            requestOptions: o,
+            type: DioExceptionType.receiveTimeout,
+          ));
+
+      await expectLater(
+        client.dio.post<dynamic>('/interpreter/sessions/join'),
+        throwsA(isA<DioException>()),
+      );
+
+      // Original attempt + 2 transient retries (default maxRetries).
+      expect(requestsOf(client), hasLength(3));
+    });
+
+    test(
+        'connectionError with the flag is still retried — the request never left',
+        () async {
+      final client = buildClient((o) => DioException(
+            requestOptions: o,
+            type: DioExceptionType.connectionError,
+          ));
+
+      await expectLater(
+        client.dio.post<dynamic>(
+          '/interpreter/sessions/join',
+          options: Options(extra: {kNoResendAfterTimeout: true}),
+        ),
+        throwsA(isA<DioException>()),
+      );
+
+      expect(requestsOf(client), hasLength(3));
+    });
+
+    test('connectionTimeout with the flag is still retried too', () async {
+      final client = buildClient((o) => DioException(
+            requestOptions: o,
+            type: DioExceptionType.connectionTimeout,
+          ));
+
+      await expectLater(
+        client.dio.post<dynamic>(
+          '/interpreter/sessions/join',
+          options: Options(extra: {kNoResendAfterTimeout: true}),
+        ),
+        throwsA(isA<DioException>()),
+      );
+
+      expect(requestsOf(client), hasLength(3));
+    });
+  });
 }
```

Run: `flutter test test/core/retry_interceptor_test.dart`
Expected: `test/core/retry_interceptor_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

Патч к `lib/core/api/dio_client.dart`:

```diff
--- a/lib/core/api/dio_client.dart
+++ b/lib/core/api/dio_client.dart
@@ -8,6 +8,12 @@
 import 'endpoint_service.dart';
 import '../services/device_id_service.dart';
 
+/// [Options.extra] key for a request the server must not get twice (a
+/// single-use code, a billing session): after a receive timeout it may have
+/// arrived, so it is neither retried nor failed over to another edge. A
+/// connection timeout or error still retries — that request never left.
+const kNoResendAfterTimeout = 'noResendAfterTimeout';
+
 class _RetryInterceptor extends Interceptor {
   final Dio dio;
   final int maxRetries;
@@ -25,7 +31,13 @@
     // Don't retry logout — it's fire-and-forget; local cleanup runs regardless.
     final isLogout = err.requestOptions.path.contains('/auth/logout');
 
-    if (isNetworkError && !isLogout && retryCount < maxRetries) {
+    final mustNotResend = err.type == DioExceptionType.receiveTimeout &&
+        err.requestOptions.extra[kNoResendAfterTimeout] == true;
+
+    if (isNetworkError &&
+        !isLogout &&
+        !mustNotResend &&
+        retryCount < maxRetries) {
       await Future.delayed(Duration(milliseconds: 500 * (retryCount + 1)));
       final opts = err.requestOptions;
       opts.extra['retryCount'] = retryCount + 1;
@@ -44,6 +56,7 @@
     final failoverCount = err.requestOptions.extra['failoverCount'] as int? ?? 0;
     if (isNetworkError &&
         !isLogout &&
+        !mustNotResend &&
         ep != null &&
         ep.hasFallback &&
         failoverCount < ep.candidates.length - 1) {
@@ -155,10 +168,11 @@
   Future<T> post<T>(
     String path, {
     dynamic data,
-    T Function(dynamic)? fromJson,
-  }) async {
-    try {
-      final response = await _dio.post(path, data: data);
+    Options? options,
+    T Function(dynamic)? fromJson,
+  }) async {
+    try {
+      final response = await _dio.post(path, data: data, options: options);
       return fromJson != null ? fromJson(response.data) : response.data as T;
     } on DioException catch (e) {
       throw ApiErrorHandler.handle(e);
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/core 2>&1 | tail -1
flutter analyze lib/core/api/dio_client.dart 2>&1 | grep -c " • "; true
```

Ожидается: `+725: All tests passed!`; замечаний анализатора на изменённых старых файлах столько же, сколько до задачи: `1` (давние, не наши).

- [ ] **Step 4: Коммит**

```bash
git add test/core/retry_interceptor_test.dart lib/core/api/dio_client.dart
git commit -m "fix(api): kNoResendAfterTimeout — запрос с одноразовым кодом не уходит повторно после таймаута" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Данные: источник, репозиторий, язык

- Вход по коду ждёт ответа до 45 с (`receiveTimeout`): бэкенд ждёт старта агента до 35 с, обычные 30 с клиента оборвали бы удачный вход. Вход и создание помечены `kNoResendAfterTimeout`.
- Последний выбранный язык хранится на телефоне (`SecureStorageService`, ключ `interpreter_lang`), в профиль не пишется. По умолчанию — язык приложения, если агент его знает, иначе `en`.
- Код из ссылки, открытой до входа в аккаунт, ждёт входа в памяти процесса 5 минут (столько живёт сам код) — как запрос OAuth в `OAuthPendingRequest`: холодный старт по ссылке и вход идут в одном процессе.

**Files:**
- Create: `test/features/interpreter/data/interpreter_remote_datasource_test.dart`, `test/features/interpreter/data/interpreter_lang_store_test.dart`, `test/features/interpreter/data/pending_interpreter_join_test.dart`, `lib/features/interpreter/domain/interpreter_repository.dart`, `lib/features/interpreter/data/interpreter_remote_datasource.dart`, `lib/features/interpreter/data/interpreter_repository_impl.dart`, `lib/features/interpreter/data/interpreter_lang_store.dart`, `lib/features/interpreter/data/pending_interpreter_join.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/data/interpreter_remote_datasource_test.dart` целиком:

```dart
import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/core/api/api_exception.dart';
import 'package:taler_id_mobile/core/api/dio_client.dart';
import 'package:taler_id_mobile/features/interpreter/data/interpreter_remote_datasource.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_error.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';

class MockDioClient extends Mock implements DioClient {}

class MockDio extends Mock implements Dio {}

class FakeRequestOptions extends Fake implements RequestOptions {}

void main() {
  late MockDioClient http;
  late MockDio dio;
  late InterpreterRemoteDataSource ds;

  setUpAll(() {
    registerFallbackValue(FakeRequestOptions());
    registerFallbackValue(Options());
  });

  setUp(() {
    http = MockDioClient();
    dio = MockDio();
    ds = InterpreterRemoteDataSource(http);
  });

  group('catalog', () {
    test('parses the catalog on success', () async {
      when(() => http.get<InterpreterCatalog>(
            '/interpreter/languages',
            fromJson: any(named: 'fromJson'),
          )).thenAnswer((invocation) async {
        final fromJson = invocation.namedArguments[#fromJson]
            as InterpreterCatalog Function(dynamic);
        return fromJson({
          'enabled': true,
          'languages': [
            {'code': 'ru', 'name': 'Русский'}
          ],
        });
      });

      final result = await ds.catalog();

      expect(result.enabled, isTrue);
      expect(result.languages.single.code, 'ru');
    });

    test('maps a thrown ApiException to InterpreterException', () async {
      when(() => http.get<InterpreterCatalog>(
            '/interpreter/languages',
            fromJson: any(named: 'fromJson'),
          )).thenThrow(const ApiException(
        statusCode: 403,
        message: 'interpreter_disabled',
        data: {'message': 'interpreter_disabled'},
      ));

      await expectLater(
        ds.catalog(),
        throwsA(isA<InterpreterException>().having(
          (e) => e.kind,
          'kind',
          InterpreterErrorKind.interpreterDisabled,
        )),
      );
    });
  });

  group('create', () {
    test('posts the chosen language and parses the hosted session', () async {
      when(() => http.post<HostedSession>(
            '/interpreter/sessions',
            data: {'lang': 'ru'},
            options: any(named: 'options'),
            fromJson: any(named: 'fromJson'),
          )).thenAnswer((invocation) async {
        final fromJson = invocation.namedArguments[#fromJson] as HostedSession
            Function(dynamic);
        return fromJson({
          'sessionId': 's1',
          'code': 'ABC123',
          'expiresAt': '2026-11-01T12:05:00Z',
          'roomName': 'interp-s1',
          'token': 'tok',
          'livekitWsUrl': 'wss://lk/',
        });
      });

      final result = await ds.create('ru');

      expect(result.sessionId, 's1');
      expect(result.code, 'ABC123');
    });

    test(
        'flags the request as never-resend-after-timeout — a retried/'
        'failed-over create would open a second QR session', () async {
      when(() => http.post<HostedSession>(
            '/interpreter/sessions',
            data: {'lang': 'ru'},
            options: any(named: 'options'),
            fromJson: any(named: 'fromJson'),
          )).thenAnswer((invocation) async {
        final fromJson = invocation.namedArguments[#fromJson] as HostedSession
            Function(dynamic);
        return fromJson({
          'sessionId': 's1',
          'code': 'ABC123',
          'expiresAt': '2026-11-01T12:05:00Z',
          'roomName': 'interp-s1',
          'token': 'tok',
          'livekitWsUrl': 'wss://lk/',
        });
      });

      await ds.create('ru');

      final captured = verify(() => http.post<HostedSession>(
            '/interpreter/sessions',
            data: {'lang': 'ru'},
            options: captureAny(named: 'options'),
            fromJson: any(named: 'fromJson'),
          )).captured;
      final options = captured.single as Options;
      expect(options.extra?[kNoResendAfterTimeout], isTrue);
    });

    test('maps same_language to InterpreterErrorKind.sameLanguage', () async {
      when(() => http.post<HostedSession>(
            '/interpreter/sessions',
            data: {'lang': 'ru'},
            options: any(named: 'options'),
            fromJson: any(named: 'fromJson'),
          )).thenThrow(const ApiException(
        statusCode: 400,
        message: 'same_language',
        data: {'message': 'same_language'},
      ));

      await expectLater(
        ds.create('ru'),
        throwsA(isA<InterpreterException>()
            .having((e) => e.kind, 'kind', InterpreterErrorKind.sameLanguage)),
      );
    });
  });

  group('newCode', () {
    test('posts to the session code endpoint and parses the response',
        () async {
      when(() => http.post<NewCode>(
            '/interpreter/sessions/s1/code',
            fromJson: any(named: 'fromJson'),
          )).thenAnswer((invocation) async {
        final fromJson =
            invocation.namedArguments[#fromJson] as NewCode Function(dynamic);
        return fromJson({
          'code': 'XYZ789',
          'expiresAt': '2026-11-01T12:10:00Z',
        });
      });

      final result = await ds.newCode('s1');

      expect(result.code, 'XYZ789');
    });

    test('maps not_waiting on failure', () async {
      when(() => http.post<NewCode>(
            '/interpreter/sessions/s1/code',
            fromJson: any(named: 'fromJson'),
          )).thenThrow(const ApiException(
        statusCode: 409,
        message: 'not_waiting',
        data: {'message': 'not_waiting'},
      ));

      await expectLater(
        ds.newCode('s1'),
        throwsA(isA<InterpreterException>()
            .having((e) => e.kind, 'kind', InterpreterErrorKind.notWaiting)),
      );
    });
  });

  group('get', () {
    test('parses a session view', () async {
      when(() => http.get<SessionView>(
            '/interpreter/sessions/s1',
            fromJson: any(named: 'fromJson'),
          )).thenAnswer((invocation) async {
        final fromJson = invocation.namedArguments[#fromJson] as SessionView
            Function(dynamic);
        return fromJson({
          'status': 'active',
          'endReason': null,
          'partner': null,
          'directions': null,
          'startedAt': null,
          'spentPlanck': null,
        });
      });

      final result = await ds.get('s1');

      expect(result.status, InterpreterStatus.active);
    });

    test('maps session_not_found on failure', () async {
      when(() => http.get<SessionView>(
            '/interpreter/sessions/s1',
            fromJson: any(named: 'fromJson'),
          )).thenThrow(const ApiException(
        statusCode: 404,
        message: 'session_not_found',
        data: {'message': 'session_not_found'},
      ));

      await expectLater(
        ds.get('s1'),
        throwsA(isA<InterpreterException>().having(
          (e) => e.kind,
          'kind',
          InterpreterErrorKind.sessionNotFound,
        )),
      );
    });
  });

  group('end', () {
    test('posts to the end endpoint', () async {
      when(() => http.post<dynamic>('/interpreter/sessions/s1/end'))
          .thenAnswer((_) async {});

      await ds.end('s1');

      verify(() => http.post<dynamic>('/interpreter/sessions/s1/end'))
          .called(1);
    });

    test('maps a failure to InterpreterException', () async {
      when(() => http.post<dynamic>('/interpreter/sessions/s1/end')).thenThrow(
          const ApiException(statusCode: 404, message: 'session_not_found'));

      await expectLater(ds.end('s1'), throwsA(isA<InterpreterException>()));
    });
  });

  group('join', () {
    Response<dynamic> responseWith(Map<String, dynamic> data) => Response(
          requestOptions: RequestOptions(path: '/interpreter/sessions/join'),
          statusCode: 200,
          data: data,
        );

    final joinJson = {
      'sessionId': 's1',
      'roomName': 'interp-s1',
      'token': 'tok',
      'livekitWsUrl': 'wss://lk/',
      'partner': {'firstName': 'Anna', 'avatarUrl': null, 'lang': 'de'},
      'directions': {'toMe': 'simultaneous', 'fromMe': 'phrase'},
    };

    test(
        'goes through client.dio with a receiveTimeout of at least 40s and the right body',
        () async {
      when(() => http.dio).thenReturn(dio);
      when(() => dio.post(
            any(),
            data: any(named: 'data'),
            options: any(named: 'options'),
          )).thenAnswer((_) async => responseWith(joinJson));

      final result = await ds.join('ABC123', 'en');

      expect(result.sessionId, 's1');
      expect(result.partner.firstName, 'Anna');
      expect(result.directions.fromMe, InterpreterEngine.phrase);

      final captured = verify(() => dio.post(
            '/interpreter/sessions/join',
            data: captureAny(named: 'data'),
            options: captureAny(named: 'options'),
          )).captured;
      final body = captured[0] as Map;
      final options = captured[1] as Options;
      expect(body, {'code': 'ABC123', 'lang': 'en'});
      expect(options.receiveTimeout, isNotNull);
      expect(options.receiveTimeout!.inSeconds, greaterThanOrEqualTo(40));
      // A retried/failed-over join could consume the single-use code twice
      // and double-open the host's billing session.
      expect(options.extra?[kNoResendAfterTimeout], isTrue);
    });

    test('maps a DioException with a backend code to InterpreterException',
        () async {
      when(() => http.dio).thenReturn(dio);
      when(() => dio.post(
            any(),
            data: any(named: 'data'),
            options: any(named: 'options'),
          )).thenThrow(DioException(
        requestOptions: RequestOptions(path: '/interpreter/sessions/join'),
        type: DioExceptionType.badResponse,
        response: Response(
          requestOptions: RequestOptions(path: '/interpreter/sessions/join'),
          statusCode: 410,
          data: {'statusCode': 410, 'message': 'code_expired'},
        ),
      ));

      await expectLater(
        ds.join('ABC123', 'en'),
        throwsA(isA<InterpreterException>().having(
          (e) => e.kind,
          'kind',
          InterpreterErrorKind.codeExpired,
        )),
      );
    });

    test('maps a connection-level DioException to network', () async {
      when(() => http.dio).thenReturn(dio);
      when(() => dio.post(
            any(),
            data: any(named: 'data'),
            options: any(named: 'options'),
          )).thenThrow(DioException(
        requestOptions: RequestOptions(path: '/interpreter/sessions/join'),
        type: DioExceptionType.connectionError,
      ));

      await expectLater(
        ds.join('ABC123', 'en'),
        throwsA(isA<InterpreterException>()
            .having((e) => e.kind, 'kind', InterpreterErrorKind.network)),
      );
    });
  });
}
```

`test/features/interpreter/data/interpreter_lang_store_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/core/storage/secure_storage_service.dart';
import 'package:taler_id_mobile/features/interpreter/data/interpreter_lang_store.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';

class MockSecureStorageService extends Mock implements SecureStorageService {}

void main() {
  late MockSecureStorageService storage;
  late InterpreterLangStore store;

  final catalog = InterpreterCatalog(
    enabled: true,
    languages: const [
      InterpreterLanguage(code: 'ru', name: 'Русский'),
      InterpreterLanguage(code: 'en', name: 'English'),
    ],
  );

  setUp(() {
    storage = MockSecureStorageService();
    store = InterpreterLangStore(storage);
  });

  group('initial', () {
    test('returns the stored language when the catalog still supports it',
        () async {
      when(() => storage.read('interpreter_lang'))
          .thenAnswer((_) async => 'en');

      final result = await store.initial(catalog, 'ru');

      expect(result, 'en');
    });

    test(
        'falls back to the app locale when the stored language is no longer supported',
        () async {
      when(() => storage.read('interpreter_lang'))
          .thenAnswer((_) async => 'de');

      final result = await store.initial(catalog, 'ru');

      expect(result, 'ru');
    });

    test('falls back to the app locale when nothing is stored', () async {
      when(() => storage.read('interpreter_lang'))
          .thenAnswer((_) async => null);

      final result = await store.initial(catalog, 'en');

      expect(result, 'en');
    });

    test('falls back to en when neither stored nor app locale is supported',
        () async {
      when(() => storage.read('interpreter_lang'))
          .thenAnswer((_) async => null);

      final result = await store.initial(catalog, 'fr');

      expect(result, 'en');
    });
  });

  group('remember', () {
    test('writes the chosen code under the interpreter_lang key', () async {
      when(() => storage.write('interpreter_lang', 'de'))
          .thenAnswer((_) async {});

      await store.remember('de');

      verify(() => storage.write('interpreter_lang', 'de')).called(1);
    });
  });
}
```

`test/features/interpreter/data/pending_interpreter_join_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/data/pending_interpreter_join.dart';

void main() {
  group('PendingInterpreterJoin', () {
    late PendingInterpreterJoin pending;
    late DateTime fakeNow;

    setUp(() {
      fakeNow = DateTime.utc(2026, 11, 1, 12, 0, 0);
      pending = PendingInterpreterJoin(now: () => fakeNow);
    });

    test('consume returns null when nothing was saved', () {
      expect(pending.consume(), isNull);
    });

    test('consume returns the saved code', () {
      pending.save('ABCD1234');
      expect(pending.consume(), 'ABCD1234');
    });

    test('consume is one-shot — a second call returns null', () {
      pending.save('ABCD1234');
      pending.consume();
      expect(pending.consume(), isNull);
    });

    test('consume within the 5-minute TTL returns the code', () {
      pending.save('ABCD1234');
      fakeNow = fakeNow.add(const Duration(minutes: 4));
      expect(pending.consume(), 'ABCD1234');
    });

    test('consume past the TTL returns null and clears the slot', () {
      pending.save('ABCD1234');
      fakeNow = fakeNow.add(const Duration(minutes: 6));
      expect(pending.consume(), isNull);
      // Clearing even on expiry matters — otherwise a later, correctly-timed
      // consume would wrongly resurrect the stale code.
      fakeNow = fakeNow.subtract(const Duration(minutes: 6));
      expect(pending.consume(), isNull);
    });

    test('consume on the exact TTL boundary returns null', () {
      pending.save('ABCD1234');
      fakeNow = fakeNow.add(const Duration(minutes: 5));
      expect(pending.consume(), isNull);
    });

    test(
        'consume returns null when the device clock was corrected backwards '
        'between save and consume', () {
      pending.save('ABCD1234');
      fakeNow = fakeNow.subtract(const Duration(minutes: 1));
      expect(pending.consume(), isNull);
    });

    test('save overwrites a previous, not yet consumed code', () {
      pending.save('FIRST111');
      pending.save('SECOND22');
      expect(pending.consume(), 'SECOND22');
    });
  });
}
```

Run: `flutter test test/features/interpreter/data/interpreter_remote_datasource_test.dart test/features/interpreter/data/interpreter_lang_store_test.dart test/features/interpreter/data/pending_interpreter_join_test.dart`
Expected: `test/features/interpreter/data/interpreter_lang_store_test.dart` — не запускается (нет ещё кода, который он импортирует); `test/features/interpreter/data/interpreter_remote_datasource_test.dart` — не запускается (нет ещё кода, который он импортирует); `test/features/interpreter/data/pending_interpreter_join_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 3.

- [ ] **Step 2: Код**

`lib/features/interpreter/domain/interpreter_repository.dart` целиком:

```dart
import 'interpreter_models.dart';

/// Gateway to `src/interpreter/*` on the backend. Every method throws
/// [InterpreterException] (never the underlying [DioException]/[ApiException])
/// so bloc code only ever catches one exception type.
abstract class InterpreterRepository {
  /// `GET /interpreter/languages`.
  Future<InterpreterCatalog> catalog();

  /// `POST /interpreter/sessions` — host (A) starts a new session.
  Future<HostedSession> create(String lang);

  /// `POST /interpreter/sessions/:id/code` — host asks for a fresh QR code
  /// on a session that is still waiting.
  Future<NewCode> newCode(String sessionId);

  /// `POST /interpreter/sessions/join` — guest (B) joins by scanned code.
  Future<JoinedSession> join(String code, String lang);

  /// `GET /interpreter/sessions/:id` — status poll, used by both sides.
  Future<SessionView> get(String sessionId);

  /// `POST /interpreter/sessions/:id/end` — idempotent; either side may end.
  Future<void> end(String sessionId);
}
```

`lib/features/interpreter/data/interpreter_remote_datasource.dart` целиком:

```dart
import 'package:dio/dio.dart';

import '../../../core/api/api_error_handler.dart';
import '../../../core/api/dio_client.dart';
import '../domain/interpreter_error.dart';
import '../domain/interpreter_models.dart';

/// REST calls under `src/interpreter/*`. Every method rethrows as
/// [InterpreterException] so the repository and bloc never see a bare
/// [ApiException]/[DioException].
class InterpreterRemoteDataSource {
  final DioClient client;

  InterpreterRemoteDataSource(this.client);

  Future<InterpreterCatalog> catalog() async {
    try {
      return await client.get<InterpreterCatalog>(
        '/interpreter/languages',
        fromJson: (d) => InterpreterCatalog.fromJson(
          Map<String, dynamic>.from(d as Map),
        ),
      );
    } catch (e) {
      throw InterpreterException.from(e);
    }
  }

  Future<HostedSession> create(String lang) async {
    try {
      return await client.post<HostedSession>(
        '/interpreter/sessions',
        data: {'lang': lang},
        // A retry/failover on a receiveTimeout would risk a second QR
        // session opening for the same host if the first create() actually
        // reached the server.
        options: Options(extra: {kNoResendAfterTimeout: true}),
        fromJson: (d) => HostedSession.fromJson(
          Map<String, dynamic>.from(d as Map),
        ),
      );
    } catch (e) {
      throw InterpreterException.from(e);
    }
  }

  Future<NewCode> newCode(String sessionId) async {
    try {
      return await client.post<NewCode>(
        '/interpreter/sessions/$sessionId/code',
        fromJson: (d) => NewCode.fromJson(Map<String, dynamic>.from(d as Map)),
      );
    } catch (e) {
      throw InterpreterException.from(e);
    }
  }

  /// Goes through `client.dio` directly (not `DioClient.post`) because the
  /// backend waits for the agent to start up to 35s before answering — the
  /// shared client's 30s default `receiveTimeout` would time this call out
  /// on its own before the server gets a chance to.
  Future<JoinedSession> join(String code, String lang) async {
    try {
      final response = await client.dio.post(
        '/interpreter/sessions/join',
        data: {'code': code, 'lang': lang},
        // The single-use code may already be consumed and the host's
        // billing session already opened by the time a receiveTimeout
        // fires — a retry/failover would risk the server seeing this twice.
        options: Options(
          receiveTimeout: const Duration(seconds: 45),
          extra: {kNoResendAfterTimeout: true},
        ),
      );
      return JoinedSession.fromJson(
        Map<String, dynamic>.from(response.data as Map),
      );
    } on DioException catch (e) {
      throw InterpreterException.from(ApiErrorHandler.handle(e));
    } catch (e) {
      throw InterpreterException.from(e);
    }
  }

  Future<SessionView> get(String sessionId) async {
    try {
      return await client.get<SessionView>(
        '/interpreter/sessions/$sessionId',
        fromJson: (d) => SessionView.fromJson(
          Map<String, dynamic>.from(d as Map),
        ),
      );
    } catch (e) {
      throw InterpreterException.from(e);
    }
  }

  Future<void> end(String sessionId) async {
    try {
      await client.post<dynamic>('/interpreter/sessions/$sessionId/end');
    } catch (e) {
      throw InterpreterException.from(e);
    }
  }
}
```

`lib/features/interpreter/data/interpreter_repository_impl.dart` целиком:

```dart
import '../domain/interpreter_models.dart';
import '../domain/interpreter_repository.dart';
import 'interpreter_remote_datasource.dart';

class InterpreterRepositoryImpl implements InterpreterRepository {
  final InterpreterRemoteDataSource remote;

  InterpreterRepositoryImpl(this.remote);

  @override
  Future<InterpreterCatalog> catalog() => remote.catalog();

  @override
  Future<HostedSession> create(String lang) => remote.create(lang);

  @override
  Future<NewCode> newCode(String sessionId) => remote.newCode(sessionId);

  @override
  Future<JoinedSession> join(String code, String lang) =>
      remote.join(code, lang);

  @override
  Future<SessionView> get(String sessionId) => remote.get(sessionId);

  @override
  Future<void> end(String sessionId) => remote.end(sessionId);
}
```

`lib/features/interpreter/data/interpreter_lang_store.dart` целиком:

```dart
import '../../../core/storage/secure_storage_service.dart';
import '../domain/interpreter_models.dart';

/// Remembers the last language chosen on the start screen, on-device only —
/// nothing is written to the profile.
class InterpreterLangStore {
  static const _key = 'interpreter_lang';

  final SecureStorageService storage;

  InterpreterLangStore(this.storage);

  /// The language the start screen should preselect: the stored choice if
  /// the catalog still supports it, else the app's own locale if supported,
  /// else `'en'`.
  Future<String> initial(
      InterpreterCatalog catalog, String appLocaleCode) async {
    final supported = catalog.languages.map((l) => l.code).toSet();

    final stored = await storage.read(_key);
    if (stored != null && supported.contains(stored)) return stored;

    if (supported.contains(appLocaleCode)) return appLocaleCode;

    return 'en';
  }

  Future<void> remember(String code) => storage.write(_key, code);
}
```

`lib/features/interpreter/data/pending_interpreter_join.dart` целиком:

```dart
/// Carries a face-to-face interpreter join code across the login screen.
///
/// `talerid://interp/<code>` opened from the system camera while logged out
/// lands on `/login` (see `_globalRedirect` in `app_router.dart`) before the
/// code can be used — without this, the code is simply lost. Mirrors
/// `OAuthPendingRequest`, but in memory only: a cold start by link and the
/// login that follows it happen in the same process, so there is nothing to
/// persist across app restarts, unlike the OAuth consent flow (which can be
/// interrupted by a biometric prompt or backgrounding long enough to need
/// secure storage).
class PendingInterpreterJoin {
  /// The join code's own life, not an arbitrary pick — matches the 5-minute
  /// QR/code expiry on the backend.
  static const _ttl = Duration(minutes: 5);

  PendingInterpreterJoin({DateTime Function()? now})
      : _now = now ?? DateTime.now;

  final DateTime Function() _now;

  String? _code;
  DateTime? _savedAt;

  void save(String code) {
    _code = code;
    _savedAt = _now();
  }

  /// Returns the saved code if one is pending and still fresh, consuming it
  /// either way (one-shot, like `OAuthPendingRequest.consume`).
  String? consume() {
    final code = _code;
    final savedAt = _savedAt;
    _code = null;
    _savedAt = null;
    if (code == null || savedAt == null) return null;
    final age = _now().difference(savedAt);
    // Reject negative ages too — guards against a device clock corrected
    // backwards between save and consume, which would otherwise bypass TTL.
    if (age < Duration.zero || age >= _ttl) return null;
    return code;
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/data/interpreter_remote_datasource_test.dart test/features/interpreter/data/interpreter_lang_store_test.dart test/features/interpreter/data/pending_interpreter_join_test.dart lib/features/interpreter/domain/interpreter_repository.dart lib/features/interpreter/data/interpreter_remote_datasource.dart lib/features/interpreter/data/interpreter_repository_impl.dart lib/features/interpreter/data/interpreter_lang_store.dart lib/features/interpreter/data/pending_interpreter_join.dart
```

Ожидается: `+92: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/data/interpreter_remote_datasource_test.dart test/features/interpreter/data/interpreter_lang_store_test.dart test/features/interpreter/data/pending_interpreter_join_test.dart lib/features/interpreter/domain/interpreter_repository.dart lib/features/interpreter/data/interpreter_remote_datasource.dart lib/features/interpreter/data/interpreter_repository_impl.dart lib/features/interpreter/data/interpreter_lang_store.dart lib/features/interpreter/data/pending_interpreter_join.dart
git commit -m "feat(interpreter): источник данных, репозиторий и хранение языка" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Сигналы агента и строки субтитров

- Агент шлёт по данным (topic `interp`) субтитры, «кто говорит» и состояние перевода. Разбор не бросает исключений: кривое сообщение — просто `null`.
- Синхронный движок шлёт дельты, фразовый — фразы целиком (`final:true`). Новая строка начинается, если дельт не было 1,2 с: перевод отстаёт от речи на секунды, и по концу речи хвост перевода начал бы новую строку. По 20 строк на роль.

**Files:**
- Create: `test/features/interpreter/room/interpreter_signal_test.dart`, `test/features/interpreter/room/caption_lines_test.dart`, `lib/features/interpreter/room/interpreter_signal.dart`, `lib/features/interpreter/room/caption_lines.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/room/interpreter_signal_test.dart` целиком:

```dart
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_signal.dart';

List<int> _bytes(Object json) => utf8.encode(jsonEncode(json));

void main() {
  group('parse — caption', () {
    test('parses a translation delta', () {
      final signal = parse(_bytes({
        'type': 'caption',
        'role': 'translation',
        'speaker': 'user-1',
        'text': 'Hallo',
        'final': false,
      }));
      expect(signal, isA<CaptionSignal>());
      final caption = signal as CaptionSignal;
      expect(caption.role, CaptionRole.translation);
      expect(caption.speaker, 'user-1');
      expect(caption.text, 'Hallo');
      expect(caption.isFinal, isFalse);
    });

    test('parses a final source phrase', () {
      final signal = parse(_bytes({
        'type': 'caption',
        'role': 'source',
        'speaker': 'user-1',
        'text': 'Привет',
        'final': true,
      })) as CaptionSignal;
      expect(signal.role, CaptionRole.source);
      expect(signal.isFinal, isTrue);
    });

    test('unknown role returns null', () {
      expect(
        parse(_bytes({
          'type': 'caption',
          'role': 'nonsense',
          'speaker': 'user-1',
          'text': 'x',
          'final': false,
        })),
        isNull,
      );
    });

    test('missing field returns null', () {
      expect(
        parse(_bytes({
          'type': 'caption',
          'role': 'source',
          'speaker': 'user-1',
          'final': false,
        })),
        isNull,
      );
    });

    test('wrong field type returns null', () {
      expect(
        parse(_bytes({
          'type': 'caption',
          'role': 'source',
          'speaker': 'user-1',
          'text': 'x',
          'final': 'not-a-bool',
        })),
        isNull,
      );
    });
  });

  group('parse — speaking', () {
    test('parses on', () {
      final signal = parse(_bytes({
        'type': 'speaking',
        'speaker': 'user-1',
        'on': true,
      })) as SpeakingSignal;
      expect(signal.speaker, 'user-1');
      expect(signal.on, isTrue);
    });

    test('missing field returns null', () {
      expect(parse(_bytes({'type': 'speaking', 'speaker': 'user-1'})), isNull);
    });
  });

  group('parse — status', () {
    test('parses reconnecting', () {
      final signal = parse(_bytes({'type': 'status', 'state': 'reconnecting'}))
          as StatusSignal;
      expect(signal.state, StatusState.reconnecting);
    });

    test('parses ok', () {
      final signal =
          parse(_bytes({'type': 'status', 'state': 'ok'})) as StatusSignal;
      expect(signal.state, StatusState.ok);
    });

    test('parses failed', () {
      final signal =
          parse(_bytes({'type': 'status', 'state': 'failed'})) as StatusSignal;
      expect(signal.state, StatusState.failed);
    });

    test('unknown state returns null', () {
      expect(parse(_bytes({'type': 'status', 'state': 'confused'})), isNull);
    });
  });

  group('parse — never throws', () {
    test('unknown type returns null', () {
      expect(parse(_bytes({'type': 'something_else'})), isNull);
    });

    test('bad JSON returns null', () {
      expect(parse(utf8.encode('{not valid json')), isNull);
    });

    test('non-UTF8 bytes return null', () {
      // 0xFF is not a valid start byte in UTF-8.
      expect(parse(const [0xFF, 0xFE, 0x00, 0x01]), isNull);
    });

    test('a JSON value that is not an object returns null', () {
      expect(parse(_bytes([1, 2, 3])), isNull);
    });

    test('empty bytes return null', () {
      expect(parse(const []), isNull);
    });
  });
}
```

`test/features/interpreter/room/caption_lines_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/room/caption_lines.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_signal.dart';

CaptionSignal _delta(CaptionRole role, String text, {String speaker = 's'}) =>
    CaptionSignal(role: role, speaker: speaker, text: text, isFinal: false);

CaptionSignal _final(CaptionRole role, String text, {String speaker = 's'}) =>
    CaptionSignal(role: role, speaker: speaker, text: text, isFinal: true);

void main() {
  final t0 = DateTime.utc(2026, 11, 1, 12, 0, 0);

  group('deltas', () {
    test('consecutive deltas within the gap join into one open line', () {
      final lines = CaptionLines();
      lines.add(_delta(CaptionRole.translation, 'Hal'), t0);
      lines.add(_delta(CaptionRole.translation, 'lo'),
          t0.add(const Duration(milliseconds: 500)));

      final result = lines.linesFor(CaptionRole.translation);
      expect(result, hasLength(1));
      expect(result.single.text, 'Hallo');
      expect(result.single.isFinal, isFalse);
    });

    test('a gap over 1.2s starts a new line', () {
      final lines = CaptionLines();
      lines.add(_delta(CaptionRole.translation, 'A'), t0);
      lines.add(_delta(CaptionRole.translation, 'B'),
          t0.add(const Duration(milliseconds: 1201)));

      final result = lines.linesFor(CaptionRole.translation);
      expect(result, hasLength(2));
      expect(result[0].text, 'A');
      expect(result[1].text, 'B');
    });

    test(
        'exactly at the gap boundary still joins (strictly greater-than splits)',
        () {
      final lines = CaptionLines();
      lines.add(_delta(CaptionRole.translation, 'A'), t0);
      lines.add(_delta(CaptionRole.translation, 'B'),
          t0.add(const Duration(milliseconds: 1200)));

      final result = lines.linesFor(CaptionRole.translation);
      expect(result, hasLength(1));
      expect(result.single.text, 'AB');
    });
  });

  group('final phrases', () {
    test('final:true is always its own line, not merged with an open delta',
        () {
      final lines = CaptionLines();
      lines.add(_delta(CaptionRole.source, 'partial'), t0);
      lines.add(_final(CaptionRole.source, 'full phrase'),
          t0.add(const Duration(milliseconds: 100)));

      final result = lines.linesFor(CaptionRole.source);
      expect(result, hasLength(2));
      expect(result[0].text, 'partial');
      expect(result[0].isFinal, isFalse);
      expect(result[1].text, 'full phrase');
      expect(result[1].isFinal, isTrue);
    });

    test(
        'a delta after a final always starts fresh, even within the gap window',
        () {
      final lines = CaptionLines();
      lines.add(_final(CaptionRole.source, 'done.'), t0);
      lines.add(_delta(CaptionRole.source, 'next'),
          t0.add(const Duration(milliseconds: 10)));

      final result = lines.linesFor(CaptionRole.source);
      expect(result, hasLength(2));
      expect(result[1].text, 'next');
      expect(result[1].isFinal, isFalse);
    });
  });

  group('cap at 20 lines per role', () {
    test('keeps only the most recent 20, newest last', () {
      final lines = CaptionLines();
      for (var i = 0; i < 25; i++) {
        lines.add(
            _final(CaptionRole.source, 'line$i'), t0.add(Duration(seconds: i)));
      }

      final result = lines.linesFor(CaptionRole.source);
      expect(result, hasLength(20));
      expect(result.first.text, 'line5');
      expect(result.last.text, 'line24');
    });
  });

  group('roles are independent', () {
    test('source and translation lines never mix', () {
      final lines = CaptionLines();
      lines.add(_delta(CaptionRole.source, 'rus'), t0);
      lines.add(_delta(CaptionRole.translation, 'deu'), t0);
      lines.add(_delta(CaptionRole.source, 'skiy'),
          t0.add(const Duration(milliseconds: 100)));

      expect(lines.linesFor(CaptionRole.source).single.text, 'russkiy');
      expect(lines.linesFor(CaptionRole.translation).single.text, 'deu');
    });

    test('a gap in one role does not affect the other', () {
      final lines = CaptionLines();
      lines.add(_delta(CaptionRole.source, 'A'), t0);
      lines.add(_delta(CaptionRole.translation, 'X'),
          t0.add(const Duration(seconds: 5)));
      lines.add(
          _delta(CaptionRole.source, 'B'), t0.add(const Duration(seconds: 5)));

      // source had a 5s gap -> 2 lines; translation's only delta -> 1 line.
      expect(lines.linesFor(CaptionRole.source), hasLength(2));
      expect(lines.linesFor(CaptionRole.translation), hasLength(1));
    });
  });

  test('linesFor returns an empty list for a role with no signals yet', () {
    final lines = CaptionLines();
    expect(lines.linesFor(CaptionRole.source), isEmpty);
  });
}
```

Run: `flutter test test/features/interpreter/room/interpreter_signal_test.dart test/features/interpreter/room/caption_lines_test.dart`
Expected: `test/features/interpreter/room/caption_lines_test.dart` — не запускается (нет ещё кода, который он импортирует); `test/features/interpreter/room/interpreter_signal_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 2.

- [ ] **Step 2: Код**

`lib/features/interpreter/room/interpreter_signal.dart` целиком:

```dart
import 'dart:convert';

import 'package:equatable/equatable.dart';

/// A parsed message from the `interp` reliable data topic the agent
/// publishes. `parse` never throws — a room full of unrelated data packets
/// (or a future signal shape) should degrade to "ignored", not crash the
/// call.
sealed class InterpreterSignal extends Equatable {
  const InterpreterSignal();
}

/// Which side of the conversation a [CaptionSignal] reports: `source` is how
/// the speaker's own speech was recognised, `translation` is what the other
/// side hears.
enum CaptionRole { source, translation }

class CaptionSignal extends InterpreterSignal {
  final CaptionRole role;
  final String speaker;
  final String text;
  final bool isFinal;

  const CaptionSignal({
    required this.role,
    required this.speaker,
    required this.text,
    required this.isFinal,
  });

  @override
  List<Object?> get props => [role, speaker, text, isFinal];
}

class SpeakingSignal extends InterpreterSignal {
  final String speaker;
  final bool on;

  const SpeakingSignal({required this.speaker, required this.on});

  @override
  List<Object?> get props => [speaker, on];
}

enum StatusState { reconnecting, ok, failed }

class StatusSignal extends InterpreterSignal {
  final StatusState state;

  const StatusSignal(this.state);

  @override
  List<Object?> get props => [state];
}

CaptionRole? _roleFromJson(Object? raw) => switch (raw) {
      'source' => CaptionRole.source,
      'translation' => CaptionRole.translation,
      _ => null,
    };

StatusState? _stateFromJson(Object? raw) => switch (raw) {
      'reconnecting' => StatusState.reconnecting,
      'ok' => StatusState.ok,
      'failed' => StatusState.failed,
      _ => null,
    };

/// Parses one `interp`-topic data packet. Returns `null` on malformed UTF-8,
/// invalid JSON, an unknown `type`, or any field of the wrong shape —
/// callers treat all of those the same way: ignore the packet.
InterpreterSignal? parse(List<int> bytes) {
  try {
    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map) return null;

    switch (decoded['type']) {
      case 'caption':
        final role = _roleFromJson(decoded['role']);
        final speaker = decoded['speaker'];
        final text = decoded['text'];
        final isFinal = decoded['final'];
        if (role == null ||
            speaker is! String ||
            text is! String ||
            isFinal is! bool) {
          return null;
        }
        return CaptionSignal(
          role: role,
          speaker: speaker,
          text: text,
          isFinal: isFinal,
        );

      case 'speaking':
        final speaker = decoded['speaker'];
        final on = decoded['on'];
        if (speaker is! String || on is! bool) return null;
        return SpeakingSignal(speaker: speaker, on: on);

      case 'status':
        final state = _stateFromJson(decoded['state']);
        if (state == null) return null;
        return StatusSignal(state);

      default:
        return null;
    }
  } catch (_) {
    return null;
  }
}
```

`lib/features/interpreter/room/caption_lines.dart` целиком:

```dart
import 'interpreter_signal.dart';

/// One subtitle line. Delta lines (simultaneous engine) stay `isFinal: false`
/// while more text keeps arriving for them; phrase lines (phrase engine)
/// are always `isFinal: true` and never grow.
class CaptionLine {
  final String text;
  final CaptionRole role;
  final bool isFinal;

  const CaptionLine({
    required this.text,
    required this.role,
    required this.isFinal,
  });
}

/// Pure assembly of caption subtitles from the agent's `caption` signals,
/// kept separately per [CaptionRole] since `source` (own speech) and
/// `translation` (partner's speech) run independently and can overlap.
///
/// Time is injected rather than read from the wall clock so the gap rule is
/// deterministic in tests.
class CaptionLines {
  static const _gap = Duration(milliseconds: 1200);
  static const _maxPerRole = 20;

  final Map<CaptionRole, List<CaptionLine>> _lines = {
    for (final role in CaptionRole.values) role: <CaptionLine>[],
  };
  final Map<CaptionRole, DateTime> _lastDeltaAt = {};

  /// Newest last, at most the last 20 lines for [role].
  List<CaptionLine> linesFor(CaptionRole role) =>
      List.unmodifiable(_lines[role]!);

  void add(CaptionSignal signal, DateTime now) {
    final role = signal.role;
    final list = _lines[role]!;

    if (signal.isFinal) {
      // The phrase engine hands over a whole utterance at once; it never
      // merges with whatever delta line happened to be open for this role.
      list.add(CaptionLine(text: signal.text, role: role, isFinal: true));
      _lastDeltaAt.remove(role);
      _trim(list);
      return;
    }

    final last = _lastDeltaAt[role];
    final gapped = last == null || now.difference(last) > _gap || list.isEmpty;
    if (gapped) {
      list.add(CaptionLine(text: signal.text, role: role, isFinal: false));
    } else {
      // Still inside the 1.2s window since the last delta of this role —
      // append to the open line rather than starting a new one.
      list[list.length - 1] = CaptionLine(
        text: list.last.text + signal.text,
        role: role,
        isFinal: false,
      );
    }
    _lastDeltaAt[role] = now;
    _trim(list);
  }

  void _trim(List<CaptionLine> list) {
    while (list.length > _maxPerRole) {
      list.removeAt(0);
    }
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/room/interpreter_signal_test.dart test/features/interpreter/room/caption_lines_test.dart lib/features/interpreter/room/interpreter_signal.dart lib/features/interpreter/room/caption_lines.dart
```

Ожидается: `+117: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/room/interpreter_signal_test.dart test/features/interpreter/room/caption_lines_test.dart lib/features/interpreter/room/interpreter_signal.dart lib/features/interpreter/room/caption_lines.dart
git commit -m "feat(interpreter): разбор сигналов агента и строки субтитров" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Контроллер комнаты

- Логика комнаты отдельно от LiveKit (порт `InterpreterRoomPort`), чтобы её можно было проверить без настоящей комнаты.
- Права на микрофон — только агенту, и выставлены до публикации микрофона. Подписка — только на `interp-for-<я>` от `voice-interpreter`: живой микрофон собеседника и его дорожка перевода игнорируются, в том числе после переподключения.
- Что уже было в комнате к подключению (гость приходит всегда после агента), разбирается сразу после подписки на события.
- При полном переподключении livekit_client 2.4.1 публикует микрофон заново раньше, чем мы снова ограничим права, — поэтому на время переподключения микрофон глушится и включается обратно только после `restrictMicTo`.

**Files:**
- Create: `test/features/interpreter/fakes.dart`, `test/features/interpreter/room/interpreter_room_controller_test.dart`, `lib/features/interpreter/room/interpreter_room_port.dart`, `lib/features/interpreter/room/interpreter_room_controller.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/fakes.dart` целиком:

```dart
import 'dart:async';

import 'package:taler_id_mobile/features/interpreter/room/interpreter_room_port.dart';

/// Hand-written fake instead of mocktail: the controller's behaviour is a
/// sequence of reactions to a stream of events plus the order of a few
/// calls, which reads far more plainly as a recorded call log + a stream
/// controller than as a pile of `verify`/`verifyInOrder`.
///
/// Shared between the room controller's own tests and the bloc's: the bloc
/// wraps a real `InterpreterRoomController` around this fake rather than
/// mocking the controller itself, so the controller's subscription/mic
/// ordering rules stay exercised end-to-end in bloc tests too.
class FakeRoomPort implements InterpreterRoomPort {
  FakeRoomPort({this.identity = 'me-user#aaaaaaaa', this.connectGate});

  final String identity;

  /// When set, [connect] records its call and then waits on this completer
  /// before returning — lets a test hold a room "connecting" indefinitely to
  /// exercise what happens if the bloc is closed while that is in flight.
  final Completer<void>? connectGate;

  final _events = StreamController<RoomPortEvent>.broadcast();

  final List<String> calls = [];
  final List<RoomTrackRef> subscribed = [];
  bool disconnected = false;
  List<String> present = [];
  List<RoomTrackRef> tracks = [];

  @override
  List<String> get remoteIdentities => present;

  @override
  List<RoomTrackRef> get remoteTracks => tracks;

  void emit(RoomPortEvent event) => _events.add(event);

  @override
  String get localIdentity => identity;

  @override
  Stream<RoomPortEvent> get events => _events.stream;

  @override
  Future<void> connect(String url, String token) async {
    calls.add('connect($url, $token)');
    final gate = connectGate;
    if (gate != null) await gate.future;
  }

  @override
  void restrictMicTo(String agentIdentity) {
    calls.add('restrictMicTo($agentIdentity)');
  }

  @override
  Future<void> setMicrophone(bool on) async {
    calls.add('setMicrophone($on)');
  }

  @override
  Future<void> subscribe(RoomTrackRef track) async {
    calls.add('subscribe(${track.trackName})');
    subscribed.add(track);
  }

  @override
  Future<void> disconnect() async {
    disconnected = true;
    calls.add('disconnect()');
  }

  Future<void> close() => _events.close();
}
```

`test/features/interpreter/room/interpreter_room_controller_test.dart` целиком:

```dart
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_room_controller.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_room_port.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_signal.dart';

import '../fakes.dart';

void main() {
  late FakeRoomPort port;
  late InterpreterRoomController controller;

  setUp(() {
    port = FakeRoomPort();
    controller = InterpreterRoomController(port);
  });

  tearDown(() async {
    await port.close();
  });

  group('start', () {
    test('restricts the mic to the agent before publishing it', () async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);

      expect(port.calls, [
        'connect(wss://lk, tok)',
        'restrictMicTo(voice-interpreter)',
        'setMicrophone(true)',
      ]);
    });

    test('still restricts before publishing when starting muted', () async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: false);

      expect(port.calls, [
        'connect(wss://lk, tok)',
        'restrictMicTo(voice-interpreter)',
        'setMicrophone(false)',
      ]);
    });
  });

  group('what was in the room before me', () {
    const myTrack = RoomTrackRef(
      participantIdentity: 'voice-interpreter',
      trackName: 'interp-for-me-user',
      trackSid: 'TR_MINE',
    );

    test('subscribes to my track the agent published before I connected',
        () async {
      // The guest always joins after the agent: its track is already there.
      port.present = ['voice-interpreter', 'host-user#bbbbbbbb'];
      port.tracks = [
        myTrack,
        const RoomTrackRef(
          participantIdentity: 'voice-interpreter',
          trackName: 'interp-for-host-user',
          trackSid: 'TR_HOST',
        ),
      ];
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
      await pumpEventQueue();

      expect(port.subscribed, [myTrack]);
      expect(updates, [
        const AgentJoined(),
        const PartnerJoined('host-user#bbbbbbbb'),
      ]);
      expect(controller.agentPresent, isTrue);
    });

    test('subscribes again to my track after a reconnect', () async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
      port.tracks = [myTrack];

      port.emit(const Reconnected());
      await pumpEventQueue();

      expect(port.subscribed, [myTrack]);
    });
  });

  group('track subscription', () {
    setUp(() async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
    });

    test('subscribes to my own interp-for track published by the agent',
        () async {
      const track = RoomTrackRef(
        participantIdentity: 'voice-interpreter',
        trackName: 'interp-for-me-user',
        trackSid: 'TR_1',
      );
      port.emit(TrackPublished(track));
      await pumpEventQueue();

      expect(port.subscribed, [track]);
    });

    test('ignores the partner\'s own mic track', () async {
      const track = RoomTrackRef(
        participantIdentity: 'partner-user#bbbbbbbb',
        trackName: 'microphone',
        trackSid: 'TR_2',
      );
      port.emit(TrackPublished(track));
      await pumpEventQueue();

      expect(port.subscribed, isEmpty);
    });

    test('ignores the other listener\'s interp-for track from the agent',
        () async {
      const track = RoomTrackRef(
        participantIdentity: 'voice-interpreter',
        trackName: 'interp-for-partner-user',
        trackSid: 'TR_3',
      );
      port.emit(TrackPublished(track));
      await pumpEventQueue();

      expect(port.subscribed, isEmpty);
    });

    test('ignores a track with the right name from a non-agent identity',
        () async {
      const track = RoomTrackRef(
        participantIdentity: 'partner-user#bbbbbbbb',
        trackName: 'interp-for-me-user',
        trackSid: 'TR_4',
      );
      port.emit(TrackPublished(track));
      await pumpEventQueue();

      expect(port.subscribed, isEmpty);
    });
  });

  group('participants', () {
    setUp(() async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
    });

    test('a different base identity joining is the partner', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const ParticipantJoined('partner-user#bbbbbbbb'));
      await pumpEventQueue();

      expect(updates, [const PartnerJoined('partner-user#bbbbbbbb')]);
    });

    test('my own other device joining is NOT reported as a partner', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const ParticipantJoined('me-user#cccccccc'));
      await pumpEventQueue();

      expect(updates, isEmpty);
    });

    test('the agent joining/leaving is reported distinctly, not as a partner',
        () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const ParticipantJoined('voice-interpreter'));
      port.emit(const ParticipantLeft('voice-interpreter'));
      await pumpEventQueue();

      expect(updates, [const AgentJoined(), const AgentLeft()]);
      expect(controller.agentPresent, isFalse);
    });

    test('a partner leaving is reported', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const ParticipantLeft('partner-user#bbbbbbbb'));
      await pumpEventQueue();

      expect(updates, [const PartnerLeft('partner-user#bbbbbbbb')]);
    });
  });

  group('data signals', () {
    setUp(() async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
    });

    test('parses interp-topic data from the agent', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(DataReceived(
        topic: 'interp',
        bytes: parseToBytes({
          'type': 'speaking',
          'speaker': 'partner-user',
          'on': true,
        }),
        fromIdentity: 'voice-interpreter',
      ));
      await pumpEventQueue();

      expect(updates, hasLength(1));
      final signal = (updates.single as Signal).signal;
      expect(signal, isA<SpeakingSignal>());
    });

    test('ignores interp-topic data from the partner, not just the agent',
        () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(DataReceived(
        topic: 'interp',
        bytes: parseToBytes({
          'type': 'speaking',
          'speaker': 'partner-user',
          'on': true,
        }),
        fromIdentity: 'partner-user#bbbbbbbb',
      ));
      await pumpEventQueue();

      expect(updates, isEmpty);
    });

    test('ignores data on other topics even from the agent', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(DataReceived(
        topic: 'chat',
        bytes: parseToBytes({
          'type': 'speaking',
          'speaker': 'partner-user',
          'on': true,
        }),
        fromIdentity: 'voice-interpreter',
      ));
      await pumpEventQueue();

      expect(updates, isEmpty);
    });

    test('a signal that fails to parse produces no update', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(DataReceived(
        topic: 'interp',
        bytes: const [0xFF, 0xFE],
        fromIdentity: 'voice-interpreter',
      ));
      await pumpEventQueue();

      expect(updates, isEmpty);
    });
  });

  group('reconnects', () {
    setUp(() async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
      port.calls.clear();
    });

    test('reconnecting is reported', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const Reconnecting());
      await pumpEventQueue();

      expect(
          updates, [const Connection(InterpreterConnectionState.reconnecting)]);
    });

    test(
        'reconnected re-applies the mic restriction and restores the mic '
        'state, and is reported as ok', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const Reconnected());
      await pumpEventQueue();

      expect(port.calls,
          ['restrictMicTo(voice-interpreter)', 'setMicrophone(true)']);
      expect(updates, [const Connection(InterpreterConnectionState.ok)]);
    });

    test('reconnecting mutes the mic; reconnected restores it in order',
        () async {
      port.emit(const Reconnecting());
      await pumpEventQueue();
      expect(port.calls, ['setMicrophone(false)']);

      port.calls.clear();
      port.emit(const Reconnected());
      await pumpEventQueue();
      expect(port.calls,
          ['restrictMicTo(voice-interpreter)', 'setMicrophone(true)']);
    });

    test('a mic muted by the user before the reconnect stays muted after it',
        () async {
      await controller.setMic(false);
      port.calls.clear();

      port.emit(const Reconnecting());
      await pumpEventQueue();
      expect(port.calls, ['setMicrophone(false)']);

      port.calls.clear();
      port.emit(const Reconnected());
      await pumpEventQueue();
      // Restored to the remembered (muted) state, not force-unmuted.
      expect(port.calls,
          ['restrictMicTo(voice-interpreter)', 'setMicrophone(false)']);
    });

    test(
        'setMic during a reconnect only remembers the new state; it is '
        'applied once reconnected', () async {
      port.emit(const Reconnecting());
      await pumpEventQueue();
      port.calls.clear();

      // Started on, the gap muted it; the user taps to turn it back on
      // while still mid-reconnect.
      await controller.setMic(true);
      expect(port.calls, isEmpty);

      port.emit(const Reconnected());
      await pumpEventQueue();
      expect(port.calls,
          ['restrictMicTo(voice-interpreter)', 'setMicrophone(true)']);
    });
  });

  group('disconnect', () {
    setUp(() async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);
    });

    test('disconnected is reported as closed', () async {
      final updates = <RoomUpdate>[];
      controller.updates.listen(updates.add);

      port.emit(const Disconnected());
      await pumpEventQueue();

      expect(updates, [const Closed()]);
    });
  });

  group('dispose', () {
    test('disconnects the port and closes the update stream', () async {
      await controller.start(url: 'wss://lk', token: 'tok', micOn: true);

      var done = false;
      controller.updates.listen(null, onDone: () => done = true);

      await controller.dispose();
      await pumpEventQueue();

      expect(port.disconnected, isTrue);
      expect(done, isTrue);
    });
  });
}

/// Test-only helper so signal payloads can be built as plain maps instead of
/// hand-encoded byte literals.
List<int> parseToBytes(Map<String, Object?> json) =>
    utf8.encode(jsonEncode(json));
```

Run: `flutter test test/features/interpreter/room/interpreter_room_controller_test.dart`
Expected: `test/features/interpreter/room/interpreter_room_controller_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/room/interpreter_room_port.dart` целиком:

```dart
import 'package:equatable/equatable.dart';

/// Identifies one published LiveKit track, enough for the controller to
/// decide whether to subscribe to it and for the port to act on that
/// decision.
class RoomTrackRef extends Equatable {
  final String participantIdentity;
  final String trackName;
  final String trackSid;

  const RoomTrackRef({
    required this.participantIdentity,
    required this.trackName,
    required this.trackSid,
  });

  @override
  List<Object?> get props => [participantIdentity, trackName, trackSid];
}

/// Everything the room can tell [InterpreterRoomController] about, in LiveKit
/// vocabulary but without a LiveKit import — that is what keeps the
/// controller unit-testable against a hand-written fake.
sealed class RoomPortEvent extends Equatable {
  const RoomPortEvent();
}

class ParticipantJoined extends RoomPortEvent {
  final String identity;
  const ParticipantJoined(this.identity);
  @override
  List<Object?> get props => [identity];
}

class ParticipantLeft extends RoomPortEvent {
  final String identity;
  const ParticipantLeft(this.identity);
  @override
  List<Object?> get props => [identity];
}

class TrackPublished extends RoomPortEvent {
  final RoomTrackRef track;
  const TrackPublished(this.track);
  @override
  List<Object?> get props => [track];
}

class DataReceived extends RoomPortEvent {
  final String topic;
  final List<int> bytes;
  final String fromIdentity;
  const DataReceived({
    required this.topic,
    required this.bytes,
    required this.fromIdentity,
  });
  @override
  List<Object?> get props => [topic, bytes, fromIdentity];
}

class Reconnecting extends RoomPortEvent {
  const Reconnecting();
  @override
  List<Object?> get props => const [];
}

class Reconnected extends RoomPortEvent {
  const Reconnected();
  @override
  List<Object?> get props => const [];
}

class Disconnected extends RoomPortEvent {
  const Disconnected();
  @override
  List<Object?> get props => const [];
}

/// Thin seam over `livekit_client`'s `Room` so [InterpreterRoomController]'s
/// logic (subscription filtering, mic ordering, partner/agent detection) is
/// testable without a real room. The production implementation adapts
/// `livekit_client` to this port and is exercised manually, not unit-tested.
abstract class InterpreterRoomPort {
  Future<void> connect(String url, String token);

  /// `<userId>#<8 hex>` of the local participant, valid only after [connect].
  String get localIdentity;

  /// Who and what was already in the room when [connect] returned. [events]
  /// only reports later changes, and the guest always arrives after the agent
  /// has published its tracks.
  List<String> get remoteIdentities;
  List<RoomTrackRef> get remoteTracks;

  /// Restricts which other participants may subscribe to the local mic to
  /// just [agentIdentity] — must be called before [setMicrophone] publishes
  /// the track, otherwise there is a window where the partner's device could
  /// subscribe to raw, untranslated audio.
  void restrictMicTo(String agentIdentity);

  Future<void> setMicrophone(bool on);

  Future<void> subscribe(RoomTrackRef track);

  Future<void> disconnect();

  Stream<RoomPortEvent> get events;
}
```

`lib/features/interpreter/room/interpreter_room_controller.dart` целиком:

```dart
import 'dart:async';

import 'package:equatable/equatable.dart';

import 'interpreter_room_port.dart';
import 'interpreter_signal.dart' as sig;

/// Identity of the translation agent in every interpreter room (spec:
/// "the agent is `voice-interpreter`").
const agentIdentity = 'voice-interpreter';

/// Connection health as the controller reports it upward; distinct from
/// Flutter's own `ConnectionState` to avoid a confusing shadowed import at
/// call sites.
enum InterpreterConnectionState { reconnecting, ok }

/// What [InterpreterRoomController] reports to the screen/bloc.
sealed class RoomUpdate extends Equatable {
  const RoomUpdate();
}

class PartnerJoined extends RoomUpdate {
  final String identity;
  const PartnerJoined(this.identity);
  @override
  List<Object?> get props => [identity];
}

class PartnerLeft extends RoomUpdate {
  final String identity;
  const PartnerLeft(this.identity);
  @override
  List<Object?> get props => [identity];
}

class AgentJoined extends RoomUpdate {
  const AgentJoined();
  @override
  List<Object?> get props => const [];
}

class AgentLeft extends RoomUpdate {
  const AgentLeft();
  @override
  List<Object?> get props => const [];
}

class Signal extends RoomUpdate {
  final sig.InterpreterSignal signal;
  const Signal(this.signal);
  @override
  List<Object?> get props => [signal];
}

class Connection extends RoomUpdate {
  final InterpreterConnectionState state;
  const Connection(this.state);
  @override
  List<Object?> get props => [state];
}

class Closed extends RoomUpdate {
  const Closed();
  @override
  List<Object?> get props => const [];
}

/// Owns one interpreter LiveKit room for the lifetime of a call. Translates
/// raw [RoomPortEvent]s from [InterpreterRoomPort] into the [RoomUpdate]s the
/// screen/bloc understand, applying the spec's subscription and mic rules:
///
/// - mic access is restricted to the agent *before* the mic track is
///   published, so there is never a window where the partner's device could
///   subscribe to raw, untranslated audio;
/// - the only track ever subscribed to is the one named
///   `interp-for-<my base identity>`, and only when published by the agent —
///   the partner's own mic track and the other listener's `interp-for-*`
///   track are both ignored, including after a reconnect re-announces them.
class InterpreterRoomController {
  final InterpreterRoomPort _port;

  final _updates = StreamController<RoomUpdate>.broadcast();
  StreamSubscription<RoomPortEvent>? _sub;
  String _myBase = '';
  String _myTrackName = '';
  bool _agentPresent = false;

  /// Mic state as last set through [start]/[setMic] — independent of
  /// whatever the mic is actually doing mid-reconnect (see [Reconnecting]).
  bool _micOn = false;
  bool _reconnecting = false;

  InterpreterRoomController(this._port);

  Stream<RoomUpdate> get updates => _updates.stream;
  bool get agentPresent => _agentPresent;

  /// Base identity (`<userId>`, without the `#<device>` suffix) of the local
  /// participant, valid only after [start]. Callers that need to tell "is
  /// this me?" from a signal's bare `speaker` userId — which is exactly the
  /// shape the agent's `interp`-topic data uses — compare against this
  /// rather than against [InterpreterRoomPort.localIdentity] directly.
  String get myBaseIdentity => _myBase;

  static String baseOf(String identity) {
    final i = identity.indexOf('#');
    return i == -1 ? identity : identity.substring(0, i);
  }

  Future<void> start({
    required String url,
    required String token,
    required bool micOn,
  }) async {
    await _port.connect(url, token);
    _myBase = baseOf(_port.localIdentity);
    _myTrackName = 'interp-for-$_myBase';
    _micOn = micOn;

    // Order matters: permissions must be in place before the mic track is
    // published, otherwise the partner's device has a window to subscribe to
    // the raw (untranslated) track.
    _port.restrictMicTo(agentIdentity);
    await _port.setMicrophone(micOn);

    // Listen first, then go through what is already there: an event may be
    // reported twice, but nothing falls between the two.
    _sub = _port.events.listen(_onEvent);
    for (final id in _port.remoteIdentities) {
      _onEvent(ParticipantJoined(id));
    }
    _subscribePresentTracks();
  }

  void _subscribePresentTracks() {
    for (final track in _port.remoteTracks) {
      _onEvent(TrackPublished(track));
    }
  }

  /// While a full reconnect is in progress the mic is force-muted (see
  /// [Reconnecting]) and must stay that way regardless of what the user
  /// taps — only the remembered state changes, to be applied once
  /// [Reconnected] restores it.
  Future<void> setMic(bool on) {
    _micOn = on;
    if (_reconnecting) return Future.value();
    return _port.setMicrophone(on);
  }

  void _onEvent(RoomPortEvent event) {
    switch (event) {
      case ParticipantJoined(identity: final id):
        if (id == agentIdentity) {
          _agentPresent = true;
          _updates.add(const AgentJoined());
        } else if (baseOf(id) != _myBase) {
          _updates.add(PartnerJoined(id));
        }
      case ParticipantLeft(identity: final id):
        if (id == agentIdentity) {
          _agentPresent = false;
          _updates.add(const AgentLeft());
        } else if (baseOf(id) != _myBase) {
          _updates.add(PartnerLeft(id));
        }
      case TrackPublished(track: final track):
        if (track.participantIdentity == agentIdentity &&
            track.trackName == _myTrackName) {
          _port.subscribe(track);
        }
      case DataReceived(
          topic: final topic,
          bytes: final bytes,
          fromIdentity: final from
        ):
        if (topic == 'interp' && from == agentIdentity) {
          final parsed = sig.parse(bytes);
          if (parsed != null) _updates.add(Signal(parsed));
        }
      case Reconnecting():
        // livekit_client republishes the mic on a full restart BEFORE
        // reporting Reconnected, i.e. before restrictMicTo can be
        // re-applied below — muting here closes that window instead of
        // leaving the raw mic briefly subscribable by the partner.
        _reconnecting = true;
        _port.setMicrophone(false).catchError((_) {});
        _updates.add(const Connection(InterpreterConnectionState.reconnecting));
      case Reconnected():
        _reconnecting = false;
        // LiveKit re-announces existing tracks/participants after a
        // reconnect but does not remember per-track subscription
        // permissions, so the restriction has to be re-applied — before the
        // mic is unmuted again, for the same reason it came first in start().
        _port.restrictMicTo(agentIdentity);
        _port.setMicrophone(_micOn).catchError((_) {});
        _subscribePresentTracks();
        _updates.add(const Connection(InterpreterConnectionState.ok));
      case Disconnected():
        _updates.add(const Closed());
    }
  }

  Future<void> dispose() async {
    await _sub?.cancel();
    await _port.disconnect();
    await _updates.close();
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/fakes.dart test/features/interpreter/room/interpreter_room_controller_test.dart lib/features/interpreter/room/interpreter_room_port.dart lib/features/interpreter/room/interpreter_room_controller.dart
```

Ожидается: `+140: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/fakes.dart test/features/interpreter/room/interpreter_room_controller_test.dart lib/features/interpreter/room/interpreter_room_port.dart lib/features/interpreter/room/interpreter_room_controller.dart
git commit -m "feat(interpreter): контроллер комнаты — микрофон только агенту, подписка только на свой перевод" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: LiveKit-адаптер и адрес комнаты

- Тонкий адаптер `livekit_client` к порту; без модульных тестов (поддельной комнаты LiveKit нет), проверяется вручную.
- Адрес комнаты — как у звонков: медиа-адрес приложения (`EndpointService.mediaBaseUrl` + `/livekit/`), а не `LIVEKIT_WS_URL` сервера: из сетей СНГ тот недоступен, а RU-edge проксирует `/livekit/`. На резервном edge — только relay, как у звонков. Без E2EE: перевод делает сервер.

**Files:**
- Create: `test/features/interpreter/room/livekit_url_test.dart`, `lib/features/interpreter/room/livekit_interpreter_room.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/room/livekit_url_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/core/api/endpoint_service.dart';
import 'package:taler_id_mobile/features/interpreter/room/livekit_interpreter_room.dart';

void main() {
  test('the room is reached through the media endpoint, as calls do', () {
    final endpoints = EndpointService(
      candidates: ['https://api.talerid.io', 'https://ru.talerid.io'],
      mediaCapable: ['https://api.talerid.io', 'https://ru.talerid.io'],
    );
    expect(interpreterLivekitUrl(endpoints), 'wss://api.talerid.io/livekit/');

    // On the CIS edge the room goes through the edge as well.
    endpoints.activeUrl.value = 'https://ru.talerid.io';
    expect(interpreterLivekitUrl(endpoints), 'wss://ru.talerid.io/livekit/');
  });
}
```

Run: `flutter test test/features/interpreter/room/livekit_url_test.dart`
Expected: `test/features/interpreter/room/livekit_url_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/room/livekit_interpreter_room.dart` целиком:

```dart
import 'dart:async';

import 'package:livekit_client/livekit_client.dart' as lk;

import '../../../core/api/endpoint_service.dart';
import '../../../core/di/service_locator.dart';
import 'interpreter_room_port.dart';

/// Thin adapter of `livekit_client`'s [lk.Room] to [InterpreterRoomPort]. Not
/// unit-tested (no fake LiveKit room exists) — exercised manually, and kept
/// deliberately thin so there is little logic left to get wrong here; the
/// subscription/mic-ordering rules live in `InterpreterRoomController`.
class LiveKitInterpreterRoom implements InterpreterRoomPort {
  LiveKitInterpreterRoom({EndpointService? endpointService})
      : _endpointService = endpointService ?? sl<EndpointService>();

  final EndpointService _endpointService;

  lk.Room? _room;
  lk.EventsListener<lk.RoomEvent>? _listener;
  final _events = StreamController<RoomPortEvent>.broadcast();

  @override
  Stream<RoomPortEvent> get events => _events.stream;

  @override
  Future<void> connect(String url, String token) async {
    final room = lk.Room(
      roomOptions: const lk.RoomOptions(
        defaultAudioPublishOptions: lk.AudioPublishOptions(audioBitrate: 32000),
      ),
    );
    _room = room;
    _listener = room.createListener();
    _attachListeners(_listener!);

    // Same CIS fallback-edge check voice_call_screen.dart uses for calls: a
    // direct UDP path to the RU SFU from a non-primary edge dies in ~7s, so
    // force the TURN/TLS relay when the active endpoint is one. No E2EE here
    // — the server has to be able to read the audio to translate it.
    final onEdge = _endpointService.hasFallback &&
        _endpointService.mediaBaseUrl != _endpointService.candidates.first;
    await room.connect(
      url,
      token,
      connectOptions: onEdge
          ? const lk.ConnectOptions(
              autoSubscribe: false,
              rtcConfiguration: lk.RTCConfiguration(
                iceTransportPolicy: lk.RTCIceTransportPolicy.relay,
              ),
            )
          : const lk.ConnectOptions(autoSubscribe: false),
    );
  }

  void _attachListeners(lk.EventsListener<lk.RoomEvent> listener) {
    listener
      ..on<lk.ParticipantConnectedEvent>((e) {
        _events.add(ParticipantJoined(e.participant.identity));
      })
      ..on<lk.ParticipantDisconnectedEvent>((e) {
        _events.add(ParticipantLeft(e.participant.identity));
      })
      ..on<lk.TrackPublishedEvent>((e) {
        _events.add(TrackPublished(RoomTrackRef(
          participantIdentity: e.participant.identity,
          trackName: e.publication.name,
          trackSid: e.publication.sid,
        )));
      })
      ..on<lk.DataReceivedEvent>((e) {
        _events.add(DataReceived(
          topic: e.topic ?? '',
          bytes: e.data,
          fromIdentity: e.participant?.identity ?? '',
        ));
      })
      ..on<lk.RoomReconnectingEvent>((_) {
        _events.add(const Reconnecting());
      })
      ..on<lk.RoomReconnectedEvent>((_) {
        _events.add(const Reconnected());
      })
      ..on<lk.RoomDisconnectedEvent>((_) {
        _events.add(const Disconnected());
      });
  }

  @override
  String get localIdentity => _room?.localParticipant?.identity ?? '';

  @override
  List<String> get remoteIdentities => _room == null
      ? const []
      : [for (final p in _room!.remoteParticipants.values) p.identity];

  @override
  List<RoomTrackRef> get remoteTracks => _room == null
      ? const []
      : [
          for (final p in _room!.remoteParticipants.values)
            for (final pub in p.trackPublications.values)
              RoomTrackRef(
                participantIdentity: p.identity,
                trackName: pub.name,
                trackSid: pub.sid,
              ),
        ];

  @override
  void restrictMicTo(String agentIdentity) {
    _room?.localParticipant?.setTrackSubscriptionPermissions(
      allParticipantsAllowed: false,
      trackPermissions: [
        lk.ParticipantTrackPermission(agentIdentity, true, null),
      ],
    );
  }

  @override
  Future<void> setMicrophone(bool on) async {
    await _room?.localParticipant?.setMicrophoneEnabled(on);
  }

  @override
  Future<void> subscribe(RoomTrackRef track) async {
    final room = _room;
    if (room == null) return;
    for (final p in room.remoteParticipants.values) {
      final pub = p.trackPublications[track.trackSid];
      if (pub != null) {
        // RemoteTrackPublication.subscribe() is itself a no-op when already
        // subscribed, so no extra check is needed here.
        await pub.subscribe();
        return;
      }
    }
  }

  @override
  Future<void> disconnect() async {
    await _listener?.dispose();
    _listener = null;
    await _room?.disconnect();
    await _room?.dispose();
    _room = null;
    await _events.close();
  }
}

/// The room URL calls use: the media endpoint the app is on (the CIS edge
/// included), not the server's own LiveKit address.
String interpreterLivekitUrl([EndpointService? endpoints]) {
  final media = (endpoints ?? sl<EndpointService>()).mediaBaseUrl;
  return '${media.replaceFirst('https://', 'wss://')}/livekit/';
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/room/livekit_url_test.dart lib/features/interpreter/room/livekit_interpreter_room.dart
```

Ожидается: `+141: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/room/livekit_url_test.dart lib/features/interpreter/room/livekit_interpreter_room.dart
git commit -m "feat(interpreter): адаптер LiveKit и адрес комнаты через медиа-адрес приложения" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Устройство: трубка, датчик приближения, фон

- Звук — в трубку (наушники по-прежнему важнее), громкая связь не включается: перевод из динамика попал бы в микрофон соседа. `Hardware.instance` — глобальный, поэтому прежнее предпочтение запоминается и возвращается после разговора.
- Датчик приближения (экран гаснет у уха) включается отдельно и только в самом разговоре: на экране QR рука, поднявшая телефон показать код, погасила бы его. Когда телефон не у уха, экран не гаснет (wakelock). На Android микрофон в фоне держит foreground-сервис. Ошибка нативного вызова не ломает разговор — только пишется в журнал.

**Files:**
- Create: `test/features/interpreter/room/interpreter_device_test.dart`, `lib/features/interpreter/room/interpreter_device.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/room/interpreter_device_test.dart` целиком:

```dart
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_device.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('taler_id/interpreter_device');

  late List<String> log;
  late List<MethodCall> channelCalls;

  InterpreterDevice makeDevice({
    bool isAndroid = true,
    bool preferSpeakerOutput = true,
  }) {
    return InterpreterDevice(
      channel: channel,
      isAndroid: isAndroid,
      getPreferSpeakerOutput: () {
        log.add('getPreferSpeakerOutput');
        return preferSpeakerOutput;
      },
      setSpeakerphoneOn: (on) async {
        log.add('setSpeakerphoneOn($on)');
      },
      wakelockEnable: () async {
        log.add('wakelockEnable');
      },
      wakelockDisable: () async {
        log.add('wakelockDisable');
      },
    );
  }

  setUp(() {
    log = [];
    channelCalls = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      channelCalls.add(call);
      log.add('${call.method}(${call.arguments})');
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('InterpreterDevice.enterConversation', () {
    test(
        'remembers speaker pref, then earpiece, wakelock, foreground in '
        'order (Android) — proximity is not touched', () async {
      final device = makeDevice(isAndroid: true, preferSpeakerOutput: true);
      await device.enterConversation();

      expect(log, [
        'getPreferSpeakerOutput',
        'setSpeakerphoneOn(false)',
        'wakelockEnable',
        'startForeground(null)',
      ]);
      expect(
          channelCalls.map((c) => c.method), isNot(contains('setProximity')));
    });

    test('does not start the Android foreground service on iOS', () async {
      final device = makeDevice(isAndroid: false);
      await device.enterConversation();

      expect(log, [
        'getPreferSpeakerOutput',
        'setSpeakerphoneOn(false)',
        'wakelockEnable',
      ]);
      expect(channelCalls.map((c) => c.method),
          isNot(contains('startForeground')));
    });

    test('calling it twice in a row has no further effect', () async {
      final device = makeDevice();
      await device.enterConversation();
      log.clear();
      channelCalls.clear();
      await device.enterConversation();

      expect(log, isEmpty);
    });
  });

  group('InterpreterDevice.leaveConversation', () {
    test(
        'reverses enterConversation in the opposite order, restoring the '
        'remembered speaker pref (Android)', () async {
      final device = makeDevice(isAndroid: true, preferSpeakerOutput: false);
      await device.enterConversation();
      log.clear();
      channelCalls.clear();

      await device.leaveConversation();

      expect(log, [
        'stopForeground(null)',
        'setProximity(false)',
        'wakelockDisable',
        'setSpeakerphoneOn(false)', // restores the remembered pref
      ]);
    });

    test('is idempotent: leaving without having entered does nothing',
        () async {
      final device = makeDevice();
      await device.leaveConversation();
      expect(log, isEmpty);
      expect(channelCalls, isEmpty);
    });

    test('is idempotent: leaving twice only acts once', () async {
      final device = makeDevice();
      await device.enterConversation();
      log.clear();
      await device.leaveConversation();
      log.clear();
      await device.leaveConversation();
      expect(log, isEmpty);
    });
  });

  group('InterpreterDevice.setNearEarScreenOff', () {
    test('on(true) calls setProximity(true), independent of enterConversation',
        () async {
      final device = makeDevice();
      await device.setNearEarScreenOff(true);

      expect(log, ['setProximity(true)']);
    });

    test('on(false) calls setProximity(false)', () async {
      final device = makeDevice();
      await device.setNearEarScreenOff(false);

      expect(log, ['setProximity(false)']);
    });

    test('can be called without enterConversation ever having run', () async {
      final device = makeDevice();
      await expectLater(device.setNearEarScreenOff(true), completes);
      expect(log, ['setProximity(true)']);
    });
  });

  group('error handling', () {
    test('a channel error during enterConversation does not throw', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'boom', message: 'no proximity sensor');
      });
      final device = makeDevice();

      await expectLater(device.enterConversation(), completes);
    });

    test('a channel error during leaveConversation does not throw', () async {
      final device = makeDevice();
      await device.enterConversation();

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'boom', message: 'gone');
      });

      await expectLater(device.leaveConversation(), completes);
    });

    test('a channel error during setNearEarScreenOff does not throw',
        () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'boom', message: 'no proximity sensor');
      });
      final device = makeDevice();

      await expectLater(device.setNearEarScreenOff(true), completes);
    });

    test(
        'no handler registered at all (MissingPluginException) does not '
        'throw', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
      final device = makeDevice();

      await expectLater(device.enterConversation(), completes);
      await expectLater(device.leaveConversation(), completes);
      await expectLater(device.setNearEarScreenOff(true), completes);
    });
  });
}
```

Run: `flutter test test/features/interpreter/room/interpreter_device_test.dart`
Expected: `test/features/interpreter/room/interpreter_device_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/room/interpreter_device.dart` целиком:

```dart
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:livekit_client/livekit_client.dart' as lk;
import 'package:wakelock_plus/wakelock_plus.dart';

/// Owns the device-level side effects of an interpreter conversation:
/// earpiece output, the wakelock that keeps the screen alive while the phone
/// isn't at the ear, (Android only) the foreground service that keeps the
/// microphone running while the app is backgrounded, and — separately, via
/// [setNearEarScreenOff] — the proximity-triggered screen-off.
///
/// Proximity is deliberately not part of [enterConversation]: that runs
/// before the host's QR code is even shown, and the proximity sensor would
/// blank the screen while the user is still holding the phone up for the
/// partner to scan. Callers turn it on only once two people are actually
/// talking (host: after the partner joins; guest: after joining).
///
/// Every platform call is best-effort: a conversation must not crash because
/// a channel call failed or a plugin is missing (e.g. in tests), so failures
/// are logged via [debugPrint] and swallowed, mirroring how the rest of the
/// codebase treats these channels.
class InterpreterDevice {
  static const _channelName = 'taler_id/interpreter_device';

  InterpreterDevice({
    MethodChannel? channel,
    bool? isAndroid,
    bool Function()? getPreferSpeakerOutput,
    Future<void> Function(bool on)? setSpeakerphoneOn,
    Future<void> Function()? wakelockEnable,
    Future<void> Function()? wakelockDisable,
  })  : _channel = channel ?? const MethodChannel(_channelName),
        _isAndroid =
            isAndroid ?? (defaultTargetPlatform == TargetPlatform.android),
        _getPreferSpeakerOutput = getPreferSpeakerOutput ??
            (() => lk.Hardware.instance.preferSpeakerOutput),
        _setSpeakerphoneOn = setSpeakerphoneOn ??
            ((on) => lk.Hardware.instance.setSpeakerphoneOn(on)),
        _wakelockEnable = wakelockEnable ?? WakelockPlus.enable,
        _wakelockDisable = wakelockDisable ?? WakelockPlus.disable;

  final MethodChannel _channel;
  final bool _isAndroid;
  final bool Function() _getPreferSpeakerOutput;
  final Future<void> Function(bool on) _setSpeakerphoneOn;
  final Future<void> Function() _wakelockEnable;
  final Future<void> Function() _wakelockDisable;

  bool _active = false;
  bool? _rememberedSpeakerPref;

  /// Switches the device into "interpreter conversation" mode. Idempotent —
  /// calling it again while already active does nothing. Does not touch the
  /// proximity sensor — see [setNearEarScreenOff].
  Future<void> enterConversation() async {
    if (_active) return;
    _active = true;
    _rememberedSpeakerPref = _getPreferSpeakerOutput();
    // Earpiece by default; a connected headset still wins over this.
    await _guard(() => _setSpeakerphoneOn(false));
    await _guard(_wakelockEnable);
    if (_isAndroid) {
      await _guard(() => _channel.invokeMethod<void>('startForeground'));
    }
  }

  /// Reverses [enterConversation] and, idempotently, also turns the
  /// proximity sensor off regardless of whether [setNearEarScreenOff] was
  /// ever called — a conversation must never leave the screen locked off.
  /// Never throws.
  Future<void> leaveConversation() async {
    if (!_active) return;
    _active = false;
    if (_isAndroid) {
      await _guard(() => _channel.invokeMethod<void>('stopForeground'));
    }
    await _guard(() => _channel.invokeMethod<void>('setProximity', false));
    await _guard(_wakelockDisable);
    final pref = _rememberedSpeakerPref;
    _rememberedSpeakerPref = null;
    if (pref != null) await _guard(() => _setSpeakerphoneOn(pref));
  }

  /// Turns the proximity-triggered screen-off on or off. Independent of
  /// [enterConversation]/[leaveConversation] — called once two people are
  /// actually in the conversation, not while a QR/code is still on screen.
  /// Best-effort: never throws.
  Future<void> setNearEarScreenOff(bool on) =>
      _guard(() => _channel.invokeMethod<void>('setProximity', on));

  Future<void> _guard(Future<void> Function() action) async {
    try {
      await action();
    } catch (e) {
      debugPrint('[InterpreterDevice] platform call failed: $e');
    }
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/room/interpreter_device_test.dart lib/features/interpreter/room/interpreter_device.dart
```

Ожидается: `+154: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/room/interpreter_device_test.dart lib/features/interpreter/room/interpreter_device.dart
git commit -m "feat(interpreter): трубка вместо динамика, датчик приближения, фон — на время разговора" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Android: датчик приближения и foreground-сервис

- Канал `taler_id/interpreter_device` в `MainActivity`: `setProximity` — wake lock `PROXIMITY_SCREEN_OFF_WAKE_LOCK` (отпускается и при уничтожении активити), `startForeground`/`stopForeground` — `InterpreterForegroundService` с типом `microphone` (Android 14 требует тип и `FOREGROUND_SERVICE_MICROPHONE`). `START_NOT_STICKY`: жизнью сервиса управляет Dart.

**Files:**
- Create: `android/app/src/main/kotlin/tirol/taler/taler_id_mobile/InterpreterForegroundService.kt`
- Modify: `android/app/src/main/AndroidManifest.xml`, `android/app/src/main/kotlin/tirol/taler/taler_id_mobile/MainActivity.kt`

- [ ] **Step 1: Код**

Патч к `android/app/src/main/AndroidManifest.xml`:

```diff
--- a/android/app/src/main/AndroidManifest.xml
+++ b/android/app/src/main/AndroidManifest.xml
@@ -32,6 +32,10 @@
     <uses-permission android:name="android.permission.BLUETOOTH_CONNECT"/>
     <uses-permission android:name="android.permission.BLUETOOTH_SCAN" android:usesPermissionFlags="neverForLocation"/>
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE"/>
+    <!-- Interpreter ("Разговор с переводом"): proximity screen-off wake lock
+         + foreground service that keeps the microphone open in background. -->
+    <uses-permission android:name="android.permission.WAKE_LOCK"/>
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE"/>
     <application
         android:label="@string/app_name"
         android:name="${applicationName}"
@@ -125,6 +129,10 @@
             android:foregroundServiceType="phoneCall"
             android:exported="false" />
         <service
+            android:name=".InterpreterForegroundService"
+            android:foregroundServiceType="microphone"
+            android:exported="false" />
+        <service
             android:name=".notifications.TalerNotificationListenerService"
             android:label="@string/app_name"
             android:exported="true"
```

`android/app/src/main/kotlin/tirol/taler/taler_id_mobile/InterpreterForegroundService.kt` целиком:

```kotlin
package tirol.taler.taler_id_mobile

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Anchors the process while an interpreter conversation ("Разговор с
 * переводом") keeps the microphone open in the background — the same role
 * [MeshForegroundService] plays for mesh calls, but with
 * `foregroundServiceType="microphone"` since interpreter rooms are plain
 * LiveKit rooms, never CallKit/telecom calls.
 */
class InterpreterForegroundService : Service() {
    companion object {
        const val CHANNEL_ID = "interpreter_fg"
        const val NOTIFICATION_ID = 9002
        const val ACTION_STOP = "tirol.taler.INTERPRETER_FG_STOP"
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Перевод в разговоре",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Держит микрофон активным во время разговора с переводом"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val openApp = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val contentIntent = PendingIntent.getActivity(
            this,
            NOTIFICATION_ID,
            openApp,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("Разговор с переводом")
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        try {
            // ServiceCompat ignores the type argument itself on API < 29 and
            // forwards it to the native 3-arg startForeground() from 29 on —
            // no manual SDK_INT branch needed here.
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE,
            )
        } catch (e: Exception) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Dart owns the call's lifecycle (InterpreterDevice/InterpreterBloc);
        // if the system kills this process, restarting the bare service
        // with no Dart side behind it would just leave an orphaned
        // notification with nothing driving it.
        return START_NOT_STICKY
    }
}
```

Патч к `android/app/src/main/kotlin/tirol/taler/taler_id_mobile/MainActivity.kt`:

```diff
--- a/android/app/src/main/kotlin/tirol/taler/taler_id_mobile/MainActivity.kt
+++ b/android/app/src/main/kotlin/tirol/taler/taler_id_mobile/MainActivity.kt
@@ -62,6 +62,9 @@
     private var webrtcPlugin: FlutterWebRTCPlugin? = null
     private val audioRouteEventSink = AtomicReference<EventChannel.EventSink?>(null)
     private var audioDeviceCallback: AudioDeviceCallback? = null
+    // Interpreter conversations: screen-off proximity sensor, held only
+    // while a conversation is active (taler_id/interpreter_device channel).
+    private var proximityWakeLock: PowerManager.WakeLock? = null
 
     /**
      * Single owner of the in-call output route. Every path that requests audio
@@ -121,6 +124,7 @@
 
     override fun onDestroy() {
         unregisterAudioRouteCallback()
+        setProximity(false)
         super.onDestroy()
     }
 
@@ -440,6 +444,54 @@
                     else -> result.notImplemented()
                 }
             }
+
+        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "taler_id/interpreter_device")
+            .setMethodCallHandler { call, result ->
+                when (call.method) {
+                    "setProximity" -> {
+                        val on = call.arguments as? Boolean ?: false
+                        setProximity(on)
+                        result.success(null)
+                    }
+                    "startForeground" -> {
+                        val intent = Intent(this, InterpreterForegroundService::class.java)
+                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
+                            startForegroundService(intent)
+                        } else {
+                            startService(intent)
+                        }
+                        result.success(null)
+                    }
+                    "stopForeground" -> {
+                        val intent = Intent(this, InterpreterForegroundService::class.java).apply {
+                            action = InterpreterForegroundService.ACTION_STOP
+                        }
+                        startService(intent)
+                        result.success(null)
+                    }
+                    else -> result.notImplemented()
+                }
+            }
+    }
+
+    /** Acquires/releases the screen-off proximity wake lock used while an
+     * interpreter conversation is active. No-op where the device doesn't
+     * support this wake lock level. */
+    private fun setProximity(on: Boolean) {
+        if (on) {
+            if (proximityWakeLock?.isHeld == true) return
+            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
+            if (!pm.isWakeLockLevelSupported(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK)) return
+            val wl = pm.newWakeLock(
+                PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK,
+                "taler_id:interpreter_proximity",
+            )
+            wl.acquire()
+            proximityWakeLock = wl
+        } else {
+            proximityWakeLock?.let { if (it.isHeld) it.release() }
+            proximityWakeLock = null
+        }
     }
 
     private fun requestAudioFocus(am: AudioManager) {
```

- [ ] **Step 2: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter build apk --debug --flavor dev -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol 2>&1 | tail -1
```

Ожидается: `+154: All tests passed!`; `✓ Built build/app/outputs/flutter-apk/app-dev-debug.apk`.

- [ ] **Step 3: Коммит**

```bash
git add android/app/src/main/AndroidManifest.xml android/app/src/main/kotlin/tirol/taler/taler_id_mobile/InterpreterForegroundService.kt android/app/src/main/kotlin/tirol/taler/taler_id_mobile/MainActivity.kt
git commit -m "feat(interpreter): Android — датчик приближения и foreground-сервис микрофона" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: iOS: датчик приближения

- Тот же канал в `AppDelegate`: `setProximity` — `UIDevice.current.isProximityMonitoringEnabled`; `startForeground`/`stopForeground` — пустые: микрофон в фоне держит `UIBackgroundModes: audio`.
- `CallKitAudioBridge.swift` не меняется: ручной режим звука WebRTC он включает только для разговоров, зарегистрированных в CallKit (`setManagedCalls` / ответ через CallKit), а разговор с переводом там не регистрируется.

**Files:**
- Modify: `ios/Runner/AppDelegate.swift`

- [ ] **Step 1: Код**

Патч к `ios/Runner/AppDelegate.swift`:

```diff
--- a/ios/Runner/AppDelegate.swift
+++ b/ios/Runner/AppDelegate.swift
@@ -187,6 +187,29 @@
               }
             }
           }
+          result(nil)
+        default:
+          result(FlutterMethodNotImplemented)
+        }
+      }
+    }
+
+    // Interpreter ("Разговор с переводом"): proximity sensor only. iOS keeps
+    // the mic running in the background through the `audio` UIBackgroundMode
+    // already declared in Info.plist, so startForeground/stopForeground
+    // (Android's foreground-service equivalent) are no-ops here.
+    if let controller = window?.rootViewController as? FlutterViewController {
+      let interpreterDeviceChannel = FlutterMethodChannel(
+        name: "taler_id/interpreter_device",
+        binaryMessenger: controller.binaryMessenger
+      )
+      interpreterDeviceChannel.setMethodCallHandler { call, result in
+        switch call.method {
+        case "setProximity":
+          let on = call.arguments as? Bool ?? false
+          UIDevice.current.isProximityMonitoringEnabled = on
+          result(nil)
+        case "startForeground", "stopForeground":
           result(nil)
         default:
           result(FlutterMethodNotImplemented)
```

- [ ] **Step 2: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
xcrun swiftc -parse ios/Runner/AppDelegate.swift && echo swift-parse-ok
```

Ожидается: `+154: All tests passed!`; `swift-parse-ok` (полная сборка iOS — в задаче 24).

- [ ] **Step 3: Коммит**

```bash
git add ios/Runner/AppDelegate.swift
git commit -m "feat(interpreter): iOS — датчик приближения на время разговора" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: BLoC разговора

- Состояния: загрузка → недоступно | нужен образец голоса → выбор языка → работа (создание/вход) → хост с QR → разговор → итог; плюс ошибка с возвратом к выбору.
- Комната и устройство освобождаются ровно один раз на любом пути: «Завершить», конец с сервера, закрытие комнаты, ошибка посреди подключения, уход с экрана во время долгого входа. Если экран закрыт, пока шёл вход или создание, — в комнату не входим, а созданную сессию завершаем: иначе хост платил бы за разговор, в котором никого нет.
- Гость подключившийся раньше, чем хост успел показать QR (события идут параллельно), не теряется.
- В разговоре — опрос `GET /interpreter/sessions/:id` раз в 15 с: стоимость у хоста и завершение.

**Files:**
- Create: `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`, `lib/features/interpreter/presentation/bloc/interpreter_event.dart`, `lib/features/interpreter/presentation/bloc/interpreter_state.dart`, `lib/features/interpreter/presentation/bloc/interpreter_bloc.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart` целиком:

```dart
import 'dart:async';
import 'dart:convert';

import 'package:bloc_test/bloc_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/features/interpreter/data/interpreter_lang_store.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_error.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_repository.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_bloc.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_event.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_state.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_device.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_room_controller.dart'
    show PartnerJoined;
import 'package:taler_id_mobile/features/interpreter/room/interpreter_room_port.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_signal.dart';
import 'package:taler_id_mobile/features/voice_enrollment/domain/entities/owner_voice_status.dart';
import 'package:taler_id_mobile/features/voice_enrollment/domain/repositories/voice_enrollment_repository.dart';

import '../../fakes.dart';

class MockInterpreterRepository extends Mock implements InterpreterRepository {}

class MockVoiceEnrollmentRepository extends Mock
    implements VoiceEnrollmentRepository {}

class MockInterpreterLangStore extends Mock implements InterpreterLangStore {}

class MockInterpreterDevice extends Mock implements InterpreterDevice {}

const _hostIdentity = 'host-user#aaaaaaaa';
const _partnerIdentity = 'partner-user#bbbbbbbb';
const _partnerUserId = 'partner-user';
const _tinyDelay = Duration(milliseconds: 5);

InterpreterCatalog _catalog() => const InterpreterCatalog(
      enabled: true,
      languages: [
        InterpreterLanguage(code: 'ru', name: 'Русский'),
        InterpreterLanguage(code: 'de', name: 'Deutsch'),
      ],
    );

HostedSession _hostedSession({String code = 'ABCD1234'}) => HostedSession(
      sessionId: 'sess-1',
      code: code,
      expiresAt: DateTime.utc(2026, 11, 1, 12, 5),
      roomName: 'interp-1',
      token: 'tok-host',
      livekitWsUrl: 'wss://lk/host',
    );

JoinedSession _joinedSession() => const JoinedSession(
      sessionId: 'sess-2',
      roomName: 'interp-2',
      token: 'tok-guest',
      livekitWsUrl: 'wss://lk/guest',
      partner: InterpreterPartner(firstName: 'B', lang: 'de'),
      directions: InterpreterDirections(
        toMe: InterpreterEngine.simultaneous,
        fromMe: InterpreterEngine.phrase,
      ),
    );

SessionView _activeView({String? spentPlanck}) => SessionView(
      status: InterpreterStatus.active,
      partner: const InterpreterPartner(firstName: 'B', lang: 'de'),
      directions: const InterpreterDirections(
        toMe: InterpreterEngine.simultaneous,
        fromMe: InterpreterEngine.simultaneous,
      ),
      startedAt: DateTime.utc(2026, 11, 1, 12, 0, 5),
      spentPlanck: spentPlanck,
    );

SessionView _endedView(InterpreterEndReason reason, {String? spentPlanck}) =>
    SessionView(
        status: InterpreterStatus.ended,
        endReason: reason,
        spentPlanck: spentPlanck);

List<int> _signalBytes(Map<String, Object?> json) =>
    utf8.encode(jsonEncode(json));

void main() {
  late MockInterpreterRepository repo;
  late MockVoiceEnrollmentRepository voice;
  late MockInterpreterLangStore langStore;
  late MockInterpreterDevice device;
  late FakeRoomPort port;
  late InterpreterBloc bloc;

  InterpreterBloc makeBloc(
          {Duration pollEvery = const Duration(seconds: 30)}) =>
      InterpreterBloc(
        repo: repo,
        langStore: langStore,
        voice: voice,
        roomFactory: () => port,
        device: device,
        appLocale: () => 'ru',
        livekitUrl: () => 'wss://media/livekit/',
        pollEvery: pollEvery,
      );

  setUpAll(() {
    registerFallbackValue(
        const InterpreterCatalog(enabled: true, languages: []));
  });

  setUp(() {
    repo = MockInterpreterRepository();
    voice = MockVoiceEnrollmentRepository();
    langStore = MockInterpreterLangStore();
    device = MockInterpreterDevice();
    port = FakeRoomPort(identity: _hostIdentity);

    when(() => device.enterConversation()).thenAnswer((_) async {});
    when(() => device.leaveConversation()).thenAnswer((_) async {});
    when(() => device.setNearEarScreenOff(any())).thenAnswer((_) async {});
    when(() => langStore.remember(any())).thenAnswer((_) async {});

    bloc = makeBloc();
  });

  tearDown(() async {
    await bloc.close();
    await port.close();
  });

  group('Started', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'catalog disabled -> Unavailable',
      build: () {
        when(() => repo.catalog()).thenAnswer(
          (_) async => const InterpreterCatalog(enabled: false, languages: []),
        );
        return bloc;
      },
      act: (b) => b.add(const Started()),
      expect: () => [
        const InterpreterLoading(),
        const InterpreterUnavailable(),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'loads the catalog and preselects the stored language',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'de');
        return bloc;
      },
      act: (b) => b.add(const Started()),
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>()
            .having((s) => s.myLang, 'myLang', 'de')
            .having((s) => s.catalog.languages.length, 'languages', 2)
            .having((s) => s.joinCode, 'joinCode', isNull),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'carries a deep-linked join code through into Choosing',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        return bloc;
      },
      act: (b) => b.add(const Started(joinCode: 'JOIN99')),
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>()
            .having((s) => s.joinCode, 'joinCode', 'JOIN99'),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'a catalog load failure has nowhere to go back to; RetryPressed reloads it',
      build: () {
        var attempt = 0;
        when(() => repo.catalog()).thenAnswer((_) async {
          attempt++;
          if (attempt == 1) {
            throw const InterpreterException(InterpreterErrorKind.network);
          }
          return _catalog();
        });
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const RetryPressed());
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterFailure>()
            .having((s) => s.kind, 'kind', InterpreterErrorKind.network)
            .having((s) => s.back, 'back', isNull),
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
      ],
    );
  });

  group('host flow', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'happy path: create, enter the room once, emit Hosting',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        // Checked here, not in `verify` — bloc_test closes the bloc (which
        // tears down the room, adding a `disconnect()` call) before `verify`
        // runs, so the room's call log has to be inspected while still live.
        expect(port.calls, [
          'connect(wss://media/livekit/, tok-host)',
          'restrictMicTo(voice-interpreter)',
          'setMicrophone(true)',
        ]);
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        const InterpreterWorking(InterpreterWorkKind.creating),
        isA<InterpreterHosting>()
            .having((s) => s.code, 'code', 'ABCD1234')
            .having((s) => s.myLang, 'myLang', 'ru'),
      ],
      verify: (_) {
        // The QR is still on screen at this point — turning the proximity
        // sensor on here would blank it before the partner can scan it.
        verifyNever(() => device.setNearEarScreenOff(any()));
      },
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'NewCodePressed replaces the code and expiry while hosting',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.newCode('sess-1')).thenAnswer(
          (_) async => NewCode(
              code: 'NEWCODE1', expiresAt: DateTime.utc(2026, 11, 1, 12, 10)),
        );
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        b.add(const NewCodePressed());
      },
      skip: 3,
      expect: () => [
        isA<InterpreterHosting>().having((s) => s.code, 'code', 'ABCD1234'),
        isA<InterpreterHosting>().having((s) => s.code, 'code', 'NEWCODE1'),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'NewCodePressed failing falls back to the last known Choosing',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.newCode('sess-1')).thenThrow(
            const InterpreterException(InterpreterErrorKind.notWaiting));
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        b.add(const NewCodePressed());
      },
      skip: 3,
      expect: () => [
        isA<InterpreterHosting>(),
        isA<InterpreterFailure>()
            .having((s) => s.kind, 'kind', InterpreterErrorKind.notWaiting)
            .having((s) => s.back, 'back', isA<InterpreterChoosing>()),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'PartnerJoined while hosting fetches the session and becomes Active',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
      },
      skip: 3,
      expect: () => [
        isA<InterpreterHosting>(),
        isA<InterpreterActive>()
            .having((s) => s.isHost, 'isHost', true)
            .having((s) => s.partner.lang, 'partner lang', 'de')
            .having((s) => s.directions.toMe, 'toMe',
                InterpreterEngine.simultaneous)
            .having((s) => s.spentPlanck, 'spentPlanck', isNull),
      ],
      verify: (_) {
        // Now that the partner is actually on the call, the proximity
        // sensor can safely take over the screen.
        verify(() => device.setNearEarScreenOff(true)).called(1);
      },
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'a session view missing partner/directions is treated like a failed '
      'repo.get, not a crash',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        // The backend contract guarantees partner/directions once a partner
        // has joined, but this is exactly the shape that used to crash via
        // `view.partner!`/`view.directions!`.
        when(() => repo.get('sess-1')).thenAnswer(
            (_) async => const SessionView(status: InterpreterStatus.active));
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        // Torn down right away, same as a failed repo.get() — not left live.
        expect(port.disconnected, isTrue);
      },
      skip: 3,
      expect: () => [
        isA<InterpreterHosting>(),
        isA<InterpreterFailure>()
            .having((s) => s.kind, 'kind', InterpreterErrorKind.unknown),
      ],
      verify: (_) {
        verifyNever(() => device.setNearEarScreenOff(any()));
      },
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'a PartnerJoined that reaches the bloc before Hosting is emitted is '
      'not dropped — the host still reaches Active, not stuck on the QR',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        // Queued back-to-back, no await in between: HostPressed's handler
        // still has `voice.getStatus()`, `repo.create()`, entering the room
        // and connecting the port ahead of it before Hosting is ever
        // emitted, while this one only has to reach the `case
        // PartnerJoined` branch — exactly the ordering the room's own
        // ParticipantJoined replay can produce for real.
        b.add(const HostPressed());
        b.add(RoomUpdateArrived(const PartnerJoined(_partnerIdentity)));
        await Future.delayed(_tinyDelay);
      },
      verify: (b) {
        expect(b.state, isA<InterpreterActive>());
      },
    );
  });

  group('guest flow', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'happy path: join, enter the room once, emit Active from the join answer',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.join('CODE1', 'ru'))
            .thenAnswer((_) async => _joinedSession());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const JoinPressed('CODE1'));
        await Future.delayed(_tinyDelay);
        // Checked here, not in `verify` — see the host happy-path test for why.
        expect(port.calls, [
          'connect(wss://media/livekit/, tok-guest)',
          'restrictMicTo(voice-interpreter)',
          'setMicrophone(true)',
        ]);
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        const InterpreterWorking(InterpreterWorkKind.joining),
        isA<InterpreterActive>()
            .having((s) => s.isHost, 'isHost', false)
            .having((s) => s.partner.firstName, 'partner', 'B')
            .having((s) => s.spentPlanck, 'spentPlanck', isNull),
      ],
      verify: (_) {
        verify(() => device.setNearEarScreenOff(true)).called(1);
      },
    );
  });

  group('voice-print gate', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'missing voice print opens the gate; cancelling returns to Choosing',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: false));
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        b.add(const VoicePrintResult(false));
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        const InterpreterNeedVoicePrint(then: InterpreterPendingAction.host),
        isA<InterpreterChoosing>(),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'missing voice print opens the gate; confirming continues hosting',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: false));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        b.add(const VoicePrintResult(true));
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        const InterpreterNeedVoicePrint(then: InterpreterPendingAction.host),
        const InterpreterWorking(InterpreterWorkKind.creating),
        isA<InterpreterHosting>(),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'missing voice print for a join carries the code through and on into Active',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: false));
        when(() => repo.join('CODE1', 'ru'))
            .thenAnswer((_) async => _joinedSession());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const JoinPressed('CODE1'));
        await Future.delayed(_tinyDelay);
        b.add(const VoicePrintResult(true));
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        const InterpreterNeedVoicePrint(
            then: InterpreterPendingAction.join, code: 'CODE1'),
        const InterpreterWorking(InterpreterWorkKind.joining),
        isA<InterpreterActive>(),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'a 409 voice_print_required from the server also opens the gate',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.join('CODE1', 'ru')).thenThrow(
          const InterpreterException(InterpreterErrorKind.voicePrintRequired),
        );
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const JoinPressed('CODE1'));
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        const InterpreterWorking(InterpreterWorkKind.joining),
        const InterpreterNeedVoicePrint(
            then: InterpreterPendingAction.join, code: 'CODE1'),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'a failed voice-print check itself surfaces as Failure, not NeedVoicePrint',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus()).thenThrow(Exception('network'));
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
      },
      expect: () => [
        const InterpreterLoading(),
        isA<InterpreterChoosing>(),
        isA<InterpreterFailure>()
            .having((s) => s.kind, 'kind', InterpreterErrorKind.unknown)
            .having((s) => s.back, 'back', isA<InterpreterChoosing>()),
      ],
    );
  });

  group('every backend error kind surfaces as Failure', () {
    const kinds = [
      InterpreterErrorKind.sameLanguage,
      InterpreterErrorKind.ownCode,
      InterpreterErrorKind.codeUsed,
      InterpreterErrorKind.codeExpired,
      InterpreterErrorKind.codeNotFound,
      InterpreterErrorKind.hostInsufficientFunds,
      InterpreterErrorKind.hostVoicePrintRequired,
      InterpreterErrorKind.interpreterUnavailable,
      InterpreterErrorKind.tooManyAttempts,
      InterpreterErrorKind.network,
      InterpreterErrorKind.unknown,
    ];

    for (final kind in kinds) {
      blocTest<InterpreterBloc, InterpreterState>(
        'join failing with ${kind.name} -> Failure(back: Choosing)',
        build: () {
          when(() => repo.catalog()).thenAnswer((_) async => _catalog());
          when(() => langStore.initial(any(), any()))
              .thenAnswer((_) async => 'ru');
          when(() => voice.getStatus())
              .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
          when(() => repo.join('CODE1', 'ru'))
              .thenThrow(InterpreterException(kind));
          return bloc;
        },
        act: (b) async {
          b.add(const Started());
          await Future.delayed(_tinyDelay);
          b.add(const JoinPressed('CODE1'));
        },
        expect: () => [
          const InterpreterLoading(),
          isA<InterpreterChoosing>(),
          const InterpreterWorking(InterpreterWorkKind.joining),
          isA<InterpreterFailure>()
              .having((s) => s.kind, 'kind', kind)
              .having((s) => s.back, 'back', isA<InterpreterChoosing>()),
        ],
      );
    }
  });

  group('RetryPressed / BackToStart', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'RetryPressed from a Failure returns to the Choosing it carries',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.join('BAD', 'ru')).thenThrow(
            const InterpreterException(InterpreterErrorKind.codeExpired));
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const JoinPressed('BAD'));
        await Future.delayed(_tinyDelay);
        b.add(const RetryPressed());
      },
      skip: 3,
      expect: () => [
        isA<InterpreterFailure>(),
        isA<InterpreterChoosing>(),
      ],
    );
  });

  group('while active', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'captions, speaking, agent presence and connection signals update Active',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        // Now Active. Agent joins:
        port.emit(const ParticipantJoined('voice-interpreter'));
        await Future.delayed(_tinyDelay);
        // Partner's translation caption:
        port.emit(DataReceived(
          topic: 'interp',
          bytes: _signalBytes({
            'type': 'caption',
            'role': 'translation',
            'speaker': _partnerUserId,
            'text': 'Hallo',
            'final': false,
          }),
          fromIdentity: 'voice-interpreter',
        ));
        await Future.delayed(_tinyDelay);
        // Partner starts speaking:
        port.emit(DataReceived(
          topic: 'interp',
          bytes: _signalBytes(
              {'type': 'speaking', 'speaker': _partnerUserId, 'on': true}),
          fromIdentity: 'voice-interpreter',
        ));
        await Future.delayed(_tinyDelay);
        // Translation socket hiccups:
        port.emit(DataReceived(
          topic: 'interp',
          bytes: _signalBytes({'type': 'status', 'state': 'reconnecting'}),
          fromIdentity: 'voice-interpreter',
        ));
        await Future.delayed(_tinyDelay);
        // Agent leaves (e.g. a deploy):
        port.emit(const ParticipantLeft('voice-interpreter'));
      },
      skip: 5, // Loading, Choosing, Working(creating), Hosting, Active(initial)
      expect: () => [
        isA<InterpreterActive>()
            .having((s) => s.agentPresent, 'agentPresent', true),
        isA<InterpreterActive>().having(
          (s) => s.captions.linesFor(CaptionRole.translation).single.text,
          'caption text',
          'Hallo',
        ),
        isA<InterpreterActive>()
            .having((s) => s.partnerSpeaking, 'partnerSpeaking', true),
        isA<InterpreterActive>().having((s) => s.connection, 'connection',
            InterpreterLinkState.reconnecting),
        isA<InterpreterActive>()
            .having((s) => s.agentPresent, 'agentPresent', false),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'MicToggled calls through to the room and updates micOn',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        b.add(const MicToggled(false));
        await Future.delayed(_tinyDelay);
        // Checked here, not in `verify` — see the host happy-path test for why.
        expect(port.calls.last, 'setMicrophone(false)');
      },
      skip: 4,
      expect: () => [
        isA<InterpreterActive>().having((s) => s.micOn, 'micOn', true),
        isA<InterpreterActive>().having((s) => s.micOn, 'micOn', false),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'the poll timer refreshes the host spentPlanck, then ends the call on ended status',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());

        var call = 0;
        when(() => repo.get('sess-1')).thenAnswer((_) async {
          call++;
          if (call == 1) return _activeView();
          if (call == 2) return _activeView(spentPlanck: '1200');
          return _endedView(InterpreterEndReason.maxDuration,
              spentPlanck: '5000');
        });

        return makeBloc(pollEvery: const Duration(milliseconds: 15));
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
      },
      wait: const Duration(milliseconds: 120),
      skip: 4,
      expect: () => [
        isA<InterpreterActive>()
            .having((s) => s.spentPlanck, 'spentPlanck', isNull),
        isA<InterpreterActive>()
            .having((s) => s.spentPlanck, 'spentPlanck', '1200'),
        isA<InterpreterEnded>()
            .having((s) => s.reason, 'reason', InterpreterEndReason.maxDuration)
            .having((s) => s.spentPlanck, 'spentPlanck', '5000')
            .having((s) => s.isHost, 'isHost', true),
      ],
    );
  });

  group('abandoned rooms are always torn down', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'repo.get failing while hosting tears down the room before the failure, '
      'not only once BackToStart is pressed',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1')).thenThrow(
            const InterpreterException(InterpreterErrorKind.network));
        return bloc;
      },
      act: (b) async {
        var leaveCount = 0;
        when(() => device.leaveConversation())
            .thenAnswer((_) async => leaveCount++);

        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        // Torn down already, right here — not waiting for BackToStart.
        expect(port.disconnected, isTrue);
        expect(leaveCount, 1);
        b.add(const BackToStart());
        await Future.delayed(_tinyDelay);
        // BackToStart's own teardown call was a no-op: still exactly once.
        expect(leaveCount, 1);
      },
      skip: 4, // Loading, Choosing, Working(creating), Hosting
      expect: () => [
        isA<InterpreterFailure>()
            .having((s) => s.kind, 'kind', InterpreterErrorKind.network),
        isA<InterpreterChoosing>(),
      ],
    );
  });

  group('ending the call', () {
    blocTest<InterpreterBloc, InterpreterState>(
      'EndPressed ends the call once, tears down the room and reports hangup',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1'))
            .thenAnswer((_) async => _activeView(spentPlanck: '900'));
        when(() => repo.end('sess-1')).thenAnswer((_) async {});
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        b.add(const EndPressed());
      },
      skip: 4,
      expect: () => [
        isA<InterpreterActive>(),
        isA<InterpreterEnded>()
            .having((s) => s.reason, 'reason', InterpreterEndReason.hangup)
            .having((s) => s.spentPlanck, 'spentPlanck', '900')
            .having((s) => s.isHost, 'isHost', true),
      ],
      verify: (_) {
        verify(() => repo.end('sess-1')).called(1);
        verify(() => device.leaveConversation()).called(1);
        expect(port.disconnected, isTrue);
      },
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'EndPressed failing on the server is logged and ends the call locally anyway',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
        when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
        when(() => repo.end('sess-1')).thenThrow(Exception('offline'));
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        b.add(const EndPressed());
      },
      skip: 4,
      expect: () => [
        isA<InterpreterActive>(),
        isA<InterpreterEnded>()
            .having((s) => s.reason, 'reason', InterpreterEndReason.hangup),
      ],
    );

    blocTest<InterpreterBloc, InterpreterState>(
      'the room closing on its own fetches the reason exactly once and ends the call',
      build: () {
        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
        when(() => langStore.initial(any(), any()))
            .thenAnswer((_) async => 'ru');
        when(() => voice.getStatus())
            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
        when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());

        var call = 0;
        when(() => repo.get('sess-1')).thenAnswer((_) async {
          call++;
          if (call == 1) return _activeView();
          return _endedView(InterpreterEndReason.partnerLeft,
              spentPlanck: '300');
        });
        return bloc;
      },
      act: (b) async {
        b.add(const Started());
        await Future.delayed(_tinyDelay);
        b.add(const HostPressed());
        await Future.delayed(_tinyDelay);
        port.emit(const ParticipantJoined(_partnerIdentity));
        await Future.delayed(_tinyDelay);
        port.emit(const Disconnected());
      },
      skip: 4,
      expect: () => [
        isA<InterpreterActive>(),
        isA<InterpreterEnded>()
            .having((s) => s.reason, 'reason', InterpreterEndReason.partnerLeft)
            .having((s) => s.spentPlanck, 'spentPlanck', '300'),
      ],
      verify: (_) {
        verify(() => repo.get('sess-1')).called(2);
      },
    );

    test(
        'closing the bloc tears down the room without ending the session on the server',
        () async {
      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
      when(() => voice.getStatus())
          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
      when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
      when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());

      bloc.add(const Started());
      await Future.delayed(_tinyDelay);
      bloc.add(const HostPressed());
      await Future.delayed(_tinyDelay);
      port.emit(const ParticipantJoined(_partnerIdentity));
      await Future.delayed(_tinyDelay);
      expect(bloc.state, isA<InterpreterActive>());

      await bloc.close();

      verify(() => device.leaveConversation()).called(1);
      verifyNever(() => repo.end(any()));
      expect(port.disconnected, isTrue);
    });
  });

  group('closing the bloc mid-flight', () {
    test(
        'closing while repo.create is still resolving never enters the room, '
        'and ends the session once create finally answers', () async {
      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
      when(() => voice.getStatus())
          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));

      final createGate = Completer<HostedSession>();
      when(() => repo.create('ru')).thenAnswer((_) => createGate.future);
      when(() => repo.end('sess-1')).thenAnswer((_) async {});

      bloc.add(const Started());
      await Future.delayed(_tinyDelay);
      bloc.add(const HostPressed());
      await Future.delayed(_tinyDelay); // now awaiting repo.create

      // Deliberately not awaited yet — awaiting here would deadlock: close()
      // itself waits for this very handler to return.
      final closeFuture = bloc.close();
      await Future.delayed(_tinyDelay);

      createGate.complete(_hostedSession());
      // `closeFuture` itself resolves as soon as close() cancels the
      // in-flight emitter — it does not wait for the handler's `async`
      // function to actually finish running, so that finish has to be
      // pumped for separately.
      await closeFuture;
      await Future.delayed(_tinyDelay);

      expect(port.calls, isEmpty);
      verify(() => repo.end('sess-1')).called(1);
    });

    test(
        'closing while repo.join is still resolving never enters the room, '
        'and ends the session once join finally answers', () async {
      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
      when(() => voice.getStatus())
          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));

      final joinGate = Completer<JoinedSession>();
      when(() => repo.join('CODE1', 'ru')).thenAnswer((_) => joinGate.future);
      when(() => repo.end('sess-2')).thenAnswer((_) async {});

      bloc.add(const Started());
      await Future.delayed(_tinyDelay);
      bloc.add(const JoinPressed('CODE1'));
      await Future.delayed(_tinyDelay); // now awaiting repo.join

      final closeFuture = bloc.close();
      await Future.delayed(_tinyDelay);

      joinGate.complete(_joinedSession());
      await closeFuture;
      await Future.delayed(_tinyDelay);

      expect(port.calls, isEmpty);
      verify(() => repo.end('sess-2')).called(1);
    });

    test(
        'closing while the room itself is still connecting tears it down '
        'and ends the session once connect finally answers', () async {
      final connectGate = Completer<void>();
      port = FakeRoomPort(identity: _hostIdentity, connectGate: connectGate);

      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
      when(() => voice.getStatus())
          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
      when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
      when(() => repo.end('sess-1')).thenAnswer((_) async {});

      bloc.add(const Started());
      await Future.delayed(_tinyDelay);
      bloc.add(const HostPressed());
      await Future.delayed(_tinyDelay); // connect() called, stuck on the gate

      expect(port.calls, ['connect(wss://media/livekit/, tok-host)']);

      final closeFuture = bloc.close();
      await Future.delayed(_tinyDelay);

      connectGate.complete();
      await closeFuture;
      await Future.delayed(_tinyDelay);

      verify(() => device.leaveConversation()).called(1);
      verify(() => repo.end('sess-1')).called(1);
      expect(port.disconnected, isTrue);
    });
  });
}
```

Run: `flutter test test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`
Expected: `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/presentation/bloc/interpreter_event.dart` целиком:

```dart
import 'package:equatable/equatable.dart';

import '../../room/interpreter_room_controller.dart' show RoomUpdate;

sealed class InterpreterEvent extends Equatable {
  const InterpreterEvent();
}

/// Opens the feature. [joinCode] is set when the screen was reached via a
/// scanned/deep-linked `talerid://interp/<code>` link, so it can be carried
/// through to a [JoinPressed] once a language is picked.
class Started extends InterpreterEvent {
  final String? joinCode;
  const Started({this.joinCode});
  @override
  List<Object?> get props => [joinCode];
}

class LanguageChosen extends InterpreterEvent {
  final String code;
  const LanguageChosen(this.code);
  @override
  List<Object?> get props => [code];
}

class HostPressed extends InterpreterEvent {
  const HostPressed();
  @override
  List<Object?> get props => const [];
}

/// Also used to resume a join after a scan or a deep link, once a language
/// has been picked and (if needed) a voice print has been recorded.
class JoinPressed extends InterpreterEvent {
  final String code;
  const JoinPressed(this.code);
  @override
  List<Object?> get props => [code];
}

/// Sent by the screen after the owner-enrollment sheet closes: `true` if a
/// usable voice print now exists, `false` on cancel.
class VoicePrintResult extends InterpreterEvent {
  final bool ok;
  const VoicePrintResult(this.ok);
  @override
  List<Object?> get props => [ok];
}

class NewCodePressed extends InterpreterEvent {
  const NewCodePressed();
  @override
  List<Object?> get props => const [];
}

class EndPressed extends InterpreterEvent {
  const EndPressed();
  @override
  List<Object?> get props => const [];
}

class MicToggled extends InterpreterEvent {
  final bool on;
  const MicToggled(this.on);
  @override
  List<Object?> get props => [on];
}

class RetryPressed extends InterpreterEvent {
  const RetryPressed();
  @override
  List<Object?> get props => const [];
}

class BackToStart extends InterpreterEvent {
  const BackToStart();
  @override
  List<Object?> get props => const [];
}

/// Internal: one update from [InterpreterRoomController.updates], funneled
/// through the bloc's own event queue like every other state change rather
/// than reacted to directly from the subscription callback.
class RoomUpdateArrived extends InterpreterEvent {
  final RoomUpdate update;
  const RoomUpdateArrived(this.update);
  @override
  List<Object?> get props => [update];
}

/// Internal: fired by the poll timer while [InterpreterActive].
class PollTicked extends InterpreterEvent {
  const PollTicked();
  @override
  List<Object?> get props => const [];
}
```

`lib/features/interpreter/presentation/bloc/interpreter_state.dart` целиком:

```dart
import 'package:equatable/equatable.dart';

import '../../domain/interpreter_error.dart';
import '../../domain/interpreter_models.dart';
import '../../room/caption_lines.dart';

/// Pending action a still-open [InterpreterNeedVoicePrint] gate will resume
/// once the owner finishes (or cancels) recording a voice print.
enum InterpreterPendingAction { host, join }

/// How a would-be host/guest is working through the start flow, shown while
/// a REST round-trip to create or join a session is in flight.
enum InterpreterWorkKind { creating, joining }

/// Health of the call as the UI reports it. A reconnecting/healthy LiveKit
/// room (the controller's own `Connection` update) and a
/// reconnecting/healthy/failed translation socket on the agent side (a
/// `StatusSignal`) both funnel into this one field — either kind of trouble
/// reads the same to the person holding the phone.
enum InterpreterLinkState { reconnecting, ok, failed }

sealed class InterpreterState extends Equatable {
  const InterpreterState();
}

class InterpreterLoading extends InterpreterState {
  const InterpreterLoading();
  @override
  List<Object?> get props => const [];
}

/// `GET /interpreter/languages` answered `enabled: false`.
class InterpreterUnavailable extends InterpreterState {
  const InterpreterUnavailable();
  @override
  List<Object?> get props => const [];
}

/// The owner has no usable voice print. [then]/[code] say what to resume
/// once the enrollment sheet reports back via `VoicePrintResult`; the
/// Choosing state to fall back to on cancel is tracked internally by the
/// bloc, not carried on this state.
class InterpreterNeedVoicePrint extends InterpreterState {
  final InterpreterPendingAction then;
  final String? code;

  const InterpreterNeedVoicePrint({required this.then, this.code});

  @override
  List<Object?> get props => [then, code];
}

class InterpreterChoosing extends InterpreterState {
  final InterpreterCatalog catalog;
  final String myLang;
  final String? joinCode;

  const InterpreterChoosing({
    required this.catalog,
    required this.myLang,
    this.joinCode,
  });

  InterpreterChoosing copyWith({String? myLang}) => InterpreterChoosing(
        catalog: catalog,
        myLang: myLang ?? this.myLang,
        joinCode: joinCode,
      );

  @override
  List<Object?> get props => [catalog, myLang, joinCode];
}

/// A `create`/`join` REST round-trip is in flight.
class InterpreterWorking extends InterpreterState {
  final InterpreterWorkKind kind;
  const InterpreterWorking(this.kind);
  @override
  List<Object?> get props => [kind];
}

/// Host (A), connected and waiting for a guest to scan [code].
class InterpreterHosting extends InterpreterState {
  final HostedSession session;
  final String code;
  final DateTime expiresAt;
  final String myLang;

  const InterpreterHosting({
    required this.session,
    required this.code,
    required this.expiresAt,
    required this.myLang,
  });

  InterpreterHosting copyWith({String? code, DateTime? expiresAt}) =>
      InterpreterHosting(
        session: session,
        code: code ?? this.code,
        expiresAt: expiresAt ?? this.expiresAt,
        myLang: myLang,
      );

  @override
  List<Object?> get props => [session, code, expiresAt, myLang];
}

/// The conversation itself, for both host and guest.
class InterpreterActive extends InterpreterState {
  final bool isHost;
  final String myLang;
  final InterpreterPartner partner;
  final InterpreterDirections directions;
  final CaptionLines captions;
  final bool partnerSpeaking;
  final bool meSpeaking;
  final bool agentPresent;
  final InterpreterLinkState connection;
  final bool micOn;
  final DateTime startedAt;
  final String? spentPlanck;
  final int _revision;

  // Not `const`-able: `captions` is a mutable accumulator, not a value.
  // ignore: prefer_const_constructors_in_immutables
  InterpreterActive({
    required this.isHost,
    required this.myLang,
    required this.partner,
    required this.directions,
    required this.captions,
    required this.partnerSpeaking,
    required this.meSpeaking,
    required this.agentPresent,
    required this.connection,
    required this.micOn,
    required this.startedAt,
    this.spentPlanck,
    int revision = 0,
  }) : _revision = revision;

  /// [captions] is the very same mutable accumulator on every copy — new
  /// signals are appended to it in place by the bloc rather than rebuilt —
  /// so it is deliberately left out of [props]: comparing it would always
  /// see the identical object. [_revision] is bumped on every copy instead,
  /// so each update is a distinct state Equatable will actually deliver to
  /// listeners, including a caption-only one that touches no other field.
  InterpreterActive copyWith({
    InterpreterPartner? partner,
    InterpreterDirections? directions,
    bool? partnerSpeaking,
    bool? meSpeaking,
    bool? agentPresent,
    InterpreterLinkState? connection,
    bool? micOn,
    String? spentPlanck,
  }) =>
      InterpreterActive(
        isHost: isHost,
        myLang: myLang,
        partner: partner ?? this.partner,
        directions: directions ?? this.directions,
        captions: captions,
        partnerSpeaking: partnerSpeaking ?? this.partnerSpeaking,
        meSpeaking: meSpeaking ?? this.meSpeaking,
        agentPresent: agentPresent ?? this.agentPresent,
        connection: connection ?? this.connection,
        micOn: micOn ?? this.micOn,
        startedAt: startedAt,
        spentPlanck: spentPlanck ?? this.spentPlanck,
        revision: _revision + 1,
      );

  @override
  List<Object?> get props => [
        isHost,
        myLang,
        partner,
        directions,
        partnerSpeaking,
        meSpeaking,
        agentPresent,
        connection,
        micOn,
        startedAt,
        spentPlanck,
        _revision,
      ];
}

class InterpreterEnded extends InterpreterState {
  final InterpreterEndReason? reason;
  final Duration? duration;
  final String? spentPlanck;
  final bool isHost;

  const InterpreterEnded({
    this.reason,
    this.duration,
    this.spentPlanck,
    required this.isHost,
  });

  @override
  List<Object?> get props => [reason, duration, spentPlanck, isHost];
}

/// [back] is the Choosing state to return to on `RetryPressed`/`BackToStart`
/// — `null` only when the very first catalog load failed, before any
/// Choosing state had ever been reached.
class InterpreterFailure extends InterpreterState {
  final InterpreterErrorKind kind;
  final InterpreterChoosing? back;

  const InterpreterFailure({required this.kind, this.back});

  @override
  List<Object?> get props => [kind, back];
}
```

`lib/features/interpreter/presentation/bloc/interpreter_bloc.dart` целиком:

```dart
import 'dart:async';

import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../../voice_enrollment/domain/repositories/voice_enrollment_repository.dart';
import '../../data/interpreter_lang_store.dart';
import '../../domain/interpreter_error.dart';
import '../../domain/interpreter_models.dart';
import '../../domain/interpreter_repository.dart';
import '../../room/caption_lines.dart';
import '../../room/interpreter_device.dart';
import '../../room/interpreter_room_controller.dart';
import '../../room/interpreter_room_port.dart';
import '../../room/interpreter_signal.dart';
import 'interpreter_event.dart';
import 'interpreter_state.dart';

/// State machine for "Разговор с переводом" (two phones, side by side, each
/// hearing only the translation of the other).
///
/// Every repository failure funnels through [_emitRepoFailure], which also
/// handles the one cross-cutting rule the spec calls for: a bare
/// `voice_print_required` from the server reopens the voice-print gate
/// instead of surfacing as a generic [InterpreterFailure] — `
/// host_voice_print_required` and every other code do not, since there is
/// nothing the current user can do about someone else's missing print.
class InterpreterBloc extends Bloc<InterpreterEvent, InterpreterState> {
  final InterpreterRepository repo;
  final InterpreterLangStore langStore;
  final VoiceEnrollmentRepository voice;
  final InterpreterRoomPort Function() roomFactory;
  final InterpreterDevice device;
  final String Function() appLocale;

  /// Where the room is, from the client's own media endpoint (the CIS edge
  /// when the app runs on it), as calls do — not the server's LIVEKIT_WS_URL,
  /// which a CIS network cannot reach.
  final String Function() livekitUrl;
  final DateTime Function() now;
  final Duration pollEvery;

  InterpreterRoomController? _controller;
  StreamSubscription<RoomUpdate>? _roomSub;
  Timer? _pollTimer;
  bool _pollInFlight = false;

  /// `true` once the current room attempt's teardown (device + controller)
  /// has run, so [_teardownRoom] — called from more than one place a call
  /// can end — performs it exactly once. Starts `true`: there is nothing to
  /// tear down before the first room is ever attached.
  bool _tornDown = true;

  String? _initialJoinCode;
  InterpreterChoosing? _lastChoosing;
  String? _sessionId;
  bool _isHost = false;
  DateTime? _startedAt;
  String? _partnerUserId;
  bool _agentPresentNow = false;

  /// Set when a [PartnerJoined] update is processed before the bloc has
  /// had a chance to emit [InterpreterHosting] itself — see [_onRoomUpdate].
  bool _partnerJoinedBeforeHosting = false;

  InterpreterBloc({
    required this.repo,
    required this.langStore,
    required this.voice,
    required this.roomFactory,
    required this.device,
    required this.appLocale,
    required this.livekitUrl,
    this.now = DateTime.now,
    this.pollEvery = const Duration(seconds: 15),
  }) : super(const InterpreterLoading()) {
    on<Started>(_onStarted);
    on<LanguageChosen>(_onLanguageChosen);
    on<HostPressed>(_onHostPressed);
    on<JoinPressed>(_onJoinPressed);
    on<VoicePrintResult>(_onVoicePrintResult);
    on<NewCodePressed>(_onNewCodePressed);
    on<EndPressed>(_onEndPressed);
    on<MicToggled>(_onMicToggled);
    on<RetryPressed>(_onRetryPressed);
    on<BackToStart>(_onBackToStart);
    on<RoomUpdateArrived>(_onRoomUpdate);
    on<PollTicked>(_onPollTicked);
  }

  String? get _myUserId => _controller?.myBaseIdentity;

  InterpreterErrorKind _kindOf(Object error) =>
      InterpreterException.from(error).kind;

  Future<void> _onStarted(Started event, Emitter<InterpreterState> emit) async {
    _initialJoinCode = event.joinCode;
    emit(const InterpreterLoading());

    InterpreterCatalog catalog;
    try {
      catalog = await repo.catalog();
    } catch (e) {
      // No Choosing has ever been reached yet — there is nothing to fall
      // back to except retrying this same load.
      emit(InterpreterFailure(kind: _kindOf(e)));
      return;
    }

    if (!catalog.enabled) {
      emit(const InterpreterUnavailable());
      return;
    }

    final myLang = await langStore.initial(catalog, appLocale());
    _emitChoosing(
      InterpreterChoosing(
        catalog: catalog,
        myLang: myLang,
        joinCode: event.joinCode,
      ),
      emit,
    );
  }

  Future<void> _onLanguageChosen(
    LanguageChosen event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterChoosing) return;
    await langStore.remember(event.code);
    _emitChoosing(current.copyWith(myLang: event.code), emit);
  }

  Future<void> _onHostPressed(
    HostPressed event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterChoosing) return;
    await _gateOnVoicePrint(
      back: current,
      then: InterpreterPendingAction.host,
      code: null,
      emit: emit,
    );
  }

  Future<void> _onJoinPressed(
    JoinPressed event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterChoosing) return;
    await _gateOnVoicePrint(
      back: current,
      then: InterpreterPendingAction.join,
      code: event.code,
      emit: emit,
    );
  }

  Future<void> _gateOnVoicePrint({
    required InterpreterChoosing back,
    required InterpreterPendingAction then,
    required String? code,
    required Emitter<InterpreterState> emit,
  }) async {
    bool enrolled;
    try {
      enrolled = (await voice.getStatus()).enrolled;
    } catch (e) {
      _emitRepoFailure(e, emit: emit, back: back);
      return;
    }

    if (!enrolled) {
      emit(InterpreterNeedVoicePrint(then: then, code: code));
      return;
    }

    if (then == InterpreterPendingAction.host) {
      await _hostSession(lang: back.myLang, emit: emit, back: back);
    } else {
      await _joinSession(
          code: code!, lang: back.myLang, emit: emit, back: back);
    }
  }

  Future<void> _onVoicePrintResult(
    VoicePrintResult event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterNeedVoicePrint) return;
    final back = _lastChoosing;
    // Defensive: NeedVoicePrint always follows a Choosing.
    if (back == null) return;

    if (!event.ok) {
      _emitChoosing(back, emit);
      return;
    }

    if (current.then == InterpreterPendingAction.host) {
      await _hostSession(lang: back.myLang, emit: emit, back: back);
    } else {
      await _joinSession(
        code: current.code!,
        lang: back.myLang,
        emit: emit,
        back: back,
      );
    }
  }

  Future<void> _hostSession({
    required String lang,
    required Emitter<InterpreterState> emit,
    required InterpreterChoosing back,
  }) async {
    emit(const InterpreterWorking(InterpreterWorkKind.creating));

    HostedSession hosted;
    try {
      hosted = await repo.create(lang);
    } catch (e) {
      if (emit.isDone) return;
      _emitRepoFailure(
        e,
        emit: emit,
        back: back,
        pendingThen: InterpreterPendingAction.host,
      );
      return;
    }

    // The bloc closed while create() was resolving: the session is real on
    // the server, but there is no one left to use it or to show a failure
    // to — release the QR slot and stop here, never touching the room.
    if (emit.isDone) {
      _abandonSession(hosted.sessionId);
      return;
    }

    _isHost = true;
    _sessionId = hosted.sessionId;
    try {
      await _enterRoom(url: livekitUrl(), token: hosted.token, emit: emit);
    } catch (e) {
      await _teardownRoom();
      if (emit.isDone) {
        _abandonSession(hosted.sessionId);
      } else {
        emit(InterpreterFailure(kind: _kindOf(e), back: back));
      }
      return;
    }

    if (emit.isDone) {
      await _teardownRoom();
      _abandonSession(hosted.sessionId);
      return;
    }

    final hosting = InterpreterHosting(
      session: hosted,
      code: hosted.code,
      expiresAt: hosted.expiresAt,
      myLang: lang,
    );
    emit(hosting);

    if (_partnerJoinedBeforeHosting) {
      _partnerJoinedBeforeHosting = false;
      await _hostSeesPartnerJoin(hosting, emit);
    }
  }

  Future<void> _joinSession({
    required String code,
    required String lang,
    required Emitter<InterpreterState> emit,
    required InterpreterChoosing back,
  }) async {
    emit(const InterpreterWorking(InterpreterWorkKind.joining));

    JoinedSession joined;
    try {
      joined = await repo.join(code, lang);
    } catch (e) {
      if (emit.isDone) return;
      _emitRepoFailure(
        e,
        emit: emit,
        back: back,
        pendingThen: InterpreterPendingAction.join,
        pendingCode: code,
      );
      return;
    }

    // The bloc closed while join() was resolving: the single-use code was
    // already consumed and the host's billing session opened, but nobody is
    // left to talk to — ending it now, rather than leaving it to expire on
    // its own, is what stops the host being billed for an empty room.
    if (emit.isDone) {
      _abandonSession(joined.sessionId);
      return;
    }

    _isHost = false;
    _sessionId = joined.sessionId;
    try {
      await _enterRoom(url: livekitUrl(), token: joined.token, emit: emit);
    } catch (e) {
      await _teardownRoom();
      if (emit.isDone) {
        _abandonSession(joined.sessionId);
      } else {
        emit(InterpreterFailure(kind: _kindOf(e), back: back));
      }
      return;
    }

    if (emit.isDone) {
      await _teardownRoom();
      _abandonSession(joined.sessionId);
      return;
    }

    // The join answer carries no `startedAt` (unlike the host's later
    // `GET /interpreter/sessions/:id`) — the guest's own clock is the only
    // option.
    _startedAt = now();
    // The guest only reaches here once already connected to the host, so
    // unlike the host's QR screen there is no code on screen left to blank.
    await device.setNearEarScreenOff(true);
    emit(InterpreterActive(
      isHost: false,
      myLang: lang,
      partner: joined.partner,
      directions: joined.directions,
      captions: CaptionLines(),
      partnerSpeaking: false,
      meSpeaking: false,
      agentPresent: _agentPresentNow,
      connection: InterpreterLinkState.ok,
      micOn: true,
      startedAt: _startedAt!,
      spentPlanck: null,
    ));
    _startPolling();
  }

  Future<void> _hostSeesPartnerJoin(
    InterpreterHosting hosting,
    Emitter<InterpreterState> emit,
  ) async {
    SessionView view;
    try {
      view = await repo.get(hosting.session.sessionId);
    } catch (e) {
      // The room is already connected at this point — leaving it live would
      // strand the host on a mic-open, proximity-locked device with nowhere
      // to go but a second room stacked over this one.
      await _teardownRoom();
      _emitRepoFailure(e, emit: emit);
      return;
    }

    final partner = view.partner;
    final directions = view.directions;
    if (partner == null || directions == null) {
      // Defensive: the backend contract guarantees both once a partner has
      // joined, but a null here must not crash the call via a force-unwrap
      // — fall back to exactly what a failed repo.get() above would have
      // done.
      await _teardownRoom();
      _emitRepoFailure(
        const InterpreterException(InterpreterErrorKind.unknown),
        emit: emit,
      );
      return;
    }

    _startedAt = view.startedAt ?? now();
    // Only now, with a partner actually on the call, is it safe to let the
    // proximity sensor blank the screen — turning it on any earlier would
    // blank the QR the host is still showing.
    await device.setNearEarScreenOff(true);
    emit(InterpreterActive(
      isHost: true,
      myLang: hosting.myLang,
      partner: partner,
      directions: directions,
      captions: CaptionLines(),
      partnerSpeaking: false,
      meSpeaking: false,
      agentPresent: _agentPresentNow,
      connection: InterpreterLinkState.ok,
      micOn: true,
      startedAt: _startedAt!,
      spentPlanck: view.spentPlanck,
    ));
    _startPolling();
  }

  Future<void> _onNewCodePressed(
    NewCodePressed event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterHosting) return;
    try {
      final fresh = await repo.newCode(current.session.sessionId);
      emit(current.copyWith(code: fresh.code, expiresAt: fresh.expiresAt));
    } catch (e) {
      _emitRepoFailure(e, emit: emit);
    }
  }

  Future<void> _onEndPressed(
    EndPressed event,
    Emitter<InterpreterState> emit,
  ) async {
    final sessionId = _sessionId;
    if (sessionId != null) {
      try {
        await repo.end(sessionId);
      } catch (e) {
        // Spec: errors here are logged, not surfaced — the call is being
        // torn down regardless of whether the server confirmed cleanup.
        debugPrint('[InterpreterBloc] repo.end($sessionId) failed: $e');
      }
    }
    await _finish(emit: emit, reason: InterpreterEndReason.hangup);
  }

  Future<void> _onMicToggled(
    MicToggled event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterActive) return;
    await _controller?.setMic(event.on);
    emit(current.copyWith(micOn: event.on));
  }

  Future<void> _onRetryPressed(
    RetryPressed event,
    Emitter<InterpreterState> emit,
  ) =>
      _returnToChoosing(emit);

  Future<void> _onBackToStart(
    BackToStart event,
    Emitter<InterpreterState> emit,
  ) =>
      _returnToChoosing(emit);

  Future<void> _returnToChoosing(Emitter<InterpreterState> emit) async {
    // Idempotent — a no-op whenever the room was already torn down (the
    // common case), but the one thing standing between every path back to
    // the start screen and a room left live behind it.
    await _teardownRoom();
    final current = state;
    final back = current is InterpreterFailure ? current.back : _lastChoosing;
    if (back != null) {
      _emitChoosing(back, emit);
      return;
    }
    // Only reachable when the very first catalog load failed: nothing to go
    // back to except retrying that same load.
    await _onStarted(Started(joinCode: _initialJoinCode), emit);
  }

  Future<void> _onRoomUpdate(
    RoomUpdateArrived event,
    Emitter<InterpreterState> emit,
  ) async {
    switch (event.update) {
      case PartnerJoined(identity: final id):
        _partnerUserId = InterpreterRoomController.baseOf(id);
        final current = state;
        if (current is InterpreterHosting) {
          await _hostSeesPartnerJoin(current, emit);
        } else {
          // Events process concurrently with the create()+room-connect
          // round trip, so this can arrive while the host is still
          // `InterpreterWorking(creating)` (or earlier) — the room's own
          // `ParticipantJoined` replay for an already-present partner can
          // easily win that race. Remembered here and picked back up the
          // moment Hosting itself is emitted, instead of being dropped with
          // the host left waiting on the QR forever.
          _partnerJoinedBeforeHosting = true;
        }
      case PartnerLeft():
        // The backend gives a reconnecting partner 60s before closing the
        // session as `partner_left`; nothing for the UI to do here beyond
        // what the next poll or a room `Closed` will already handle.
        break;
      case AgentJoined():
        _agentPresentNow = true;
        _updateActive(emit, (a) => a.copyWith(agentPresent: true));
      case AgentLeft():
        _agentPresentNow = false;
        _updateActive(emit, (a) => a.copyWith(agentPresent: false));
      case Signal(signal: final signal):
        _applySignal(signal, emit);
      case Connection(state: final connectionState):
        _updateActive(
          emit,
          (a) => a.copyWith(
            connection: connectionState == InterpreterConnectionState.ok
                ? InterpreterLinkState.ok
                : InterpreterLinkState.reconnecting,
          ),
        );
      case Closed():
        await _finishFromClosed(emit);
    }
  }

  void _updateActive(
    Emitter<InterpreterState> emit,
    InterpreterActive Function(InterpreterActive current) update,
  ) {
    final current = state;
    if (current is InterpreterActive) emit(update(current));
  }

  void _applySignal(InterpreterSignal signal, Emitter<InterpreterState> emit) {
    final current = state;
    if (current is! InterpreterActive) return;

    switch (signal) {
      case CaptionSignal():
        // Mutated in place; copyWith() alone bumps the revision so this is
        // still a distinct, deliverable state.
        current.captions.add(signal, now());
        emit(current.copyWith());
      case SpeakingSignal(speaker: final speaker, on: final on):
        final myId = _myUserId;
        emit(current.copyWith(
          meSpeaking: myId != null && speaker == myId ? on : current.meSpeaking,
          partnerSpeaking:
              speaker == _partnerUserId ? on : current.partnerSpeaking,
        ));
      case StatusSignal(state: final s):
        emit(current.copyWith(
            connection: switch (s) {
          StatusState.reconnecting => InterpreterLinkState.reconnecting,
          StatusState.ok => InterpreterLinkState.ok,
          StatusState.failed => InterpreterLinkState.failed,
        }));
    }
  }

  Future<void> _finishFromClosed(Emitter<InterpreterState> emit) async {
    if (state is InterpreterEnded || _controller == null) return;

    SessionView? view;
    final sessionId = _sessionId;
    if (sessionId != null) {
      try {
        view = await repo.get(sessionId);
      } catch (_) {
        view = null;
      }
    }

    await _finish(
      emit: emit,
      reason: view?.endReason,
      spentPlanckOverride: view?.spentPlanck,
    );
  }

  Future<void> _onPollTicked(
    PollTicked event,
    Emitter<InterpreterState> emit,
  ) async {
    final current = state;
    if (current is! InterpreterActive || _pollInFlight) return;
    final sessionId = _sessionId;
    if (sessionId == null) return;

    _pollInFlight = true;
    try {
      final view = await repo.get(sessionId);
      if (view.status == InterpreterStatus.ended) {
        await _finish(
          emit: emit,
          reason: view.endReason,
          spentPlanckOverride: view.spentPlanck,
        );
        return;
      }
      if (current.isHost && view.spentPlanck != null) {
        final latest = state;
        if (latest is InterpreterActive) {
          emit(latest.copyWith(spentPlanck: view.spentPlanck));
        }
      }
    } catch (_) {
      // A transient poll failure just waits for the next tick rather than
      // tearing down an otherwise-healthy call.
    } finally {
      _pollInFlight = false;
    }
  }

  Future<void> _finish({
    required Emitter<InterpreterState> emit,
    InterpreterEndReason? reason,
    String? spentPlanckOverride,
  }) async {
    if (state is InterpreterEnded) return;
    final current = state;
    final spentPlanck = spentPlanckOverride ??
        (current is InterpreterActive ? current.spentPlanck : null);
    final duration = _startedAt == null ? null : now().difference(_startedAt!);
    final isHost = _isHost;

    await _teardownRoom();

    emit(InterpreterEnded(
      reason: reason,
      duration: duration,
      spentPlanck: spentPlanck,
      isHost: isHost,
    ));
  }

  void _emitChoosing(
    InterpreterChoosing choosing,
    Emitter<InterpreterState> emit,
  ) {
    _lastChoosing = choosing;
    emit(choosing);
  }

  /// Centralises what happens to a thrown repo/voice error: a bare
  /// `voice_print_required` reopens the gate when there is a pending
  /// action to resume; everything else — including `network`/`unknown` and
  /// every other backend code — becomes an [InterpreterFailure] pointing
  /// back at the last known [InterpreterChoosing] ([back], or the bloc's own
  /// memory of it when the caller has none at hand).
  void _emitRepoFailure(
    Object error, {
    required Emitter<InterpreterState> emit,
    InterpreterChoosing? back,
    InterpreterPendingAction? pendingThen,
    String? pendingCode,
  }) {
    final kind = _kindOf(error);
    if (kind == InterpreterErrorKind.voicePrintRequired &&
        pendingThen != null) {
      emit(InterpreterNeedVoicePrint(then: pendingThen, code: pendingCode));
      return;
    }
    emit(InterpreterFailure(kind: kind, back: back ?? _lastChoosing));
  }

  Future<void> _enterRoom({
    required String url,
    required String token,
    required Emitter<InterpreterState> emit,
  }) async {
    _tornDown = false;
    await device.enterConversation();
    if (emit.isDone) return;
    await _attachRoom();
    if (emit.isDone) return;
    await _controller!.start(url: url, token: token, micOn: true);
  }

  /// The bloc closed mid-flight after a create/join had already gone
  /// through on the server (whether just the REST call, or the room that
  /// followed it too — [_enterRoom] bails out early on its own checks either
  /// way). Nobody is left to see a failure, but the session is real on the
  /// server, so it still has to be released. Best-effort: there is no one
  /// left to retry for.
  void _abandonSession(String sessionId) {
    repo.end(sessionId).catchError((_) {});
  }

  /// Defensive: under the intended flow nothing is ever attached twice —
  /// [_teardownRoom] always clears [_controller] first — but a stray leftover
  /// controller must not simply be overwritten and leaked (a live mic +
  /// subscription under a reference nothing holds any more).
  Future<void> _attachRoom() async {
    final stale = _controller;
    final staleSub = _roomSub;
    _controller = null;
    _roomSub = null;
    await staleSub?.cancel();
    if (stale != null) {
      try {
        await stale.dispose();
      } catch (_) {
        // Best-effort: already being replaced regardless.
      }
    }

    _controller = InterpreterRoomController(roomFactory());
    _roomSub = _controller!.updates.listen((u) => add(RoomUpdateArrived(u)));
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(pollEvery, (_) => add(const PollTicked()));
  }

  /// Always runs device + controller teardown exactly once per room
  /// attempt, however the call ended (`EndPressed`, the room closing on its
  /// own, a poll detecting `ended`, or the bloc itself closing).
  Future<void> _teardownRoom() async {
    if (_tornDown) return;
    _tornDown = true;

    _pollTimer?.cancel();
    _pollTimer = null;
    await _roomSub?.cancel();
    _roomSub = null;

    final controller = _controller;
    _controller = null;
    await controller?.dispose();
    await device.leaveConversation();

    _sessionId = null;
    _startedAt = null;
    _partnerUserId = null;
    _agentPresentNow = false;
    _partnerJoinedBeforeHosting = false;
    _isHost = false;
  }

  @override
  Future<void> close() async {
    await _teardownRoom();
    return super.close();
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart lib/features/interpreter/presentation/bloc/interpreter_event.dart lib/features/interpreter/presentation/bloc/interpreter_state.dart lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
```

Ожидается: `+193: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart lib/features/interpreter/presentation/bloc/interpreter_event.dart lib/features/interpreter/presentation/bloc/interpreter_state.dart lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
git commit -m "feat(interpreter): BLoC разговора с переводом" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: Тексты

- Все строки — в `app_en.arb` (настоящий шаблон gen-l10n: `template-arb-locale` в `l10n.yaml` не опция и не действует) и в `app_ru.arb`. Сгенерированные `app_localizations*.dart` в этом репозитории коммитятся.
- Тексты ошибок и причин завершения — функции `interpreterErrorText`/`interpreterEndText`, по одному тексту на каждое значение.

**Files:**
- Create: `test/features/interpreter/presentation/widgets/interpreter_texts_test.dart`, `lib/features/interpreter/presentation/widgets/interpreter_texts.dart`
- Modify: `lib/l10n/app_en.arb`, `lib/l10n/app_ru.arb`
- Regenerate: `lib/l10n/app_localizations*.dart` (`flutter gen-l10n`)

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/widgets/interpreter_texts_test.dart` целиком:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_error.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/widgets/interpreter_texts.dart';
import 'package:taler_id_mobile/l10n/app_localizations_en.dart';

void main() {
  final l10n = AppLocalizationsEn();

  group('interpreterErrorText', () {
    test('covers every InterpreterErrorKind with a non-empty, distinct text',
        () {
      final seen = <String>{};
      for (final kind in InterpreterErrorKind.values) {
        final text = interpreterErrorText(l10n, kind);
        expect(text, isNotEmpty, reason: 'no text for $kind');
        // Each kind gets its own wording — a shared fallback for several
        // kinds would be a sign one of them was forgotten in the switch.
        expect(seen.add(text), isTrue, reason: '$kind reuses "$text"');
      }
    });

    test('insufficientFunds text differs from hostInsufficientFunds', () {
      expect(
        interpreterErrorText(l10n, InterpreterErrorKind.insufficientFunds),
        isNot(interpreterErrorText(
            l10n, InterpreterErrorKind.hostInsufficientFunds)),
      );
    });
  });

  group('interpreterEndText', () {
    test(
        'covers every InterpreterEndReason plus null with a non-empty, distinct text',
        () {
      final seen = <String>{};
      final allReasons = <InterpreterEndReason?>[
        null,
        ...InterpreterEndReason.values
      ];
      for (final reason in allReasons) {
        final text = interpreterEndText(l10n, reason);
        expect(text, isNotEmpty, reason: 'no text for $reason');
      }
      // hangup and the null fallback both read "Call ended" by design (a
      // click on End and a reason-less close look the same to the user) —
      // everything else must be distinct from each other.
      for (final reason in InterpreterEndReason.values) {
        if (reason == InterpreterEndReason.hangup) continue;
        final text = interpreterEndText(l10n, reason);
        expect(seen.add(text), isTrue, reason: '$reason reuses "$text"');
      }
    });

    test('null and hangup share the generic "call ended" wording', () {
      expect(
        interpreterEndText(l10n, null),
        interpreterEndText(l10n, InterpreterEndReason.hangup),
      );
    });
  });

  group('interpreterLanguageName', () {
    const languages = [
      InterpreterLanguage(code: 'ru', name: 'Русский'),
      InterpreterLanguage(code: 'en', name: 'English'),
    ];

    test('resolves a known code to its catalog name', () {
      expect(interpreterLanguageName(languages, 'ru'), 'Русский');
    });

    test('falls back to the upper-cased code for an unknown one', () {
      expect(interpreterLanguageName(languages, 'sk'), 'SK');
    });
  });

  group('interpreterFormatDuration', () {
    test('formats minutes and seconds with zero-padded seconds', () {
      expect(interpreterFormatDuration(const Duration(minutes: 4, seconds: 5)),
          '4:05');
    });

    test('clamps a negative duration to 0:00', () {
      expect(interpreterFormatDuration(const Duration(seconds: -5)), '0:00');
    });

    test('zero duration is 0:00', () {
      expect(interpreterFormatDuration(Duration.zero), '0:00');
    });
  });
}
```

Run: `flutter test test/features/interpreter/presentation/widgets/interpreter_texts_test.dart`
Expected: `test/features/interpreter/presentation/widgets/interpreter_texts_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

Патч к `lib/l10n/app_en.arb`:

```diff
--- a/lib/l10n/app_en.arb
+++ b/lib/l10n/app_en.arb
@@ -2023,5 +2023,84 @@
         "type": "String"
       }
     }
-  }
+  },
+
+  "interpreterTitle": "Face-to-face interpreter",
+  "interpreterSpeakLabel": "I speak:",
+  "interpreterStartButton": "Start",
+  "interpreterScanButton": "Scan QR",
+  "interpreterStartHint": "Both of you need a voice print. The host pays per minute.",
+  "interpreterChooseLanguage": "Choose a language",
+  "interpreterSearchLanguage": "Search language",
+  "interpreterShowCode": "Show this code to your partner",
+  "interpreterNewCode": "New code",
+  "interpreterCodeExpiredShort": "Code expired",
+  "interpreterWaitingForPartner": "Waiting for your partner…",
+  "interpreterPartnerSpeaking": "your partner is speaking…",
+  "interpreterPhraseBadge": "phrase-by-phrase translation",
+  "interpreterServerNote": "Translation runs through the server",
+  "interpreterAgentAbsent": "Translation stopped, waiting…",
+  "interpreterReconnecting": "Translation is reconnecting…",
+  "interpreterTranslationFailedBanner": "Translation could not be restored",
+  "interpreterMicButton": "Microphone",
+  "interpreterEndButton": "End",
+  "interpreterSpentAmount": "Spent: {amount} μTAL",
+  "@interpreterSpentAmount": {
+    "placeholders": {
+      "amount": {
+        "type": "String"
+      }
+    }
+  },
+  "interpreterTranslationCaptionLabel": "Translation",
+  "interpreterMyCaptionLabel": "You said",
+  "interpreterEndedTitle": "Call ended",
+  "interpreterDurationLabel": "Duration: {duration}",
+  "@interpreterDurationLabel": {
+    "placeholders": {
+      "duration": {
+        "type": "String"
+      }
+    }
+  },
+  "interpreterDoneButton": "Done",
+  "interpreterAgainButton": "Again",
+  "interpreterEndHangup": "Call ended",
+  "interpreterEndPartnerLeft": "Your partner disconnected",
+  "interpreterEndExpired": "The code expired — nobody joined",
+  "interpreterEndTranslationFailed": "Translation could not recover",
+  "interpreterEndAgentLost": "The interpreter dropped out of the room",
+  "interpreterEndNoFunds": "The host ran out of balance",
+  "interpreterEndMaxDuration": "Call time limit reached",
+  "interpreterEndGeneric": "Call ended",
+  "interpreterUnavailableTitle": "This feature is unavailable right now",
+  "interpreterBackToStartButton": "Back to start",
+  "interpreterLeaveConfirmTitle": "End the call?",
+  "interpreterLeaveConfirmBody": "Leaving will end the call for both of you.",
+  "interpreterAskNewCodeHint": "Ask the host to show a new code",
+  "interpreterCreatingLabel": "Creating the call…",
+  "interpreterJoiningLabel": "Joining…",
+  "interpreterScanInstruction": "Point camera at QR code",
+  "interpreterPartnerFallback": "Your partner",
+  "interpreterErrInterpreterDisabled": "Face-to-face interpreter is unavailable right now",
+  "interpreterErrUnsupportedLanguage": "This language is not supported yet",
+  "interpreterErrSameLanguage": "You both speak the same language — no translation needed",
+  "interpreterErrVoicePrintRequired": "A voice print is required",
+  "interpreterErrHostVoicePrintRequired": "The host has no voice print yet",
+  "interpreterErrAlreadyInSession": "You already have an active interpreter call",
+  "interpreterErrSameVoicePrint": "Your voice is too similar to your partner's — the check failed",
+  "interpreterErrOwnCode": "That is your own code",
+  "interpreterErrCodeUsed": "This code has already been used",
+  "interpreterErrNotWaiting": "This session is no longer waiting for a guest",
+  "interpreterErrInsufficientFunds": "Insufficient balance",
+  "interpreterErrHostInsufficientFunds": "The host does not have enough balance",
+  "interpreterErrFeatureDisabled": "The feature is disabled in settings",
+  "interpreterErrHostFeatureDisabled": "The feature is disabled for the host",
+  "interpreterErrCodeNotFound": "Code not found",
+  "interpreterErrSessionNotFound": "Session not found",
+  "interpreterErrCodeExpired": "The code has expired",
+  "interpreterErrTooManyAttempts": "Too many attempts, try again later",
+  "interpreterErrInterpreterUnavailable": "The interpreter is temporarily unavailable, try again later",
+  "interpreterErrNetwork": "No connection to the server",
+  "interpreterErrUnknown": "Something went wrong"
 }
```

Патч к `lib/l10n/app_ru.arb`:

```diff
--- a/lib/l10n/app_ru.arb
+++ b/lib/l10n/app_ru.arb
@@ -2016,5 +2016,84 @@
         "type": "String"
       }
     }
-  }
+  },
+
+  "interpreterTitle": "Разговор с переводом",
+  "interpreterSpeakLabel": "Я говорю на:",
+  "interpreterStartButton": "Начать",
+  "interpreterScanButton": "Сканировать QR",
+  "interpreterStartHint": "Нужен образец голоса — ваш и собеседника. Платит тот, кто начал разговор.",
+  "interpreterChooseLanguage": "Выберите язык",
+  "interpreterSearchLanguage": "Поиск языка",
+  "interpreterShowCode": "Покажите код собеседнику",
+  "interpreterNewCode": "Новый код",
+  "interpreterCodeExpiredShort": "Код истёк",
+  "interpreterWaitingForPartner": "Ждём собеседника…",
+  "interpreterPartnerSpeaking": "собеседник говорит…",
+  "interpreterPhraseBadge": "перевод по фразам",
+  "interpreterServerNote": "Перевод идёт через сервер",
+  "interpreterAgentAbsent": "Перевод прервался, ждём…",
+  "interpreterReconnecting": "Перевод восстанавливается…",
+  "interpreterTranslationFailedBanner": "Перевод не восстановился",
+  "interpreterMicButton": "Микрофон",
+  "interpreterEndButton": "Завершить",
+  "interpreterSpentAmount": "Потрачено: {amount} μTAL",
+  "@interpreterSpentAmount": {
+    "placeholders": {
+      "amount": {
+        "type": "String"
+      }
+    }
+  },
+  "interpreterTranslationCaptionLabel": "Перевод",
+  "interpreterMyCaptionLabel": "Вы сказали",
+  "interpreterEndedTitle": "Разговор завершён",
+  "interpreterDurationLabel": "Длительность: {duration}",
+  "@interpreterDurationLabel": {
+    "placeholders": {
+      "duration": {
+        "type": "String"
+      }
+    }
+  },
+  "interpreterDoneButton": "Готово",
+  "interpreterAgainButton": "Ещё раз",
+  "interpreterEndHangup": "Разговор завершён",
+  "interpreterEndPartnerLeft": "Собеседник отключился",
+  "interpreterEndExpired": "Код истёк — никто не подключился",
+  "interpreterEndTranslationFailed": "Перевод не восстановился",
+  "interpreterEndAgentLost": "Переводчик пропал из комнаты",
+  "interpreterEndNoFunds": "У организатора закончились средства",
+  "interpreterEndMaxDuration": "Достигнут лимит разговора",
+  "interpreterEndGeneric": "Разговор завершён",
+  "interpreterUnavailableTitle": "Функция сейчас недоступна",
+  "interpreterBackToStartButton": "На старт",
+  "interpreterLeaveConfirmTitle": "Завершить разговор?",
+  "interpreterLeaveConfirmBody": "Если вы уйдёте, разговор с переводом завершится для обоих.",
+  "interpreterAskNewCodeHint": "Попросите организатора показать новый код",
+  "interpreterCreatingLabel": "Создаём разговор…",
+  "interpreterJoiningLabel": "Подключаемся…",
+  "interpreterScanInstruction": "Наведите камеру на QR код",
+  "interpreterPartnerFallback": "Собеседник",
+  "interpreterErrInterpreterDisabled": "Разговор с переводом сейчас недоступен",
+  "interpreterErrUnsupportedLanguage": "Этот язык пока не поддерживается",
+  "interpreterErrSameLanguage": "Вы говорите на одном языке — перевод не нужен",
+  "interpreterErrVoicePrintRequired": "Нужен образец голоса",
+  "interpreterErrHostVoicePrintRequired": "У организатора нет образца голоса",
+  "interpreterErrAlreadyInSession": "У вас уже идёт разговор с переводом",
+  "interpreterErrSameVoicePrint": "Ваш голос слишком похож на голос собеседника, проверка не пройдена",
+  "interpreterErrOwnCode": "Это ваш собственный код",
+  "interpreterErrCodeUsed": "Код уже использован",
+  "interpreterErrNotWaiting": "Эта сессия уже не ждёт подключения",
+  "interpreterErrInsufficientFunds": "Недостаточно средств на балансе",
+  "interpreterErrHostInsufficientFunds": "У организатора не хватает средств",
+  "interpreterErrFeatureDisabled": "Функция отключена в настройках",
+  "interpreterErrHostFeatureDisabled": "Функция отключена у организатора",
+  "interpreterErrCodeNotFound": "Код не найден",
+  "interpreterErrSessionNotFound": "Сессия не найдена",
+  "interpreterErrCodeExpired": "Код истёк",
+  "interpreterErrTooManyAttempts": "Слишком много попыток, попробуйте позже",
+  "interpreterErrInterpreterUnavailable": "Переводчик временно недоступен, попробуйте позже",
+  "interpreterErrNetwork": "Нет соединения с сервером",
+  "interpreterErrUnknown": "Что-то пошло не так"
 }
```

`lib/features/interpreter/presentation/widgets/interpreter_texts.dart` целиком:

```dart
import '../../../../l10n/app_localizations.dart';
import '../../domain/interpreter_error.dart';
import '../../domain/interpreter_models.dart';

/// User-facing text for every [InterpreterErrorKind]. The caller decides on
/// top of this which kinds additionally get a call-to-action (see the
/// failure view in `interpreter_screen.dart`): `insufficientFunds` → "Пополнить"
/// (push the wallet route), `codeExpired` → an extra "ask for a new code"
/// hint, `voicePrintRequired` never reaches here (the bloc reopens the
/// enrollment gate instead) — everything else just falls back to "back to
/// start".
String interpreterErrorText(AppLocalizations l10n, InterpreterErrorKind kind) {
  switch (kind) {
    case InterpreterErrorKind.interpreterDisabled:
      return l10n.interpreterErrInterpreterDisabled;
    case InterpreterErrorKind.unsupportedLanguage:
      return l10n.interpreterErrUnsupportedLanguage;
    case InterpreterErrorKind.sameLanguage:
      return l10n.interpreterErrSameLanguage;
    case InterpreterErrorKind.voicePrintRequired:
      return l10n.interpreterErrVoicePrintRequired;
    case InterpreterErrorKind.hostVoicePrintRequired:
      return l10n.interpreterErrHostVoicePrintRequired;
    case InterpreterErrorKind.alreadyInSession:
      return l10n.interpreterErrAlreadyInSession;
    case InterpreterErrorKind.sameVoicePrint:
      return l10n.interpreterErrSameVoicePrint;
    case InterpreterErrorKind.ownCode:
      return l10n.interpreterErrOwnCode;
    case InterpreterErrorKind.codeUsed:
      return l10n.interpreterErrCodeUsed;
    case InterpreterErrorKind.notWaiting:
      return l10n.interpreterErrNotWaiting;
    case InterpreterErrorKind.insufficientFunds:
      return l10n.interpreterErrInsufficientFunds;
    case InterpreterErrorKind.hostInsufficientFunds:
      return l10n.interpreterErrHostInsufficientFunds;
    case InterpreterErrorKind.featureDisabled:
      return l10n.interpreterErrFeatureDisabled;
    case InterpreterErrorKind.hostFeatureDisabled:
      return l10n.interpreterErrHostFeatureDisabled;
    case InterpreterErrorKind.codeNotFound:
      return l10n.interpreterErrCodeNotFound;
    case InterpreterErrorKind.sessionNotFound:
      return l10n.interpreterErrSessionNotFound;
    case InterpreterErrorKind.codeExpired:
      return l10n.interpreterErrCodeExpired;
    case InterpreterErrorKind.tooManyAttempts:
      return l10n.interpreterErrTooManyAttempts;
    case InterpreterErrorKind.interpreterUnavailable:
      return l10n.interpreterErrInterpreterUnavailable;
    case InterpreterErrorKind.network:
      return l10n.interpreterErrNetwork;
    case InterpreterErrorKind.unknown:
      return l10n.interpreterErrUnknown;
  }
}

/// User-facing text for how a call ended. `null` is the generic fallback —
/// an end reason the server didn't send or didn't name (see
/// `interpreterEndReasonFromJson`'s doc on why an unrecognised value maps to
/// `null` rather than guessing).
String interpreterEndText(AppLocalizations l10n, InterpreterEndReason? reason) {
  switch (reason) {
    case null:
      return l10n.interpreterEndGeneric;
    case InterpreterEndReason.hangup:
      return l10n.interpreterEndHangup;
    case InterpreterEndReason.partnerLeft:
      return l10n.interpreterEndPartnerLeft;
    case InterpreterEndReason.expired:
      return l10n.interpreterEndExpired;
    case InterpreterEndReason.translationFailed:
      return l10n.interpreterEndTranslationFailed;
    case InterpreterEndReason.agentLost:
      return l10n.interpreterEndAgentLost;
    case InterpreterEndReason.noFunds:
      return l10n.interpreterEndNoFunds;
    case InterpreterEndReason.maxDuration:
      return l10n.interpreterEndMaxDuration;
  }
}

/// Display name for a language code, resolved against the loaded catalog.
/// Falls back to the upper-cased code itself for one a caller passes that
/// isn't in [languages] — a partner's reported language is always one of
/// the 81 the backend knows, but defensive here is free.
String interpreterLanguageName(
    List<InterpreterLanguage> languages, String code) {
  for (final lang in languages) {
    if (lang.code == code) return lang.name;
  }
  return code.toUpperCase();
}

/// `mm:ss` rendering of a non-negative [duration], used by the QR
/// countdown, the session timer and the ended screen. Negative durations
/// (already elapsed) clamp to `0:00` rather than printing a minus sign.
String interpreterFormatDuration(Duration duration) {
  final clamped = duration.isNegative ? Duration.zero : duration;
  final minutes = clamped.inMinutes;
  final seconds = clamped.inSeconds.remainder(60);
  return '$minutes:${seconds.toString().padLeft(2, '0')}';
}
```

Затем сгенерировать локализации:

```bash
flutter gen-l10n
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/presentation/widgets/interpreter_texts_test.dart lib/features/interpreter/presentation/widgets/interpreter_texts.dart
```

Ожидается: `+202: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/widgets/interpreter_texts_test.dart lib/l10n/app_en.arb lib/l10n/app_ru.arb lib/features/interpreter/presentation/widgets/interpreter_texts.dart lib/l10n/app_localizations*.dart
git commit -m "feat(interpreter): тексты разговора с переводом (ru, en)" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: Старт и выбор языка

- «Я говорю на: <язык> ▾», «Начать», «Сканировать QR» и короткая пометка: образец голоса нужен обоим, платит тот, кто начал. Выбор языка — шторка с поиском, как в переводчике звонков.

**Files:**
- Create: `test/features/interpreter/presentation/widgets/start_view_test.dart`, `lib/features/interpreter/presentation/widgets/start_view.dart`, `lib/features/interpreter/presentation/widgets/language_picker_sheet.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/widgets/start_view_test.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/core/theme/app_theme.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/widgets/start_view.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';

const _catalog = InterpreterCatalog(
  enabled: true,
  languages: [
    InterpreterLanguage(code: 'ru', name: 'Русский'),
    InterpreterLanguage(code: 'en', name: 'English'),
  ],
);

Widget _wrap(Widget child) => MaterialApp(
      theme: AppTheme.dark,
      locale: const Locale('en'),
      supportedLocales: const [Locale('en')],
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      home: Scaffold(body: child),
    );

void main() {
  testWidgets('shows "I speak: <language>" for the current selection',
      (tester) async {
    await tester.pumpWidget(_wrap(StartView(
      catalog: _catalog,
      myLang: 'ru',
      onLanguageChosen: (_) {},
      onStart: () {},
      onScan: () {},
    )));

    expect(find.text('I speak: Русский'), findsOneWidget);
  });

  testWidgets('tapping "Start" fires onStart', (tester) async {
    var started = false;
    await tester.pumpWidget(_wrap(StartView(
      catalog: _catalog,
      myLang: 'ru',
      onLanguageChosen: (_) {},
      onStart: () => started = true,
      onScan: () {},
    )));

    await tester.tap(find.text('Start'));
    await tester.pump();

    expect(started, isTrue);
  });

  testWidgets('tapping "Scan QR" fires onScan', (tester) async {
    var scanned = false;
    await tester.pumpWidget(_wrap(StartView(
      catalog: _catalog,
      myLang: 'ru',
      onLanguageChosen: (_) {},
      onStart: () {},
      onScan: () => scanned = true,
    )));

    await tester.tap(find.text('Scan QR'));
    await tester.pump();

    expect(scanned, isTrue);
  });

  testWidgets(
      'tapping the language row opens a picker; picking a language calls onLanguageChosen',
      (tester) async {
    String? chosen;
    await tester.pumpWidget(_wrap(StartView(
      catalog: _catalog,
      myLang: 'ru',
      onLanguageChosen: (code) => chosen = code,
      onStart: () {},
      onScan: () {},
    )));

    await tester.tap(find.text('I speak: Русский'));
    await tester.pumpAndSettle();

    expect(find.text('English'), findsOneWidget);
    await tester.tap(find.text('English'));
    await tester.pumpAndSettle();

    expect(chosen, 'en');
  });

  testWidgets('shows the "both need a voice print, host pays" hint',
      (tester) async {
    await tester.pumpWidget(_wrap(StartView(
      catalog: _catalog,
      myLang: 'ru',
      onLanguageChosen: (_) {},
      onStart: () {},
      onScan: () {},
    )));

    expect(
      find.text('Both of you need a voice print. The host pays per minute.'),
      findsOneWidget,
    );
  });
}
```

Run: `flutter test test/features/interpreter/presentation/widgets/start_view_test.dart`
Expected: `test/features/interpreter/presentation/widgets/start_view_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/presentation/widgets/start_view.dart` целиком:

```dart
import 'package:flutter/material.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../core/theme/widgets.dart';
import '../../../../l10n/app_localizations.dart';
import '../../domain/interpreter_models.dart';
import 'interpreter_texts.dart';
import 'language_picker_sheet.dart';

/// Pre-session screen: pick a language, then either host a new call or scan
/// a partner's QR code. [joinCode] is purely informational here — the
/// screen that owns the bloc is the one that resumes a join once the
/// language is picked; this view doesn't act on it.
class StartView extends StatelessWidget {
  final InterpreterCatalog catalog;
  final String myLang;
  final ValueChanged<String> onLanguageChosen;
  final VoidCallback onStart;
  final VoidCallback onScan;

  const StartView({
    super.key,
    required this.catalog,
    required this.myLang,
    required this.onLanguageChosen,
    required this.onStart,
    required this.onScan,
  });

  Future<void> _openPicker(BuildContext context) async {
    final chosen = await showLanguagePickerSheet(
      context: context,
      languages: catalog.languages,
      selected: myLang,
    );
    if (chosen != null) onLanguageChosen(chosen);
  }

  @override
  Widget build(BuildContext context) {
    final colors = AppColors.of(context);
    final l10n = AppLocalizations.of(context)!;
    final langName = interpreterLanguageName(catalog.languages, myLang);

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            GestureDetector(
              onTap: () => _openPicker(context),
              child: AppCard(
                child: Row(
                  children: [
                    Icon(Icons.translate_rounded, color: colors.primary),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        '${l10n.interpreterSpeakLabel} $langName',
                        style: TextStyle(
                          color: colors.textPrimary,
                          fontSize: 15,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                    Icon(Icons.arrow_drop_down_rounded,
                        color: colors.textSecondary),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 28),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton(
                onPressed: onStart,
                child: Text(l10n.interpreterStartButton),
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: OutlinedButton.icon(
                onPressed: onScan,
                icon: const Icon(Icons.qr_code_scanner_rounded),
                label: Text(l10n.interpreterScanButton),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              l10n.interpreterStartHint,
              textAlign: TextAlign.center,
              style: TextStyle(color: colors.textSecondary, fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}
```

`lib/features/interpreter/presentation/widgets/language_picker_sheet.dart` целиком:

```dart
import 'package:flutter/material.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../l10n/app_localizations.dart';
import '../../domain/interpreter_models.dart';

/// Searchable language picker, the interpreter equivalent of
/// `voice_call_screen.dart`'s `_showLangPicker`. Returns the chosen code, or
/// `null` if the sheet was dismissed without a choice.
Future<String?> showLanguagePickerSheet({
  required BuildContext context,
  required List<InterpreterLanguage> languages,
  required String selected,
}) {
  final colors = AppColors.of(context);
  final l10n = AppLocalizations.of(context)!;
  var query = '';

  return showModalBottomSheet<String>(
    context: context,
    backgroundColor: colors.card,
    isScrollControlled: true,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
    ),
    builder: (_) => StatefulBuilder(
      builder: (ctx, setModalState) {
        final sorted = [...languages]..sort((a, b) => a.name.compareTo(b.name));
        final filtered = query.isEmpty
            ? sorted
            : sorted
                .where((lang) =>
                    lang.name.toLowerCase().contains(query.toLowerCase()) ||
                    lang.code.toLowerCase().contains(query.toLowerCase()))
                .toList();
        return SafeArea(
          child: DraggableScrollableSheet(
            initialChildSize: 0.7,
            minChildSize: 0.4,
            maxChildSize: 0.9,
            expand: false,
            builder: (_, scrollController) => Column(
              children: [
                const SizedBox(height: 12),
                Container(
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: colors.border,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  l10n.interpreterChooseLanguage,
                  style: TextStyle(
                    color: colors.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: TextField(
                    autofocus: false,
                    style: TextStyle(color: colors.textPrimary, fontSize: 15),
                    decoration: InputDecoration(
                      hintText: l10n.interpreterSearchLanguage,
                      hintStyle: TextStyle(color: colors.textSecondary),
                      prefixIcon:
                          Icon(Icons.search, color: colors.textSecondary),
                      filled: true,
                      fillColor: colors.surface,
                      contentPadding: const EdgeInsets.symmetric(
                          horizontal: 14, vertical: 10),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                        borderSide: BorderSide.none,
                      ),
                    ),
                    onChanged: (v) => setModalState(() => query = v),
                  ),
                ),
                const SizedBox(height: 8),
                Expanded(
                  child: ListView(
                    controller: scrollController,
                    children: [
                      ...filtered.map((lang) => ListTile(
                            leading: Icon(
                              Icons.language_rounded,
                              color: lang.code == selected
                                  ? colors.primary
                                  : colors.textSecondary,
                            ),
                            title: Text(
                              lang.name,
                              style: TextStyle(
                                color: lang.code == selected
                                    ? colors.primary
                                    : colors.textPrimary,
                                fontWeight: lang.code == selected
                                    ? FontWeight.w600
                                    : FontWeight.normal,
                              ),
                            ),
                            trailing: lang.code == selected
                                ? Icon(Icons.check_rounded,
                                    color: colors.primary)
                                : null,
                            onTap: () => Navigator.pop(ctx, lang.code),
                          )),
                      const SizedBox(height: 8),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    ),
  );
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/presentation/widgets/start_view_test.dart lib/features/interpreter/presentation/widgets/start_view.dart lib/features/interpreter/presentation/widgets/language_picker_sheet.dart
```

Ожидается: `+207: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/widgets/start_view_test.dart lib/features/interpreter/presentation/widgets/start_view.dart lib/features/interpreter/presentation/widgets/language_picker_sheet.dart
git commit -m "feat(interpreter): экран старта и выбор языка" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 17: QR и сканер

- Крупный QR на белом поле, обратный отсчёт 5 минут, «Новый код»; истёк — «Код истёк», кнопка остаётся. Сканер принимает только ссылку разговора и возвращает код.

**Files:**
- Create: `test/features/interpreter/presentation/widgets/qr_view_test.dart`, `lib/features/interpreter/presentation/widgets/qr_view.dart`, `lib/features/interpreter/presentation/widgets/scanner_screen.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/widgets/qr_view_test.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:taler_id_mobile/core/theme/app_theme.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/widgets/qr_view.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';

Widget _wrap(Widget child) => MaterialApp(
      theme: AppTheme.dark,
      locale: const Locale('en'),
      supportedLocales: const [Locale('en')],
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      home: Scaffold(body: child),
    );

void main() {
  final fixedNow = DateTime(2026, 11, 1, 12, 0, 0);

  testWidgets('renders the QR of the interp link and the show-code text',
      (tester) async {
    await tester.pumpWidget(_wrap(QrView(
      code: 'ABCD1234',
      expiresAt: fixedNow.add(const Duration(minutes: 5)),
      onNewCode: () {},
      now: () => fixedNow,
    )));
    await tester.pump();

    expect(find.text('Show this code to your partner'), findsOneWidget);
    // QrImageView keeps the data it was built with private — a render
    // smoke-check is all that's observable from outside; `interpreterLink`
    // itself (the `talerid://interp/<code>` format) is covered by
    // `interpreter_code_test.dart`.
    expect(find.byType(QrImageView), findsOneWidget);
  });

  testWidgets('shows a live mm:ss countdown from expiresAt', (tester) async {
    await tester.pumpWidget(_wrap(QrView(
      code: 'ABCD1234',
      expiresAt: fixedNow.add(const Duration(minutes: 4, seconds: 32)),
      onNewCode: () {},
      now: () => fixedNow,
    )));
    await tester.pump();

    expect(find.text('4:32'), findsOneWidget);
  });

  testWidgets('shows "Code expired" once expiresAt is in the past',
      (tester) async {
    await tester.pumpWidget(_wrap(QrView(
      code: 'ABCD1234',
      expiresAt: fixedNow.subtract(const Duration(seconds: 1)),
      onNewCode: () {},
      now: () => fixedNow,
    )));
    await tester.pump();

    expect(find.text('Code expired'), findsOneWidget);
    // The new-code button stays available after expiry — that's the only
    // way out of an expired code.
    expect(find.text('New code'), findsOneWidget);
  });

  testWidgets('tapping "New code" fires onNewCode', (tester) async {
    var pressed = false;
    await tester.pumpWidget(_wrap(QrView(
      code: 'ABCD1234',
      expiresAt: fixedNow.add(const Duration(minutes: 5)),
      onNewCode: () => pressed = true,
      now: () => fixedNow,
    )));
    await tester.pump();

    await tester.tap(find.text('New code'));
    await tester.pump();

    expect(pressed, isTrue);
  });
}
```

Run: `flutter test test/features/interpreter/presentation/widgets/qr_view_test.dart`
Expected: `test/features/interpreter/presentation/widgets/qr_view_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/presentation/widgets/qr_view.dart` целиком:

```dart
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../l10n/app_localizations.dart';
import '../../domain/interpreter_code.dart';
import 'interpreter_texts.dart';

/// Host-side waiting screen: a QR of `talerid://interp/<code>` plus a
/// 5-minute countdown to the code's `expiresAt`. Ticks once a second so the
/// countdown and the "expired" swap happen live without the bloc re-polling
/// anything — the code's lifetime is entirely client-computable from
/// [expiresAt].
class QrView extends StatefulWidget {
  final String code;
  final DateTime expiresAt;
  final VoidCallback onNewCode;

  /// Injectable clock for deterministic tests; defaults to the wall clock.
  final DateTime Function() now;

  const QrView({
    super.key,
    required this.code,
    required this.expiresAt,
    required this.onNewCode,
    this.now = DateTime.now,
  });

  @override
  State<QrView> createState() => _QrViewState();
}

class _QrViewState extends State<QrView> {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colors = AppColors.of(context);
    final l10n = AppLocalizations.of(context)!;
    final remaining = widget.expiresAt.difference(widget.now());
    final expired = remaining <= Duration.zero;

    return SafeArea(
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                l10n.interpreterShowCode,
                style: TextStyle(
                  color: colors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 20),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: QrImageView(
                  data: interpreterLink(widget.code),
                  version: QrVersions.auto,
                  size: 220,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 20),
              Text(
                expired
                    ? l10n.interpreterCodeExpiredShort
                    : interpreterFormatDuration(remaining),
                style: TextStyle(
                  color: expired ? colors.error : colors.textSecondary,
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                l10n.interpreterWaitingForPartner,
                style: TextStyle(color: colors.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                height: 48,
                child: OutlinedButton(
                  onPressed: widget.onNewCode,
                  child: Text(l10n.interpreterNewCode),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

`lib/features/interpreter/presentation/widgets/scanner_screen.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../../../l10n/app_localizations.dart';
import '../../domain/interpreter_code.dart';

/// QR scanner for joining a session. Pops with the extracted code as soon as
/// one barcode decodes to a `talerid://interp/<code>` link; every other
/// barcode (a user QR, a random link) is silently ignored so scanning the
/// wrong code just keeps the camera open instead of erroring out.
class InterpreterScannerScreen extends StatefulWidget {
  const InterpreterScannerScreen({super.key});

  @override
  State<InterpreterScannerScreen> createState() =>
      _InterpreterScannerScreenState();
}

class _InterpreterScannerScreenState extends State<InterpreterScannerScreen> {
  final _controller = MobileScannerController();
  bool _handled = false;

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw == null) continue;
      final code = codeFromScan(raw);
      if (code != null) {
        _handled = true;
        Navigator.of(context).pop(code);
        return;
      }
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        foregroundColor: Colors.white,
        title: Text(l10n.interpreterScanButton),
        leading: IconButton(
          icon: const Icon(Icons.close_rounded),
          onPressed: () => Navigator.of(context).pop(),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.flash_on_rounded),
            onPressed: () => _controller.toggleTorch(),
          ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(controller: _controller, onDetect: _onDetect),
          Center(
            child: Container(
              width: 240,
              height: 240,
              decoration: BoxDecoration(
                border: Border.all(color: Colors.white70, width: 2),
                borderRadius: BorderRadius.circular(16),
              ),
            ),
          ),
          Positioned(
            bottom: 48,
            left: 0,
            right: 0,
            child: Center(
              child: Text(
                l10n.interpreterScanInstruction,
                style: const TextStyle(color: Colors.white70, fontSize: 14),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/presentation/widgets/qr_view_test.dart lib/features/interpreter/presentation/widgets/qr_view.dart lib/features/interpreter/presentation/widgets/scanner_screen.dart
```

Ожидается: `+211: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/widgets/qr_view_test.dart lib/features/interpreter/presentation/widgets/qr_view.dart lib/features/interpreter/presentation/widgets/scanner_screen.dart
git commit -m "feat(interpreter): QR с обратным отсчётом и сканер" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: Разговор и итог

- Имя и язык собеседника, кто говорит, «собеседник говорит…», субтитры (перевод собеседника и своя распознанная речь), у хоста — таймер и потраченное, «перевод по фразам», «Перевод идёт через сервер», баннеры «перевод прервался» и «восстанавливается», «Микрофон» и «Завершить». Итог — причина, длительность, у хоста сумма.

**Files:**
- Create: `test/features/interpreter/presentation/widgets/session_view_test.dart`, `test/features/interpreter/presentation/widgets/ended_view_test.dart`, `lib/features/interpreter/presentation/widgets/session_view.dart`, `lib/features/interpreter/presentation/widgets/ended_view.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/widgets/session_view_test.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/core/theme/app_theme.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/widgets/session_view.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_state.dart' show InterpreterLinkState;
import 'package:taler_id_mobile/features/interpreter/room/caption_lines.dart';
import 'package:taler_id_mobile/features/interpreter/room/interpreter_signal.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';

const _partner = InterpreterPartner(firstName: 'Alice', lang: 'en');
const _languages = [InterpreterLanguage(code: 'en', name: 'English')];

Widget _wrap(Widget child) => MaterialApp(
      theme: AppTheme.dark,
      locale: const Locale('en'),
      supportedLocales: const [Locale('en')],
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      home: Scaffold(body: child),
    );

/// Like [_wrap], but pins the test surface to [width] logical pixels (via
/// `tester.view`, the only thing that actually narrows the layout — a
/// `SizedBox` nested under `MaterialApp.builder` can't shrink below the
/// ambient (tight) window constraint) and scales text by [textScale].
Future<void> _pumpAtWidth(
  WidgetTester tester,
  Widget child, {
  required double width,
  double textScale = 1.0,
}) async {
  tester.view.physicalSize = Size(width, 800);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  await tester.pumpWidget(MaterialApp(
    theme: AppTheme.dark,
    locale: const Locale('en'),
    supportedLocales: const [Locale('en')],
    localizationsDelegates: const [
      AppLocalizations.delegate,
      GlobalMaterialLocalizations.delegate,
      GlobalWidgetsLocalizations.delegate,
      GlobalCupertinoLocalizations.delegate,
    ],
    builder: (context, navigator) => MediaQuery(
      data: MediaQuery.of(context)
          .copyWith(textScaler: TextScaler.linear(textScale)),
      child: navigator!,
    ),
    home: Scaffold(body: child),
  ));
}

InterpreterSessionView _buildView({
  bool isHost = false,
  InterpreterEngine toMe = InterpreterEngine.simultaneous,
  bool partnerSpeaking = false,
  bool agentPresent = true,
  InterpreterLinkState connection = InterpreterLinkState.ok,
  bool micOn = true,
  String? spentPlanck,
  CaptionLines? captions,
  ValueChanged<bool>? onMicToggle,
  VoidCallback? onEnd,
  DateTime? now,
}) {
  final startedAt = DateTime(2026, 11, 1, 12, 0, 0);
  return InterpreterSessionView(
    isHost: isHost,
    partner: _partner,
    directions: InterpreterDirections(
        toMe: toMe, fromMe: InterpreterEngine.simultaneous),
    captions: captions ?? CaptionLines(),
    partnerSpeaking: partnerSpeaking,
    meSpeaking: false,
    agentPresent: agentPresent,
    connection: connection,
    micOn: micOn,
    startedAt: startedAt,
    spentPlanck: spentPlanck,
    languages: _languages,
    onMicToggle: onMicToggle ?? (_) {},
    onEnd: onEnd ?? () {},
    now: () => now ?? startedAt.add(const Duration(minutes: 1, seconds: 5)),
  );
}

void main() {
  testWidgets('shows partner name and language', (tester) async {
    await tester.pumpWidget(_wrap(_buildView()));
    await tester.pump();

    expect(find.text('Alice'), findsOneWidget);
    expect(find.text('English'), findsOneWidget);
  });

  testWidgets('shows "partner is speaking" only while partnerSpeaking is true',
      (tester) async {
    await tester.pumpWidget(_wrap(_buildView(partnerSpeaking: true)));
    await tester.pump();
    expect(find.text('your partner is speaking…'), findsOneWidget);

    await tester.pumpWidget(_wrap(_buildView(partnerSpeaking: false)));
    await tester.pump();
    expect(find.text('your partner is speaking…'), findsNothing);
  });

  testWidgets('shows the phrase badge only when directions.toMe is phrase',
      (tester) async {
    await tester.pumpWidget(_wrap(_buildView(toMe: InterpreterEngine.phrase)));
    await tester.pump();
    expect(find.text('phrase-by-phrase translation'), findsOneWidget);

    await tester
        .pumpWidget(_wrap(_buildView(toMe: InterpreterEngine.simultaneous)));
    await tester.pump();
    expect(find.text('phrase-by-phrase translation'), findsNothing);
  });

  testWidgets('always shows the "runs through the server" note',
      (tester) async {
    await tester.pumpWidget(_wrap(_buildView()));
    await tester.pump();
    expect(find.text('Translation runs through the server'), findsOneWidget);
  });

  testWidgets(
      'host sees the elapsed timer and the spent amount; guest sees neither',
      (tester) async {
    await tester
        .pumpWidget(_wrap(_buildView(isHost: true, spentPlanck: '12000000')));
    await tester.pump();
    expect(find.text('1:05'), findsOneWidget);
    expect(find.text('Spent: 12 μTAL'), findsOneWidget);

    await tester
        .pumpWidget(_wrap(_buildView(isHost: false, spentPlanck: '12000000')));
    await tester.pump();
    expect(find.text('1:05'), findsNothing);
    expect(find.text('Spent: 12 μTAL'), findsNothing);
  });

  testWidgets('shows the agent-absent banner when the agent is not present',
      (tester) async {
    await tester.pumpWidget(_wrap(_buildView(agentPresent: false)));
    await tester.pump();
    expect(find.text('Translation stopped, waiting…'), findsOneWidget);
  });

  testWidgets('shows the reconnecting banner when the link is reconnecting',
      (tester) async {
    await tester.pumpWidget(
        _wrap(_buildView(connection: InterpreterLinkState.reconnecting)));
    await tester.pump();
    expect(find.text('Translation is reconnecting…'), findsOneWidget);
  });

  testWidgets('no trouble banner when the agent is present and the link is ok',
      (tester) async {
    await tester.pumpWidget(_wrap(_buildView()));
    await tester.pump();
    expect(find.text('Translation stopped, waiting…'), findsNothing);
    expect(find.text('Translation is reconnecting…'), findsNothing);
  });

  testWidgets(
      'shows its own distinct banner text when the link has failed, not the '
      'agent-absent text', (tester) async {
    await tester
        .pumpWidget(_wrap(_buildView(connection: InterpreterLinkState.failed)));
    await tester.pump();
    expect(find.text('Translation could not be restored'), findsOneWidget);
    expect(find.text('Translation stopped, waiting…'), findsNothing);
  });

  testWidgets(
      'the mic/end buttons share the row width at a large text scale on a '
      'narrow screen without overflowing', (tester) async {
    // The old fixed `SizedBox(width: 150)` pair left 320 - (150*2+16) = 4px
    // of margin on an iPhone-SE-class 320px-wide screen — razor-thin, and a
    // `RenderFlex overflowed` exception reproduces outright at 300px (e.g. a
    // notched device's safe-area insets eating into the usable width).
    // `Expanded` removes the fixed widths altogether, so this holds at any
    // width, not just one that happens to clear 316px by a few pixels.
    await _pumpAtWidth(tester, _buildView(), width: 300, textScale: 1.5);

    expect(tester.takeException(), isNull);
  });

  testWidgets(
      'renders translation and own-speech caption lines, distinctly styled',
      (tester) async {
    final captions = CaptionLines()
      ..add(
          const CaptionSignal(
              role: CaptionRole.translation,
              speaker: 'u2',
              text: 'Hola',
              isFinal: true),
          DateTime(2026))
      ..add(
          const CaptionSignal(
              role: CaptionRole.source,
              speaker: 'u1',
              text: 'Hello',
              isFinal: true),
          DateTime(2026));

    await tester.pumpWidget(_wrap(_buildView(captions: captions)));
    await tester.pump();

    final translationFinder = find.text('Hola');
    final sourceFinder = find.text('Hello');
    expect(translationFinder, findsOneWidget);
    expect(sourceFinder, findsOneWidget);

    final translationStyle = tester.widget<Text>(translationFinder).style!;
    final sourceStyle = tester.widget<Text>(sourceFinder).style!;
    expect(translationStyle.fontSize, isNot(sourceStyle.fontSize));
  });

  testWidgets(
      'mic button toggles and fires onMicToggle with the opposite state',
      (tester) async {
    bool? toggledTo;
    await tester.pumpWidget(
        _wrap(_buildView(micOn: true, onMicToggle: (v) => toggledTo = v)));
    await tester.pump();

    await tester.tap(find.text('Microphone'));
    await tester.pump();

    expect(toggledTo, isFalse);
  });

  testWidgets('end button fires onEnd', (tester) async {
    var ended = false;
    await tester.pumpWidget(_wrap(_buildView(onEnd: () => ended = true)));
    await tester.pump();

    await tester.tap(find.text('End'));
    await tester.pump();

    expect(ended, isTrue);
  });
}
```

`test/features/interpreter/presentation/widgets/ended_view_test.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/core/theme/app_theme.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/widgets/ended_view.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';

Widget _wrap(Widget child) => MaterialApp(
      theme: AppTheme.dark,
      locale: const Locale('en'),
      supportedLocales: const [Locale('en')],
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      home: Scaffold(body: child),
    );

void main() {
  testWidgets('shows the reason text, duration and host spend', (tester) async {
    await tester.pumpWidget(_wrap(EndedView(
      reason: InterpreterEndReason.partnerLeft,
      duration: const Duration(minutes: 3, seconds: 20),
      spentPlanck: '24000000',
      isHost: true,
      onDone: () {},
      onAgain: () {},
    )));

    expect(find.text('Your partner disconnected'), findsOneWidget);
    expect(find.text('Duration: 3:20'), findsOneWidget);
    expect(find.text('Spent: 24 μTAL'), findsOneWidget);
  });

  testWidgets('a guest never sees a spent amount, even if one is passed',
      (tester) async {
    await tester.pumpWidget(_wrap(EndedView(
      reason: InterpreterEndReason.hangup,
      duration: const Duration(seconds: 42),
      spentPlanck: '24000000',
      isHost: false,
      onDone: () {},
      onAgain: () {},
    )));

    expect(find.textContaining('μTAL'), findsNothing);
  });

  testWidgets('a null duration omits the duration line entirely',
      (tester) async {
    await tester.pumpWidget(_wrap(EndedView(
      reason: InterpreterEndReason.expired,
      duration: null,
      spentPlanck: null,
      isHost: true,
      onDone: () {},
      onAgain: () {},
    )));

    expect(find.textContaining('Duration:'), findsNothing);
  });

  testWidgets('"Done" pops, "Again" goes back to start', (tester) async {
    var done = false;
    var again = false;
    await tester.pumpWidget(_wrap(EndedView(
      reason: InterpreterEndReason.hangup,
      duration: const Duration(seconds: 10),
      spentPlanck: null,
      isHost: false,
      onDone: () => done = true,
      onAgain: () => again = true,
    )));

    await tester.tap(find.text('Done'));
    await tester.pump();
    expect(done, isTrue);
    expect(again, isFalse);

    await tester.tap(find.text('Again'));
    await tester.pump();
    expect(again, isTrue);
  });
}
```

Run: `flutter test test/features/interpreter/presentation/widgets/session_view_test.dart test/features/interpreter/presentation/widgets/ended_view_test.dart`
Expected: `test/features/interpreter/presentation/widgets/ended_view_test.dart` — не запускается (нет ещё кода, который он импортирует); `test/features/interpreter/presentation/widgets/session_view_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 2.

- [ ] **Step 2: Код**

`lib/features/interpreter/presentation/widgets/session_view.dart` целиком:

```dart
import 'dart:async';

import 'package:flutter/material.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../l10n/app_localizations.dart';
import '../../../billing/presentation/screens/_billing_formatters.dart';
import '../../domain/interpreter_models.dart';
import '../../room/caption_lines.dart';
import '../../room/interpreter_signal.dart';
import '../bloc/interpreter_state.dart' show InterpreterLinkState;
import 'interpreter_texts.dart';

/// The conversation itself, for both host and guest. Mirrors
/// `InterpreterActive` field for field — see that state's class doc for why
/// [captions] is a mutable accumulator rather than an immutable value.
class InterpreterSessionView extends StatefulWidget {
  final bool isHost;
  final InterpreterPartner partner;
  final InterpreterDirections directions;
  final CaptionLines captions;
  final bool partnerSpeaking;
  final bool meSpeaking;
  final bool agentPresent;
  final InterpreterLinkState connection;
  final bool micOn;
  final DateTime startedAt;
  final String? spentPlanck;
  final List<InterpreterLanguage> languages;
  final ValueChanged<bool> onMicToggle;
  final VoidCallback onEnd;

  /// Injectable clock for the host's elapsed-time readout; defaults to the
  /// wall clock.
  final DateTime Function() now;

  const InterpreterSessionView({
    super.key,
    required this.isHost,
    required this.partner,
    required this.directions,
    required this.captions,
    required this.partnerSpeaking,
    required this.meSpeaking,
    required this.agentPresent,
    required this.connection,
    required this.micOn,
    required this.startedAt,
    required this.spentPlanck,
    required this.languages,
    required this.onMicToggle,
    required this.onEnd,
    this.now = DateTime.now,
  });

  @override
  State<InterpreterSessionView> createState() => _InterpreterSessionViewState();
}

class _InterpreterSessionViewState extends State<InterpreterSessionView> {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    // Only the host shows a running timer — ticking for the guest too would
    // just burn frames on a clock nobody reads (see spec: "у А — таймер и
    // стоимость").
    if (widget.isHost) {
      _timer = Timer.periodic(const Duration(seconds: 1), (_) {
        if (mounted) setState(() {});
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colors = AppColors.of(context);
    final l10n = AppLocalizations.of(context)!;
    final partnerName = widget.partner.firstName?.trim().isNotEmpty == true
        ? widget.partner.firstName!
        : l10n.interpreterPartnerFallback;
    final partnerLangName =
        interpreterLanguageName(widget.languages, widget.partner.lang);

    return SafeArea(
      child: Column(
        children: [
          const SizedBox(height: 12),
          _buildHeader(colors, partnerName, partnerLangName),
          const SizedBox(height: 8),
          if (widget.directions.toMe == InterpreterEngine.phrase)
            _buildBadge(colors, l10n.interpreterPhraseBadge),
          if (!widget.agentPresent)
            _buildBanner(colors, l10n.interpreterAgentAbsent)
          else if (widget.connection == InterpreterLinkState.reconnecting)
            _buildBanner(colors, l10n.interpreterReconnecting)
          else if (widget.connection == InterpreterLinkState.failed)
            _buildBanner(colors, l10n.interpreterTranslationFailedBanner),
          Expanded(child: _buildCaptions(colors, l10n)),
          if (widget.isHost) _buildHostMeter(colors, l10n),
          Text(
            l10n.interpreterServerNote,
            style: TextStyle(color: colors.textSecondary, fontSize: 11),
          ),
          const SizedBox(height: 12),
          _buildControls(colors, l10n),
          const SizedBox(height: 12),
        ],
      ),
    );
  }

  Widget _buildHeader(
    AppColorsExtension colors,
    String partnerName,
    String partnerLangName,
  ) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  partnerName,
                  style: TextStyle(
                    color: colors.textPrimary,
                    fontSize: 17,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  partnerLangName,
                  style: TextStyle(color: colors.textSecondary, fontSize: 13),
                ),
              ],
            ),
          ),
          if (widget.partnerSpeaking)
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                    color: colors.primary,
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 6),
                Text(
                  AppLocalizations.of(context)!.interpreterPartnerSpeaking,
                  style: TextStyle(color: colors.primary, fontSize: 12),
                ),
              ],
            ),
        ],
      ),
    );
  }

  Widget _buildBadge(AppColorsExtension colors, String text) {
    return Container(
      margin: const EdgeInsets.only(top: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: colors.accent.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: colors.accent.withValues(alpha: 0.4)),
      ),
      child: Text(
        text,
        style: TextStyle(
            color: colors.accent, fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }

  Widget _buildBanner(AppColorsExtension colors, String text) {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: colors.warning.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: colors.warning.withValues(alpha: 0.35)),
      ),
      child: Row(
        children: [
          Icon(Icons.warning_amber_rounded, color: colors.warning, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: Text(text,
                style: TextStyle(color: colors.warning, fontSize: 13)),
          ),
        ],
      ),
    );
  }

  Widget _buildCaptions(AppColorsExtension colors, AppLocalizations l10n) {
    // `linesFor` hands back oldest-first, newest-last — rendered top to
    // bottom in that same order, so the newest line of each role is always
    // the one closest to the bottom of its section.
    final translation = widget.captions.linesFor(CaptionRole.translation);
    final source = widget.captions.linesFor(CaptionRole.source);
    return ListView(
      padding: const EdgeInsets.fromLTRB(20, 16, 20, 8),
      children: [
        if (source.isNotEmpty) ...[
          Text(
            l10n.interpreterMyCaptionLabel,
            style: TextStyle(
              color: colors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.3,
            ),
          ),
          const SizedBox(height: 4),
          for (final line in source)
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text(
                line.text,
                style: TextStyle(color: colors.textSecondary, fontSize: 13),
              ),
            ),
          const SizedBox(height: 16),
        ],
        Text(
          l10n.interpreterTranslationCaptionLabel,
          style: TextStyle(
            color: colors.primary,
            fontSize: 11,
            fontWeight: FontWeight.w700,
            letterSpacing: 0.3,
          ),
        ),
        const SizedBox(height: 4),
        for (final line in translation)
          Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: Text(
              line.text,
              style: TextStyle(
                color: colors.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.w500,
                height: 1.3,
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildHostMeter(AppColorsExtension colors, AppLocalizations l10n) {
    final elapsed = widget.now().difference(widget.startedAt);
    final spent = widget.spentPlanck;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.timer_outlined, color: colors.textSecondary, size: 16),
          const SizedBox(width: 6),
          Text(
            interpreterFormatDuration(elapsed),
            style: TextStyle(color: colors.textPrimary, fontSize: 14),
          ),
          if (spent != null) ...[
            const SizedBox(width: 16),
            Text(
              l10n.interpreterSpentAmount(planckToMicroTal(spent)),
              style: TextStyle(color: colors.textSecondary, fontSize: 13),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildControls(AppColorsExtension colors, AppLocalizations l10n) {
    // The app theme gives every Elevated/OutlinedButton a 'minimumSize' of
    // `Size(double.infinity, 52)` (every other screen wraps its buttons in a
    // full-width SizedBox) — inside a plain Row that infinite minimum width
    // has nothing finite to clamp against and the layout asserts. `Expanded`
    // gives each button a finite, shared slice of the row's width instead of
    // a fixed 150px — which also used to overflow once a large text scale
    // made "Микрофон"/"Завершить" wider than that.
    return Row(
      children: [
        Expanded(
          child: SizedBox(
            height: 50,
            child: OutlinedButton.icon(
              onPressed: () => widget.onMicToggle(!widget.micOn),
              icon: Icon(
                  widget.micOn ? Icons.mic_rounded : Icons.mic_off_rounded),
              label: Text(l10n.interpreterMicButton),
            ),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: SizedBox(
            height: 50,
            child: ElevatedButton.icon(
              onPressed: widget.onEnd,
              style: ElevatedButton.styleFrom(backgroundColor: colors.error),
              icon: const Icon(Icons.call_end_rounded),
              label: Text(l10n.interpreterEndButton),
            ),
          ),
        ),
      ],
    );
  }
}
```

`lib/features/interpreter/presentation/widgets/ended_view.dart` целиком:

```dart
import 'package:flutter/material.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../l10n/app_localizations.dart';
import '../../../billing/presentation/screens/_billing_formatters.dart';
import '../../domain/interpreter_models.dart';
import 'interpreter_texts.dart';

/// Final screen after a call ends: why it ended, how long it ran and — for
/// the host only — how much it cost.
class EndedView extends StatelessWidget {
  final InterpreterEndReason? reason;
  final Duration? duration;
  final String? spentPlanck;
  final bool isHost;
  final VoidCallback onDone;
  final VoidCallback onAgain;

  const EndedView({
    super.key,
    required this.reason,
    required this.duration,
    required this.spentPlanck,
    required this.isHost,
    required this.onDone,
    required this.onAgain,
  });

  @override
  Widget build(BuildContext context) {
    final colors = AppColors.of(context);
    final l10n = AppLocalizations.of(context)!;
    final shownDuration = duration;
    final shownSpent = spentPlanck;

    return SafeArea(
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.call_end_rounded,
                  color: colors.textSecondary, size: 40),
              const SizedBox(height: 16),
              Text(
                l10n.interpreterEndedTitle,
                style: TextStyle(
                  color: colors.textPrimary,
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                interpreterEndText(l10n, reason),
                textAlign: TextAlign.center,
                style: TextStyle(color: colors.textSecondary, fontSize: 14),
              ),
              if (shownDuration != null) ...[
                const SizedBox(height: 16),
                Text(
                  l10n.interpreterDurationLabel(
                      interpreterFormatDuration(shownDuration)),
                  style: TextStyle(color: colors.textPrimary, fontSize: 14),
                ),
              ],
              if (isHost && shownSpent != null) ...[
                const SizedBox(height: 4),
                Text(
                  l10n.interpreterSpentAmount(planckToMicroTal(shownSpent)),
                  style: TextStyle(color: colors.textPrimary, fontSize: 14),
                ),
              ],
              const SizedBox(height: 28),
              SizedBox(
                width: double.infinity,
                height: 50,
                child: ElevatedButton(
                  onPressed: onDone,
                  child: Text(l10n.interpreterDoneButton),
                ),
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 50,
                child: OutlinedButton(
                  onPressed: onAgain,
                  child: Text(l10n.interpreterAgainButton),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/presentation/widgets/session_view_test.dart test/features/interpreter/presentation/widgets/ended_view_test.dart lib/features/interpreter/presentation/widgets/session_view.dart lib/features/interpreter/presentation/widgets/ended_view.dart
```

Ожидается: `+228: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/widgets/session_view_test.dart test/features/interpreter/presentation/widgets/ended_view_test.dart lib/features/interpreter/presentation/widgets/session_view.dart lib/features/interpreter/presentation/widgets/ended_view.dart
git commit -m "feat(interpreter): экран разговора и итог" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 19: Экран разговора с переводом

- Один маршрут, вид выбирается по состоянию BLoC. Нет образца голоса — та же шторка записи, что у ассистента. Уход с экрана во время разговора — с подтверждением, разговор завершается у обоих. Кнопка входа в раздел сама спрашивает сервер, включён ли режим, и кэширует только удачный ответ: после сбоя сети следующий показ спросит снова.

**Files:**
- Create: `test/features/interpreter/presentation/widgets/interpreter_entry_button_test.dart`, `lib/features/interpreter/presentation/screens/interpreter_screen.dart`, `lib/features/interpreter/presentation/widgets/interpreter_entry_button.dart`

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/widgets/interpreter_entry_button_test.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/core/di/service_locator.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_repository.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/widgets/interpreter_entry_button.dart';

class _MockInterpreterRepository extends Mock
    implements InterpreterRepository {}

const _enabledCatalog = InterpreterCatalog(
  enabled: true,
  languages: [InterpreterLanguage(code: 'ru', name: 'Русский')],
);
const _disabledCatalog = InterpreterCatalog(enabled: false, languages: []);

void main() {
  late _MockInterpreterRepository repo;

  setUp(() {
    repo = _MockInterpreterRepository();
    sl.registerSingleton<InterpreterRepository>(repo);
    debugResetInterpreterCatalogCache();
  });

  tearDown(() async {
    debugResetInterpreterCatalogCache();
    await sl.reset();
  });

  // The actual bug: `_catalogFuture ??= _fetchCatalog()` memoized a failed
  // fetch forever (`_fetchCatalog` swallows the error and resolves to
  // `null`), so one network blip or a request racing the auth token hid the
  // button until restart. Exercised directly through the
  // `debugLoadInterpreterCatalogForTest` seam rather than by pumping the
  // widget — see the "desktop test host" note below for why.
  group('catalog cache', () {
    test('a failed fetch is not memoized — the next call fetches again',
        () async {
      var call = 0;
      when(() => repo.catalog()).thenAnswer((_) async {
        call++;
        if (call == 1) throw Exception('network blip');
        return _enabledCatalog;
      });

      final first = await debugLoadInterpreterCatalogForTest();
      expect(first, isNull);

      final second = await debugLoadInterpreterCatalogForTest();
      expect(second, _enabledCatalog);
      verify(() => repo.catalog()).called(2);
    });

    test(
        'a successful fetch is memoized — a later call does not hit the '
        'repository again', () async {
      when(() => repo.catalog()).thenAnswer((_) async => _enabledCatalog);

      final first = await debugLoadInterpreterCatalogForTest();
      final second = await debugLoadInterpreterCatalogForTest();

      expect(first, _enabledCatalog);
      expect(second, _enabledCatalog);
      verify(() => repo.catalog()).called(1);
    });

    test(
        'a disabled catalog is a successful fetch too and is memoized the '
        'same way', () async {
      when(() => repo.catalog()).thenAnswer((_) async => _disabledCatalog);

      final first = await debugLoadInterpreterCatalogForTest();
      final second = await debugLoadInterpreterCatalogForTest();

      expect(first, _disabledCatalog);
      expect(second, _disabledCatalog);
      verify(() => repo.catalog()).called(1);
    });
  });

  group('InterpreterEntryButton widget', () {
    // `PlatformUtils.instance.isMobile` reads `dart:io Platform` directly
    // with no fake/override hook anywhere in this codebase (verified:
    // `PlatformUtils.instance.isMobile` is `false` / `isDesktop` is `true`
    // under `flutter test` on the host this suite runs on). `build()`'s own
    // `if (!PlatformUtils.instance.isMobile) return SizedBox.shrink();` gate
    // therefore fires before the `FutureBuilder` — and the cache it drives —
    // is ever reached, so "button shown after a successful fetch" and
    // "hidden on desktop" are indistinguishable through pumpWidget here:
    // both render nothing, and the repository is never even called. That is
    // the "desktop gating" case left untested per the task's own allowance;
    // the cache/catalog contract that actually changed is covered directly
    // above instead.
    testWidgets(
        'renders nothing on this (desktop) test host regardless of catalog '
        'state, without ever calling the repository', (tester) async {
      when(() => repo.catalog()).thenAnswer((_) async => _enabledCatalog);

      await tester.pumpWidget(MaterialApp(
        home: Scaffold(body: InterpreterEntryButton(onTap: () {})),
      ));
      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.translate_rounded), findsNothing);
      verifyNever(() => repo.catalog());
    });
  });
}
```

Run: `flutter test test/features/interpreter/presentation/widgets/interpreter_entry_button_test.dart`
Expected: `test/features/interpreter/presentation/widgets/interpreter_entry_button_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

`lib/features/interpreter/presentation/screens/interpreter_screen.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/di/service_locator.dart';
import '../../../../core/theme/app_theme.dart';
import '../../../../core/utils/constants.dart';
import '../../../../l10n/app_localizations.dart';
import '../../../voice_enrollment/presentation/bloc/voice_enrollment_bloc.dart';
import '../../../voice_enrollment/presentation/widgets/owner_enrollment_sheet.dart';
import '../../domain/interpreter_error.dart';
import '../../domain/interpreter_models.dart';
import '../bloc/interpreter_bloc.dart';
import '../bloc/interpreter_event.dart';
import '../bloc/interpreter_state.dart';
import '../widgets/ended_view.dart';
import '../widgets/interpreter_texts.dart';
import '../widgets/qr_view.dart';
import '../widgets/scanner_screen.dart';
import '../widgets/session_view.dart';
import '../widgets/start_view.dart';

/// Single route for the whole "Разговор с переводом" feature — a
/// `BlocConsumer` over [InterpreterBloc] swaps the body between views as the
/// bloc's state machine advances. [joinCode] carries a scanned/deep-linked
/// code straight into the flow; [scanFirst] opens the QR scanner once the
/// language-choosing screen is reached (used by the assistant's
/// `open_interpreter({action: 'join'})` and by `?scan=1`).
class InterpreterScreen extends StatelessWidget {
  final String? joinCode;
  final bool scanFirst;

  const InterpreterScreen({super.key, this.joinCode, this.scanFirst = false});

  @override
  Widget build(BuildContext context) {
    return BlocProvider<InterpreterBloc>(
      create: (ctx) => sl<InterpreterBloc>(
        param1: Localizations.localeOf(ctx).languageCode,
      )..add(Started(joinCode: joinCode)),
      child: _InterpreterView(scanFirst: scanFirst),
    );
  }
}

class _InterpreterView extends StatefulWidget {
  final bool scanFirst;
  const _InterpreterView({required this.scanFirst});

  @override
  State<_InterpreterView> createState() => _InterpreterViewState();
}

class _InterpreterViewState extends State<_InterpreterView> {
  bool _scanFirstPending = false;

  /// The catalog only ever arrives on [InterpreterChoosing] — remembered
  /// here so [InterpreterSessionView] (reached from [InterpreterActive], which carries
  /// no catalog of its own) can still resolve the partner's language name.
  InterpreterCatalog? _catalog;

  @override
  void initState() {
    super.initState();
    _scanFirstPending = widget.scanFirst;
  }

  Future<void> _openScanner() async {
    final code = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const InterpreterScannerScreen()),
    );
    if (code != null && mounted) {
      context.read<InterpreterBloc>().add(JoinPressed(code));
    }
  }

  Future<void> _handleNeedVoicePrint() async {
    final bloc = sl<VoiceEnrollmentBloc>();
    final result = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      isDismissible: false,
      enableDrag: false,
      builder: (ctx) => BlocProvider.value(
        value: bloc,
        child: const OwnerEnrollmentSheet(),
      ),
    );
    if (mounted) {
      context.read<InterpreterBloc>().add(VoicePrintResult(result == true));
    }
  }

  Future<bool> _confirmLeave() async {
    final l10n = AppLocalizations.of(context)!;
    final colors = AppColors.of(context);
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: colors.card,
        title: Text(l10n.interpreterLeaveConfirmTitle),
        content: Text(l10n.interpreterLeaveConfirmBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l10n.interpreterEndButton),
          ),
        ],
      ),
    );
    return result == true;
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final colors = AppColors.of(context);

    return BlocConsumer<InterpreterBloc, InterpreterState>(
      listener: (context, state) {
        if (state is InterpreterChoosing) _catalog = state.catalog;
        if (state is InterpreterNeedVoicePrint) {
          _handleNeedVoicePrint();
        } else if (state is InterpreterChoosing && _scanFirstPending) {
          _scanFirstPending = false;
          _openScanner();
        }
      },
      builder: (context, state) {
        final blockPop =
            state is InterpreterHosting || state is InterpreterActive;
        return PopScope(
          canPop: !blockPop,
          onPopInvokedWithResult: (didPop, _) async {
            if (didPop) return;
            final confirmed = await _confirmLeave();
            if (confirmed && context.mounted) {
              context.read<InterpreterBloc>().add(const EndPressed());
              Navigator.of(context).pop();
            }
          },
          child: Scaffold(
            backgroundColor: colors.background,
            appBar: AppBar(title: Text(l10n.interpreterTitle)),
            body: _buildBody(context, state, l10n, colors),
          ),
        );
      },
    );
  }

  Widget _buildBody(
    BuildContext context,
    InterpreterState state,
    AppLocalizations l10n,
    AppColorsExtension colors,
  ) {
    final bloc = context.read<InterpreterBloc>();
    switch (state) {
      case InterpreterLoading():
        return Center(child: CircularProgressIndicator(color: colors.primary));

      case InterpreterUnavailable():
        return Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text(
              l10n.interpreterUnavailableTitle,
              textAlign: TextAlign.center,
              style: TextStyle(color: colors.textSecondary, fontSize: 15),
            ),
          ),
        );

      case InterpreterNeedVoicePrint():
        // The enrollment sheet is already open (triggered from the
        // listener) — this is just what shows behind/after it.
        return Center(child: CircularProgressIndicator(color: colors.primary));

      case InterpreterChoosing(catalog: final catalog, myLang: final myLang):
        return StartView(
          catalog: catalog,
          myLang: myLang,
          onLanguageChosen: (code) => bloc.add(LanguageChosen(code)),
          onStart: () => bloc.add(const HostPressed()),
          onScan: _openScanner,
        );

      case InterpreterWorking(kind: final kind):
        return Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              CircularProgressIndicator(color: colors.primary),
              const SizedBox(height: 16),
              Text(
                kind == InterpreterWorkKind.creating
                    ? l10n.interpreterCreatingLabel
                    : l10n.interpreterJoiningLabel,
                style: TextStyle(color: colors.textSecondary),
              ),
            ],
          ),
        );

      case InterpreterHosting(code: final code, expiresAt: final expiresAt):
        return QrView(
          code: code,
          expiresAt: expiresAt,
          onNewCode: () => bloc.add(const NewCodePressed()),
        );

      case InterpreterActive(
          isHost: final isHost,
          partner: final partner,
          directions: final directions,
          captions: final captions,
          partnerSpeaking: final partnerSpeaking,
          meSpeaking: final meSpeaking,
          agentPresent: final agentPresent,
          connection: final connection,
          micOn: final micOn,
          startedAt: final startedAt,
          spentPlanck: final spentPlanck,
        ):
        return InterpreterSessionView(
          isHost: isHost,
          partner: partner,
          directions: directions,
          captions: captions,
          partnerSpeaking: partnerSpeaking,
          meSpeaking: meSpeaking,
          agentPresent: agentPresent,
          connection: connection,
          micOn: micOn,
          startedAt: startedAt,
          spentPlanck: spentPlanck,
          languages: _catalog?.languages ?? const [],
          onMicToggle: (on) => bloc.add(MicToggled(on)),
          onEnd: () => bloc.add(const EndPressed()),
        );

      case InterpreterEnded(
          reason: final reason,
          duration: final duration,
          spentPlanck: final spentPlanck,
          isHost: final isHost,
        ):
        return EndedView(
          reason: reason,
          duration: duration,
          spentPlanck: spentPlanck,
          isHost: isHost,
          onDone: () => Navigator.of(context).maybePop(),
          onAgain: () => bloc.add(const BackToStart()),
        );

      case InterpreterFailure(kind: final kind, back: final back):
        return _buildFailureView(context, kind, back, l10n, colors, bloc);
    }
  }

  Widget _buildFailureView(
    BuildContext context,
    InterpreterErrorKind kind,
    InterpreterChoosing? back,
    AppLocalizations l10n,
    AppColorsExtension colors,
    InterpreterBloc bloc,
  ) {
    return SafeArea(
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline_rounded, color: colors.error, size: 40),
              const SizedBox(height: 16),
              Text(
                interpreterErrorText(l10n, kind),
                textAlign: TextAlign.center,
                style: TextStyle(color: colors.textPrimary, fontSize: 15),
              ),
              if (kind == InterpreterErrorKind.codeExpired) ...[
                const SizedBox(height: 8),
                Text(
                  l10n.interpreterAskNewCodeHint,
                  textAlign: TextAlign.center,
                  style: TextStyle(color: colors.textSecondary, fontSize: 13),
                ),
              ],
              const SizedBox(height: 24),
              if (kind == InterpreterErrorKind.insufficientFunds) ...[
                SizedBox(
                  width: double.infinity,
                  height: 48,
                  child: ElevatedButton(
                    onPressed: () => context.push(RouteConstants.wallet),
                    child: Text(l10n.billingTopUp),
                  ),
                ),
                const SizedBox(height: 12),
              ],
              SizedBox(
                width: double.infinity,
                height: 48,
                child: OutlinedButton(
                  onPressed: () => bloc.add(const BackToStart()),
                  child: Text(
                    back == null
                        ? l10n.retry
                        : l10n.interpreterBackToStartButton,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

`lib/features/interpreter/presentation/widgets/interpreter_entry_button.dart` целиком:

```dart
import 'package:flutter/material.dart';

import '../../../../core/di/service_locator.dart';
import '../../../../core/platform/platform_utils.dart';
import '../../../../core/theme/app_theme.dart';
import '../../../../core/theme/widgets.dart';
import '../../../../l10n/app_localizations.dart';
import '../../domain/interpreter_models.dart';
import '../../domain/interpreter_repository.dart';

/// Memoized for the life of the app: the catalog only changes with a server
/// deploy, and every `CallHistoryScreen` rebuild (tab switches, pull to
/// refresh) would otherwise re-fetch it for nothing. Only a *successful*
/// answer is kept — [_fetchCatalog] reports failure as `null`, and memoizing
/// that would hide the button until restart after one network blip or a
/// request racing the auth token, instead of just trying again next build.
Future<InterpreterCatalog?>? _catalogFuture;

Future<InterpreterCatalog?> _loadCatalogOnce() {
  final cached = _catalogFuture;
  if (cached != null) return cached;

  final future = _fetchCatalog();
  _catalogFuture = future;
  future.then((catalog) {
    if (catalog == null && identical(_catalogFuture, future)) {
      _catalogFuture = null;
    }
  });
  return future;
}

Future<InterpreterCatalog?> _fetchCatalog() async {
  try {
    return await sl<InterpreterRepository>().catalog();
  } catch (_) {
    // Disabled-by-default is the safe reading of "couldn't find out" — the
    // button just doesn't render rather than risking a dead link.
    return null;
  }
}

/// Clears the memoized catalog. **Test use only** — never call in production
/// code.
@visibleForTesting
void debugResetInterpreterCatalogCache() {
  _catalogFuture = null;
}

/// Exercises the cache directly. **Test use only** — never call in
/// production code. [PlatformUtils.instance.isMobile] has no fake/override
/// hook (it reads `dart:io Platform` straight through) and is `false` under
/// `flutter test` on every host this repo builds on, so [build]'s own gate
/// would otherwise keep the cache from ever being touched in a widget test.
@visibleForTesting
Future<InterpreterCatalog?> debugLoadInterpreterCatalogForTest() =>
    _loadCatalogOnce();

/// "Разговор с переводом" entry point on the Calls tab. Renders nothing on
/// desktop (the feature is mobile-only) and nothing until the catalog is
/// known to be enabled — no loading placeholder, since a quiet skip reads
/// better than a card that flashes in and out on every screen open.
class InterpreterEntryButton extends StatelessWidget {
  final VoidCallback onTap;

  const InterpreterEntryButton({super.key, required this.onTap});

  @override
  Widget build(BuildContext context) {
    if (!PlatformUtils.instance.isMobile) return const SizedBox.shrink();

    return FutureBuilder<InterpreterCatalog?>(
      future: _loadCatalogOnce(),
      builder: (context, snapshot) {
        final catalog = snapshot.data;
        if (catalog == null || !catalog.enabled) return const SizedBox.shrink();

        final colors = AppColors.of(context);
        final l10n = AppLocalizations.of(context)!;
        return GestureDetector(
          onTap: onTap,
          child: AppCard(
            child: Row(
              children: [
                Container(
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [colors.primary, colors.accent],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(Icons.translate_rounded,
                      color: Colors.white, size: 20),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    l10n.interpreterTitle,
                    style: TextStyle(
                      color: colors.textPrimary,
                      fontSize: 15,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ),
                Icon(Icons.chevron_right_rounded,
                    color: colors.textSecondary, size: 22),
              ],
            ),
          ),
        );
      },
    );
  }
}
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze test/features/interpreter/presentation/widgets/interpreter_entry_button_test.dart lib/features/interpreter/presentation/screens/interpreter_screen.dart lib/features/interpreter/presentation/widgets/interpreter_entry_button.dart
```

Ожидается: `+232: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/widgets/interpreter_entry_button_test.dart lib/features/interpreter/presentation/screens/interpreter_screen.dart lib/features/interpreter/presentation/widgets/interpreter_entry_button.dart
git commit -m "feat(interpreter): экран разговора с переводом и кнопка входа" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 20: DI и маршруты

- Регистрация в GetIt и маршруты `/dashboard/interpreter` (`?scan=1` — сразу сканер) и `/dashboard/interpreter/join/:code` — только на мобильных, как у mesh-звонков. Маршруты — вне оболочки с нижним меню, рядом с экраном звонка: живой разговор не должен уходить со смены вкладки мимо подтверждения. BLoC — фабрика с параметром: язык приложения передаёт экран.
- Не вошедший в аккаунт, пришедший по ссылке на вход в разговор, отправляется на вход, а код запоминается (`PendingInterpreterJoin`).

**Files:**
- Modify: `lib/core/di/service_locator.dart`, `lib/core/router/app_router.dart`, `lib/core/utils/constants.dart`

- [ ] **Step 1: Код**

Патч к `lib/core/di/service_locator.dart`:

```diff
--- a/lib/core/di/service_locator.dart
+++ b/lib/core/di/service_locator.dart
@@ -174,6 +174,16 @@
 import '../../features/billing/presentation/bloc/toggles_bloc.dart';
 import '../../features/billing/presentation/bloc/transactions_bloc.dart';
 
+// Interpreter ("Разговор с переводом" — face-to-face interpreter)
+import '../../features/interpreter/data/interpreter_lang_store.dart';
+import '../../features/interpreter/data/interpreter_remote_datasource.dart';
+import '../../features/interpreter/data/interpreter_repository_impl.dart';
+import '../../features/interpreter/data/pending_interpreter_join.dart';
+import '../../features/interpreter/domain/interpreter_repository.dart';
+import '../../features/interpreter/presentation/bloc/interpreter_bloc.dart';
+import '../../features/interpreter/room/interpreter_device.dart';
+import '../../features/interpreter/room/livekit_interpreter_room.dart';
+
 // Assistant Chat
 import '../../features/assistant/data/assistant_chat_api.dart';
 import '../../features/assistant/data/assistant_draft_storage.dart';
@@ -788,6 +798,42 @@
       eventBus: sl<BillingEventBus>(),
     ),
   );
+
+  // Registered unconditionally (unlike the LiveKit/device plumbing below):
+  // `_globalRedirect` in app_router.dart has to be able to save a join code
+  // for an unauthenticated scanner on every platform, same as
+  // `OAuthPendingRequest` above — the join route itself is still mobile-only.
+  sl.registerLazySingleton<PendingInterpreterJoin>(
+      () => PendingInterpreterJoin());
+
+  // Interpreter ("Разговор с переводом") — mobile only, same as the mesh
+  // group-call BLoC above: LiveKit rooms and the device-level earpiece/
+  // proximity/foreground-service plumbing have no desktop equivalent.
+  if (PlatformUtils.instance.isMobile) {
+    sl.registerLazySingleton(
+        () => InterpreterRemoteDataSource(sl<DioClient>()));
+    sl.registerLazySingleton<InterpreterRepository>(
+      () => InterpreterRepositoryImpl(sl<InterpreterRemoteDataSource>()),
+    );
+    sl.registerLazySingleton(
+        () => InterpreterLangStore(sl<SecureStorageService>()));
+    sl.registerLazySingleton(() => InterpreterDevice());
+    // Factory with a param: the screen passes the app's current locale code
+    // (`Localizations.localeOf(context).languageCode`) as the default
+    // language to preselect — a fresh bloc per screen visit, like the
+    // other per-screen BLoCs above.
+    sl.registerFactoryParam<InterpreterBloc, String, void>(
+      (appLocaleCode, _) => InterpreterBloc(
+        repo: sl<InterpreterRepository>(),
+        langStore: sl<InterpreterLangStore>(),
+        voice: sl<VoiceEnrollmentRepository>(),
+        roomFactory: LiveKitInterpreterRoom.new,
+        device: sl<InterpreterDevice>(),
+        appLocale: () => appLocaleCode,
+        livekitUrl: interpreterLivekitUrl,
+      ),
+    );
+  }
 
   // Outbox infrastructure
   sl.registerLazySingleton<OutboxQueue>(() => OutboxQueue());
```

Патч к `lib/core/router/app_router.dart`:

```diff
--- a/lib/core/router/app_router.dart
+++ b/lib/core/router/app_router.dart
@@ -49,6 +49,8 @@
 import '../../features/voice/presentation/screens/group_call_lobby_screen.dart';
 import '../../features/voice/presentation/screens/group_call_active_screen.dart';
 import '../../features/call_history/presentation/screens/call_history_screen.dart';
+import '../../features/interpreter/data/pending_interpreter_join.dart';
+import '../../features/interpreter/presentation/screens/interpreter_screen.dart';
 import '../../features/profile_sections/presentation/screens/profile_sections_screen.dart';
 import '../../features/billing/presentation/screens/wallet_screen.dart';
 import '../../features/billing/presentation/screens/transactions_screen.dart';
@@ -224,6 +226,25 @@
         );
       },
     ),
+    // Face-to-face interpreter — mobile only (LiveKit room + device-level
+    // earpiece/proximity plumbing has no desktop equivalent). Full-screen,
+    // outside ShellRoute, same reason as the voice call route above: the
+    // proximity sensor and earpiece routing have no business sharing a
+    // screen with the bottom nav.
+    if (PlatformUtils.instance.isMobile) ...[
+      GoRoute(
+        path: RouteConstants.interpreter,
+        builder: (_, state) => InterpreterScreen(
+          scanFirst: state.uri.queryParameters['scan'] == '1',
+        ),
+      ),
+      GoRoute(
+        path: RouteConstants.interpreterJoin,
+        builder: (_, state) => InterpreterScreen(
+          joinCode: state.pathParameters['code'],
+        ),
+      ),
+    ],
     // Group mesh voice room — mobile only (mesh not available on desktop).
     if (PlatformUtils.instance.isMobile) ...[
       // Picker (Phase 1)
@@ -583,6 +604,27 @@
     return null;
   }
 
+  // Face-to-face interpreter join deep link opened from the system camera
+  // while logged out: same pattern as the native OAuth flow above — save the
+  // code before sending the user to /login, so postLoginNavigate can resume
+  // it, instead of just losing it to the generic protected-route check below.
+  if (state.matchedLocation.startsWith('${RouteConstants.interpreter}/join/')) {
+    try {
+      final storage = sl<SecureStorageService>();
+      final hasToken = await storage.hasRefreshToken;
+      if (!hasToken) {
+        final code = state.pathParameters['code'];
+        if (code != null && code.isNotEmpty) {
+          sl<PendingInterpreterJoin>().save(code);
+        }
+        return RouteConstants.login;
+      }
+    } catch (_) {
+      // Storage briefly unavailable — let it through; the screen will fail-fast.
+    }
+    return null;
+  }
+
   // Check token for protected routes — wrapped to avoid silent navigation failure
   // if Keychain is briefly inaccessible during device unlock transition.
   try {
```

Патч к `lib/core/utils/constants.dart`:

```diff
--- a/lib/core/utils/constants.dart
+++ b/lib/core/utils/constants.dart
@@ -59,6 +59,9 @@
   static const forgotPassword = '/auth/forgot-password';
   static const verifyEmail = '/dashboard/profile/verify-email';
   static const translator = '/dashboard/translator';
+  // Face-to-face interpreter ("Разговор с переводом").
+  static const interpreter = '/dashboard/interpreter';
+  static const interpreterJoin = '/dashboard/interpreter/join/:code';
   static const profileSections = '/dashboard/profile/sections';
   static const aiTwin = '/dashboard/profile/ai-twin';
 
```

- [ ] **Step 2: Проверить**

```bash
flutter test test/features/interpreter test/core/router 2>&1 | tail -1
flutter analyze lib/core/di/service_locator.dart lib/core/router/app_router.dart lib/core/utils/constants.dart 2>&1 | grep -c " • "; true
```

Ожидается: `+255: All tests passed!`; замечаний анализатора на изменённых старых файлах столько же, сколько до задачи: `1` (давние, не наши).

- [ ] **Step 3: Коммит**

```bash
git add lib/core/di/service_locator.dart lib/core/router/app_router.dart lib/core/utils/constants.dart
git commit -m "feat(interpreter): DI и маршруты раздела" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 21: Ссылки из QR: системная камера и сканер профиля

- `talerid://interp/<код>` из системной камеры ведёт на `/dashboard/interpreter/join/<код>`; сканер профиля тоже узнаёт эту ссылку и открывает вход, прежние QR пользователей работают как раньше.
- Не вошедшего в аккаунт роутер отправляет на вход и запоминает код (задача 20); после входа `postLoginNavigate` сразу после запроса OAuth ведёт в разговор, если код ещё жив.

**Files:**
- Modify: `test/core/router/deep_link_handler_test.dart`, `lib/core/router/deep_link_handler.dart`, `lib/core/router/post_login_redirect.dart`, `lib/features/profile/presentation/screens/profile_screen.dart`

- [ ] **Step 1: Тесты (падают)**

Патч к `test/core/router/deep_link_handler_test.dart`:

```diff
--- a/test/core/router/deep_link_handler_test.dart
+++ b/test/core/router/deep_link_handler_test.dart
@@ -71,6 +71,21 @@
       expect(resolve('talerid://user/u-1')!.location, '/dashboard/user/u-1');
     });
 
+    test('interpreter join code over the custom scheme', () {
+      final t = resolve('talerid://interp/ABCD1234');
+      expect(t!.location, '/dashboard/interpreter/join/ABCD1234');
+      expect(t.push, isFalse);
+    });
+
+    test('interpreter join link tolerates a trailing slash', () {
+      expect(resolve('talerid://interp/ABCD1234/')!.location,
+          '/dashboard/interpreter/join/ABCD1234');
+    });
+
+    test('a talerid link to a different path is not an interpreter join', () {
+      expect(resolve('talerid://interp/code/extra'), isNull);
+    });
+
     test('an invite link without a token is not acted on', () {
       expect(resolve('https://id.taler.tirol/ui/invite.html'), isNull);
     });
```

Run: `flutter test test/core/router/deep_link_handler_test.dart`
Expected: `test/core/router/deep_link_handler_test.dart` — падают 2 из 20. Всего тестов 20, падающих 2.

- [ ] **Step 2: Код**

Патч к `lib/core/router/deep_link_handler.dart`:

```diff
--- a/lib/core/router/deep_link_handler.dart
+++ b/lib/core/router/deep_link_handler.dart
@@ -2,6 +2,7 @@
 import 'package:flutter/foundation.dart';
 import 'package:go_router/go_router.dart';
 
+import '../../features/interpreter/domain/interpreter_code.dart';
 import '../utils/constants.dart';
 
 /// Hosts whose OAuth links this app may act on. Mirrors the associated-domains
@@ -144,6 +145,13 @@
       }
     }
 
+    // Handle interpreter join links:
+    // talerid://interp/{code}
+    final interpCode = codeFromScan(uri.toString());
+    if (interpCode != null) {
+      return DeepLinkTarget('/dashboard/interpreter/join/$interpCode');
+    }
+
     return null;
   }
 }
```

Патч к `lib/core/router/post_login_redirect.dart`:

```diff
--- a/lib/core/router/post_login_redirect.dart
+++ b/lib/core/router/post_login_redirect.dart
@@ -1,5 +1,6 @@
 import 'package:flutter/widgets.dart';
 import 'package:go_router/go_router.dart';
+import '../../features/interpreter/data/pending_interpreter_join.dart';
 import '../../features/mail/domain/repositories/i_mail_repository.dart';
 import '../../features/oauth/data/oauth_pending_request.dart';
 import '../di/service_locator.dart';
@@ -9,14 +10,22 @@
 
 /// Call this after a successful login/biometric/PIN entry. If the user opened
 /// the app via a Universal Link to /oauth/authorize before logging in,
-/// resume the OAuth consent flow. Otherwise navigate to onboarding (first
-/// login on this device) or straight to the assistant.
+/// resume the OAuth consent flow. Otherwise, if they opened a face-to-face
+/// interpreter join link, resume that. Otherwise navigate to onboarding
+/// (first login on this device) or straight to the assistant.
 Future<void> postLoginNavigate(BuildContext context) async {
   final pendingOAuth = await sl<OAuthPendingRequest>().consume();
   if (pendingOAuth != null) {
     if (!context.mounted) return;
     final query = pendingOAuth.query.isEmpty ? '' : '?${pendingOAuth.query}';
     context.go('${RouteConstants.oauthAuthorize}$query');
+    return;
+  }
+
+  final pendingJoinCode = sl<PendingInterpreterJoin>().consume();
+  if (pendingJoinCode != null) {
+    if (!context.mounted) return;
+    context.go('${RouteConstants.interpreter}/join/$pendingJoinCode');
     return;
   }
 
```

Патч к `lib/features/profile/presentation/screens/profile_screen.dart`:

```diff
--- a/lib/features/profile/presentation/screens/profile_screen.dart
+++ b/lib/features/profile/presentation/screens/profile_screen.dart
@@ -17,6 +17,7 @@
 import '../../../../core/api/dio_client.dart';
 import '../../../../core/di/service_locator.dart';
 import '../../../../core/storage/cache_service.dart';
+import '../../../interpreter/domain/interpreter_code.dart';
 import '../../domain/entities/user_entity.dart';
 import '../bloc/profile_bloc.dart';
 import '../../../voice/presentation/widgets/pulsing_avatar.dart' show rainbowColorFor;
@@ -906,6 +907,17 @@
         widget.onUserScanned(uri.pathSegments.first);
         return;
       }
+      // Face-to-face interpreter join link: talerid://interp/<code>. The
+      // system camera opens these the same way it would a user QR — this
+      // scanner has to recognise them too, not just the dedicated one in
+      // `interpreter/presentation/widgets/scanner_screen.dart`.
+      final interpCode = codeFromScan(raw);
+      if (interpCode != null) {
+        _handled = true;
+        Navigator.of(context).pop();
+        GoRouter.of(context).push('/dashboard/interpreter/join/$interpCode');
+        return;
+      }
     }
   }
 
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter test/core/router 2>&1 | tail -1
flutter analyze lib/core/router/deep_link_handler.dart lib/core/router/post_login_redirect.dart lib/features/profile/presentation/screens/profile_screen.dart 2>&1 | grep -c " • "; true
```

Ожидается: `+258: All tests passed!`; замечаний анализатора на изменённых старых файлах столько же, сколько до задачи: `20` (давние, не наши).

- [ ] **Step 4: Коммит**

```bash
git add test/core/router/deep_link_handler_test.dart lib/core/router/deep_link_handler.dart lib/core/router/post_login_redirect.dart lib/features/profile/presentation/screens/profile_screen.dart
git commit -m "feat(interpreter): ссылка talerid://interp/<код> из камеры и сканера профиля" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 22: Кнопка на вкладке «Звонки»

- «Разговор с переводом» — после «Создать встречу», только на мобильных и только если сервер говорит, что режим включён.

**Files:**
- Modify: `lib/features/call_history/presentation/screens/call_history_screen.dart`

- [ ] **Step 1: Код**

Патч к `lib/features/call_history/presentation/screens/call_history_screen.dart`:

```diff
--- a/lib/features/call_history/presentation/screens/call_history_screen.dart
+++ b/lib/features/call_history/presentation/screens/call_history_screen.dart
@@ -31,6 +31,7 @@
 import '../../../messenger/data/datasources/messenger_remote_datasource.dart';
 import '../../../messenger/presentation/bloc/messenger_bloc.dart';
 import '../../../billing/presentation/widgets/balance_chip.dart';
+import '../../../interpreter/presentation/widgets/interpreter_entry_button.dart';
 import '../../data/mesh_call_history_entry.dart';
 import '../../data/mesh_call_history_repository.dart';
 import 'call_history_merge.dart';
@@ -569,6 +570,10 @@
                   _buildPersonalRoomSection(colors),
                   const SizedBox(height: 12),
                   _buildCreateMeetingButton(colors),
+                  const SizedBox(height: 12),
+                  InterpreterEntryButton(
+                    onTap: () => context.push(RouteConstants.interpreter),
+                  ),
                   const SizedBox(height: 12),
                   _buildMeetingSummariesButton(colors),
                   const SizedBox(height: 8),
```

- [ ] **Step 2: Проверить**

```bash
flutter test test/features/interpreter test/features/call_history 2>&1 | tail -1
flutter analyze lib/features/call_history/presentation/screens/call_history_screen.dart 2>&1 | grep -c " • "; true
```

Ожидается: `+253: All tests passed!`; замечаний анализатора на изменённых старых файлах столько же, сколько до задачи: `42` (давние, не наши).

- [ ] **Step 3: Коммит**

```bash
git add lib/features/call_history/presentation/screens/call_history_screen.dart
git commit -m "feat(interpreter): кнопка «Разговор с переводом» на вкладке «Звонки»" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 23: Ассистент: `open_interpreter`

- Инструмент открывает экран старта (`host`) или сразу сканер (`join`). Как `start_call`, он обрабатывается в `assistant_screen.dart`, а не в исполнителе: перед переходом сессия ассистента освобождает микрофон. Строки в обоих встроенных промптах (ru, en) — на случай, когда серверный промпт недоступен.

**Files:**
- Modify: `lib/features/assistant/tools/assistant_tools_schema.dart`, `lib/features/assistant/tools/assistant_tools_executor.dart`, `lib/features/assistant/tools/assistant_system_prompt.dart`, `lib/features/assistant/presentation/screens/assistant_screen.dart`

- [ ] **Step 1: Код**

Патч к `lib/features/assistant/tools/assistant_tools_schema.dart`:

```diff
--- a/lib/features/assistant/tools/assistant_tools_schema.dart
+++ b/lib/features/assistant/tools/assistant_tools_schema.dart
@@ -310,6 +310,23 @@
           },
           {
             'type': 'function',
+            'name': 'open_interpreter',
+            'description':
+                'Open "Разговор с переводом" — face-to-face interpreter for two people sitting together, each with their own phone, each hearing only the translation of the other (NOT the "one phone on the table" translator mode — that is enter_translator_mode). action="host" opens the start screen to begin a new session and show a QR code; action="join" opens the QR scanner to join a session someone else started. Use when the user asks to "поговорить с переводом", "разговор с переводчиком на два телефона", "включи перевод для разговора вдвоём, у нас по телефону", "сканировать код для разговора с переводом", or similar.',
+            'parameters': {
+              'type': 'object',
+              'properties': {
+                'action': {
+                  'type': 'string',
+                  'enum': ['host', 'join'],
+                  'description': '"host" to start a new session, "join" to scan a partner\'s code',
+                },
+              },
+              'required': ['action'],
+            },
+          },
+          {
+            'type': 'function',
             'name': 'send_message',
             'description':
                 'Send a text message to a conversation. Pass replyToId to answer a specific message — that draws a real quote block in the chat, which plain text cannot do.',
```

Патч к `lib/features/assistant/tools/assistant_tools_executor.dart`:

```diff
--- a/lib/features/assistant/tools/assistant_tools_executor.dart
+++ b/lib/features/assistant/tools/assistant_tools_executor.dart
@@ -70,7 +70,11 @@
 ///
 /// NOT handled here (kept in the screen because they send realtime events
 /// mid-execution or return no output at all): `enter_translator_mode`,
-/// `exit_translator_mode`, `start_call`.
+/// `exit_translator_mode`, `start_call`, `open_interpreter` — the last two
+/// navigate away and release the voice session's own microphone, same as
+/// each other. In text-chat mode (no screen alongside) a call to any of
+/// these falls through to the "Unknown tool" branch below — the same
+/// pre-existing limitation `start_call` has there.
 class AssistantToolsExecutor {
   AssistantToolsExecutor({this.hooks, this.onAction});
 
```

Патч к `lib/features/assistant/tools/assistant_system_prompt.dart`:

```diff
--- a/lib/features/assistant/tools/assistant_system_prompt.dart
+++ b/lib/features/assistant/tools/assistant_system_prompt.dart
@@ -89,6 +89,14 @@
     '→ Если пользователь назвал язык («включи переводчик на словацкий», «переводи с русского на немецкий») — сразу вызови enter_translator_mode с lang_a и lang_b. Ничего не говори — просто вызови tool.\n'
     '→ Если язык собеседника НЕ назван — коротко спроси «На какой язык переводить?» и вызови enter_translator_mode после ответа. Не угадывай язык.\n'
     '→ Внутри переводчика язык меняют командой «выбери язык X» / «переводи на X», выходят — «Ассистент, стоп» / «хватит переводить».\n\n'
+    'РАЗГОВОР С ПЕРЕВОДОМ (два телефона, не путать с режимом «ПЕРЕВОДЧИК» выше):\n'
+    'Это отдельная функция для двух человек, каждый со своим телефоном, сидящих рядом — не один телефон на столе. '
+    'Каждый слышит в трубке только перевод речи собеседника. '
+    'Вызывай open_interpreter, если пользователь просит «поговорить с переводом», «разговор с переводчиком на два телефона», '
+    '«у нас у каждого телефон, переведи разговор», «отсканировать код для разговора с переводом» и т.п.\n'
+    '→ action="host", если пользователь начинает разговор сам (откроется экран с QR-кодом для собеседника).\n'
+    '→ action="join", если пользователь хочет отсканировать код собеседника (откроется сканер).\n'
+    'Инструмент сразу открывает нужный экран — больше ничего говорить не нужно.\n\n'
     'ПЕРЕКЛЮЧЕНИЕ РЕЖИМОВ:\n'
     '- При входе в режим — подтверди голосом какой режим активирован\n'
     '- "Сменить роль" / "выйди из роли" / "хватит" → вернись в обычный режим ассистента\n'
@@ -216,6 +224,14 @@
     '→ If the user named the language ("translator into Slovak", "translate between English and German") — call enter_translator_mode with lang_a and lang_b right away. Do not say anything — just call the tool.\n'
     '→ If the other person\'s language was NOT named — briefly ask "Which language should I translate into?" and call enter_translator_mode after the answer. Do not guess the language.\n'
     '→ Inside the translator the language is changed with "choose language X" / "translate into X"; exit with "stop translator".\n\n'
+    '"FACE-TO-FACE INTERPRETER" (two phones, not to be confused with "TRANSLATOR" mode above):\n'
+    'A separate feature for two people sitting together, each with their own phone — not one phone on the table. '
+    'Each person hears only the translation of the other in their own phone. '
+    'Call open_interpreter when the user asks to "talk with translation, we each have a phone", "interpreter call", '
+    '"scan the code for the translated call", etc.\n'
+    '→ action="host" if the user is starting the call themselves (opens a screen with a QR code for their partner).\n'
+    '→ action="join" if the user wants to scan their partner\'s code (opens the scanner).\n'
+    'The tool opens the right screen immediately — nothing more needs to be said.\n\n'
     'MODE SWITCHING:\n'
     '- When entering a mode — confirm by voice which mode is activated\n'
     '- "Switch role" / "exit role" / "enough" → return to normal assistant mode\n'
```

Патч к `lib/features/assistant/presentation/screens/assistant_screen.dart`:

```diff
--- a/lib/features/assistant/presentation/screens/assistant_screen.dart
+++ b/lib/features/assistant/presentation/screens/assistant_screen.dart
@@ -1241,6 +1241,49 @@
             }
           }
         }
+        return; // Skip the default sendEvent below — already sent
+      }
+      if (name == 'open_interpreter') {
+        Map<String, dynamic> args = const {};
+        try {
+          args = jsonDecode(argsJson) as Map<String, dynamic>;
+        } catch (_) {}
+        final action = args['action'] as String? ?? 'host';
+        debugPrint('[Assistant] tool open_interpreter (callId=$callId) action=$action');
+
+        // No confirmation needed — unlike start_call this doesn't spend
+        // money or ring anyone by itself, so answer right away.
+        _sendEvent({
+          'type': 'conversation.item.create',
+          'item': {
+            'type': 'function_call_output',
+            'call_id': callId,
+            'output': jsonEncode({'ok': true}),
+          },
+        });
+
+        unawaited(_chatLogger.flushNow());
+
+        // Same ordering as start_call: navigate first so `mounted` can't go
+        // false mid-navigation, then release the session — the interpreter
+        // screen needs the microphone this voice session is holding.
+        _navigatingToCall = true;
+        final route = action == 'join'
+            ? '/dashboard/interpreter?scan=1'
+            : '/dashboard/interpreter';
+        debugPrint('[Assistant] Navigating to interpreter: $route');
+
+        setState(() {
+          _state = _CallState.idle;
+          _muted = false;
+          _aiSpeaking = false;
+        });
+
+        if (mounted) {
+          context.push(route);
+        }
+
+        await _cleanup();
         return; // Skip the default sendEvent below — already sent
       }
       final args = argsJson.isEmpty
```

- [ ] **Step 2: Проверить**

```bash
flutter test test/features/interpreter test/features/assistant 2>&1 | tail -1
flutter analyze lib/features/assistant/tools/assistant_tools_schema.dart lib/features/assistant/tools/assistant_tools_executor.dart lib/features/assistant/tools/assistant_system_prompt.dart lib/features/assistant/presentation/screens/assistant_screen.dart 2>&1 | grep -c " • "; true
```

Ожидается: `+341: All tests passed!`; замечаний анализатора на изменённых старых файлах столько же, сколько до задачи: `9` (давние, не наши).

- [ ] **Step 3: Коммит**

```bash
git add lib/features/assistant/tools/assistant_tools_schema.dart lib/features/assistant/tools/assistant_tools_executor.dart lib/features/assistant/tools/assistant_system_prompt.dart lib/features/assistant/presentation/screens/assistant_screen.dart
git commit -m "feat(interpreter): инструмент ассистента open_interpreter" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 24: Проверка целиком

- [ ] **Step 1: Весь набор, анализатор, сборки**

```bash
flutter test 2>&1 | tail -1
flutter analyze lib/features/interpreter test/features/interpreter
flutter build apk --debug --flavor dev -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol 2>&1 | tail -1
(cd ios && pod install >/dev/null) && flutter build ios --debug --no-codesign --flavor dev -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol 2>&1 | tail -1
```

Ожидается:
- `+1911: All tests passed!` (до плана было 1672);
- `No issues found!`;
- `✓ Built build/app/outputs/flutter-apk/app-dev-debug.apk`;
- `✓ Built build/ios/iphoneos/Runner.app`.

- [ ] **Step 2: Ревью всей ветки**

Финальное ревью кода всей ветки `feat/interpreter` в мобилке (диапазон `origin/dev..HEAD`) и коммитов задач 1–3. Найденное оформляется задачами с буквой, как в планах 1 и 2: проверенный патч, исполнитель, повторное ревью.

---

## Исправления по финальному ревью (задачи с буквой)

Финальное ревью ветки (задача 24, шаг 2) и повторное ревью исправлений нашли то, что ниже. Выполняются после задачи 24, в этом порядке, до задачи 25. Числа в «Ожидается» — от состояния после задачи 24 и предыдущих задач этого раздела.

### Task 24b: Код из ссылки ведёт ко входу

- **Ссылка `talerid://interp/<код>` открывала раздел, но код пропадал (критично).** Системная камера, сканер профиля и вход после логина приводят к `InterpreterChoosing(joinCode)`, но `JoinPressed` не отправлял никто: человек видел обычный старт и должен был сканировать снова — первое, что попробует тестировщик. Теперь при ожидающем коде старт показывает «Вас пригласили…» и «Подключиться»: гость выбирает свой язык и входит, как в спеке. «Начать» в этот момент не показывается. Экрану не хватало теста — потому это и прошло; теперь он есть.

**Files:**
- Create: `test/features/interpreter/presentation/screens/interpreter_screen_test.dart`
- Modify: `test/features/interpreter/presentation/widgets/start_view_test.dart`, `lib/features/interpreter/presentation/screens/interpreter_screen.dart`, `lib/features/interpreter/presentation/widgets/start_view.dart`, `lib/l10n/app_en.arb`, `lib/l10n/app_ru.arb`
- Regenerate: `lib/l10n/app_localizations*.dart` (`flutter gen-l10n`)

- [ ] **Step 1: Тесты (падают)**

`test/features/interpreter/presentation/screens/interpreter_screen_test.dart` целиком:

```dart
import 'package:bloc_test/bloc_test.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/core/di/service_locator.dart';
import 'package:taler_id_mobile/core/theme/app_theme.dart';
import 'package:taler_id_mobile/features/interpreter/domain/interpreter_models.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_bloc.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_event.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/bloc/interpreter_state.dart';
import 'package:taler_id_mobile/features/interpreter/presentation/screens/interpreter_screen.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';

class _MockInterpreterBloc extends MockBloc<InterpreterEvent, InterpreterState>
    implements InterpreterBloc {}

const _catalog = InterpreterCatalog(
  enabled: true,
  languages: [InterpreterLanguage(code: 'ru', name: 'Русский')],
);

/// f1: a `talerid://interp/<code>` link must actually lead to joining — this
/// pumps the real screen (not just StartView in isolation) the way
/// `app_router.dart` builds it for that link, with the bloc it obtains from
/// GetIt (`sl<InterpreterBloc>(param1: ...)`, registered here the same way
/// `service_locator.dart` does it: `registerFactoryParam`) mocked out.
void main() {
  late _MockInterpreterBloc bloc;

  setUp(() {
    bloc = _MockInterpreterBloc();
    sl.registerFactoryParam<InterpreterBloc, String, void>((_, __) => bloc);
  });

  tearDown(() async {
    await sl.reset();
  });

  Widget wrap(Widget child) => MaterialApp(
        theme: AppTheme.dark,
        locale: const Locale('en'),
        supportedLocales: const [Locale('en')],
        localizationsDelegates: const [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        home: child,
      );

  testWidgets(
      'a pending joinCode reaches a Choosing screen with a "Join" button '
      'that fires JoinPressed with that code', (tester) async {
    const state = InterpreterChoosing(
      catalog: _catalog,
      myLang: 'ru',
      joinCode: 'ABCD2345',
    );
    when(() => bloc.state).thenReturn(state);
    whenListen(bloc, const Stream<InterpreterState>.empty(),
        initialState: state);

    await tester
        .pumpWidget(wrap(const InterpreterScreen(joinCode: 'ABCD2345')));
    await tester.pumpAndSettle();

    expect(find.text('Join'), findsOneWidget);
    expect(find.text('Start'), findsNothing);

    await tester.tap(find.text('Join'));
    await tester.pump();

    verify(() => bloc.add(const JoinPressed('ABCD2345'))).called(1);
  });
}
```

Патч к `test/features/interpreter/presentation/widgets/start_view_test.dart`:

```diff
--- a/test/features/interpreter/presentation/widgets/start_view_test.dart
+++ b/test/features/interpreter/presentation/widgets/start_view_test.dart
@@ -36,6 +36,7 @@
       onLanguageChosen: (_) {},
       onStart: () {},
       onScan: () {},
+      onJoin: (_) {},
     )));
 
     expect(find.text('I speak: Русский'), findsOneWidget);
@@ -49,6 +50,7 @@
       onLanguageChosen: (_) {},
       onStart: () => started = true,
       onScan: () {},
+      onJoin: (_) {},
     )));
 
     await tester.tap(find.text('Start'));
@@ -65,6 +67,7 @@
       onLanguageChosen: (_) {},
       onStart: () {},
       onScan: () => scanned = true,
+      onJoin: (_) {},
     )));
 
     await tester.tap(find.text('Scan QR'));
@@ -83,6 +86,7 @@
       onLanguageChosen: (code) => chosen = code,
       onStart: () {},
       onScan: () {},
+      onJoin: (_) {},
     )));
 
     await tester.tap(find.text('I speak: Русский'));
@@ -103,6 +107,7 @@
       onLanguageChosen: (_) {},
       onStart: () {},
       onScan: () {},
+      onJoin: (_) {},
     )));
 
     expect(
@@ -110,4 +115,73 @@
       findsOneWidget,
     );
   });
+
+  // f1: a code arriving via a scanned/deep-linked link must not be silently
+  // dropped on the plain start view — see interpreter_screen.dart's wiring
+  // and the "Вход (Б)" flow in the spec.
+  group('with a pending joinCode', () {
+    testWidgets(
+        'shows the invited hint and "Join" instead of "Start"; tapping '
+        '"Join" fires onJoin with that code', (tester) async {
+      String? joined;
+      await tester.pumpWidget(_wrap(StartView(
+        catalog: _catalog,
+        myLang: 'ru',
+        joinCode: 'ABCD2345',
+        onLanguageChosen: (_) {},
+        onStart: () {},
+        onScan: () {},
+        onJoin: (code) => joined = code,
+      )));
+
+      expect(
+        find.text(
+            'You were invited to a conversation with translation. Choose '
+            'your language and join.'),
+        findsOneWidget,
+      );
+      expect(find.text('Start'), findsNothing);
+      expect(find.text('Join'), findsOneWidget);
+
+      await tester.tap(find.text('Join'));
+      await tester.pump();
+
+      expect(joined, 'ABCD2345');
+    });
+
+    testWidgets('"Scan QR" is still shown', (tester) async {
+      await tester.pumpWidget(_wrap(StartView(
+        catalog: _catalog,
+        myLang: 'ru',
+        joinCode: 'ABCD2345',
+        onLanguageChosen: (_) {},
+        onStart: () {},
+        onScan: () {},
+        onJoin: (_) {},
+      )));
+
+      expect(find.text('Scan QR'), findsOneWidget);
+    });
+  });
+
+  testWidgets('without a joinCode, behaviour is unchanged: "Start" is shown, '
+      'no invited hint, no "Join"', (tester) async {
+    await tester.pumpWidget(_wrap(StartView(
+      catalog: _catalog,
+      myLang: 'ru',
+      onLanguageChosen: (_) {},
+      onStart: () {},
+      onScan: () {},
+      onJoin: (_) {},
+    )));
+
+    expect(find.text('Start'), findsOneWidget);
+    expect(find.text('Join'), findsNothing);
+    expect(
+      find.text(
+          'You were invited to a conversation with translation. Choose '
+          'your language and join.'),
+      findsNothing,
+    );
+  });
 }
```

Run: `flutter test test/features/interpreter/presentation/screens/interpreter_screen_test.dart test/features/interpreter/presentation/widgets/start_view_test.dart`
Expected: `test/features/interpreter/presentation/screens/interpreter_screen_test.dart` — не запускается (нет ещё кода, который он импортирует); `test/features/interpreter/presentation/widgets/start_view_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 1, падающих 1, не запустившихся файлов 2.

- [ ] **Step 2: Код**

Патч к `lib/features/interpreter/presentation/screens/interpreter_screen.dart`:

```diff
--- a/lib/features/interpreter/presentation/screens/interpreter_screen.dart
+++ b/lib/features/interpreter/presentation/screens/interpreter_screen.dart
@@ -34,9 +34,16 @@
 
   @override
   Widget build(BuildContext context) {
+    // Read on this (outer) context, not the one `create` receives: `provider`
+    // locks inherited-widget lookups for the whole duration of that callback
+    // (it only ever runs once, so it can't handle a locale change anyway),
+    // and `Localizations.localeOf` establishing a listener on it throws
+    // "Tried to listen to an InheritedWidget in a life-cycle that will never
+    // be called again" in debug builds every time this screen opens.
+    final localeCode = Localizations.localeOf(context).languageCode;
     return BlocProvider<InterpreterBloc>(
-      create: (ctx) => sl<InterpreterBloc>(
-        param1: Localizations.localeOf(ctx).languageCode,
+      create: (_) => sl<InterpreterBloc>(
+        param1: localeCode,
       )..add(Started(joinCode: joinCode)),
       child: _InterpreterView(scanFirst: scanFirst),
     );
@@ -181,13 +188,19 @@
         // listener) — this is just what shows behind/after it.
         return Center(child: CircularProgressIndicator(color: colors.primary));
 
-      case InterpreterChoosing(catalog: final catalog, myLang: final myLang):
+      case InterpreterChoosing(
+          catalog: final catalog,
+          myLang: final myLang,
+          joinCode: final joinCode,
+        ):
         return StartView(
           catalog: catalog,
           myLang: myLang,
+          joinCode: joinCode,
           onLanguageChosen: (code) => bloc.add(LanguageChosen(code)),
           onStart: () => bloc.add(const HostPressed()),
           onScan: _openScanner,
+          onJoin: (code) => bloc.add(JoinPressed(code)),
         );
 
       case InterpreterWorking(kind: final kind):
```

Патч к `lib/features/interpreter/presentation/widgets/start_view.dart`:

```diff
--- a/lib/features/interpreter/presentation/widgets/start_view.dart
+++ b/lib/features/interpreter/presentation/widgets/start_view.dart
@@ -8,23 +8,30 @@
 import 'language_picker_sheet.dart';
 
 /// Pre-session screen: pick a language, then either host a new call or scan
-/// a partner's QR code. [joinCode] is purely informational here — the
-/// screen that owns the bloc is the one that resumes a join once the
-/// language is picked; this view doesn't act on it.
+/// a partner's QR code. [joinCode] carries a code that arrived via a
+/// scanned/deep-linked `talerid://interp/<code>` link before any language
+/// was picked — per the spec's "Вход (Б)" flow the guest chooses a language
+/// first and only then joins, so while a code is pending this view swaps
+/// «Начать» for a short invitation hint and a «Подключиться» button that
+/// fires [onJoin] with that same code. «Сканировать QR» is shown either way.
 class StartView extends StatelessWidget {
   final InterpreterCatalog catalog;
   final String myLang;
+  final String? joinCode;
   final ValueChanged<String> onLanguageChosen;
   final VoidCallback onStart;
   final VoidCallback onScan;
+  final ValueChanged<String> onJoin;
 
   const StartView({
     super.key,
     required this.catalog,
     required this.myLang,
+    this.joinCode,
     required this.onLanguageChosen,
     required this.onStart,
     required this.onScan,
+    required this.onJoin,
   });
 
   Future<void> _openPicker(BuildContext context) async {
@@ -41,6 +48,7 @@
     final colors = AppColors.of(context);
     final l10n = AppLocalizations.of(context)!;
     final langName = interpreterLanguageName(catalog.languages, myLang);
+    final code = joinCode;
 
     return SafeArea(
       child: Padding(
@@ -72,14 +80,30 @@
               ),
             ),
             const SizedBox(height: 28),
-            SizedBox(
-              width: double.infinity,
-              height: 50,
-              child: ElevatedButton(
-                onPressed: onStart,
-                child: Text(l10n.interpreterStartButton),
+            if (code != null) ...[
+              Text(
+                l10n.interpreterInvitedHint,
+                textAlign: TextAlign.center,
+                style: TextStyle(color: colors.textSecondary, fontSize: 13),
               ),
-            ),
+              const SizedBox(height: 16),
+              SizedBox(
+                width: double.infinity,
+                height: 50,
+                child: ElevatedButton(
+                  onPressed: () => onJoin(code),
+                  child: Text(l10n.interpreterJoinButton),
+                ),
+              ),
+            ] else
+              SizedBox(
+                width: double.infinity,
+                height: 50,
+                child: ElevatedButton(
+                  onPressed: onStart,
+                  child: Text(l10n.interpreterStartButton),
+                ),
+              ),
             const SizedBox(height: 12),
             SizedBox(
               width: double.infinity,
```

Патч к `lib/l10n/app_en.arb`:

```diff
--- a/lib/l10n/app_en.arb
+++ b/lib/l10n/app_en.arb
@@ -2030,6 +2030,8 @@
   "interpreterStartButton": "Start",
   "interpreterScanButton": "Scan QR",
   "interpreterStartHint": "Both of you need a voice print. The host pays per minute.",
+  "interpreterInvitedHint": "You were invited to a conversation with translation. Choose your language and join.",
+  "interpreterJoinButton": "Join",
   "interpreterChooseLanguage": "Choose a language",
   "interpreterSearchLanguage": "Search language",
   "interpreterShowCode": "Show this code to your partner",
```

Патч к `lib/l10n/app_ru.arb`:

```diff
--- a/lib/l10n/app_ru.arb
+++ b/lib/l10n/app_ru.arb
@@ -2023,6 +2023,8 @@
   "interpreterStartButton": "Начать",
   "interpreterScanButton": "Сканировать QR",
   "interpreterStartHint": "Нужен образец голоса — ваш и собеседника. Платит тот, кто начал разговор.",
+  "interpreterInvitedHint": "Вас пригласили в разговор с переводом. Выберите свой язык и подключитесь.",
+  "interpreterJoinButton": "Подключиться",
   "interpreterChooseLanguage": "Выберите язык",
   "interpreterSearchLanguage": "Поиск языка",
   "interpreterShowCode": "Покажите код собеседнику",
```

Затем сгенерировать локализации:

```bash
flutter gen-l10n
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze lib/features/interpreter/presentation/screens/interpreter_screen.dart lib/features/interpreter/presentation/widgets/start_view.dart test/features/interpreter/presentation/screens/interpreter_screen_test.dart test/features/interpreter/presentation/widgets/start_view_test.dart
```

Ожидается: `+236: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/screens/interpreter_screen_test.dart test/features/interpreter/presentation/widgets/start_view_test.dart lib/features/interpreter/presentation/screens/interpreter_screen.dart lib/features/interpreter/presentation/widgets/start_view.dart lib/l10n/app_en.arb lib/l10n/app_ru.arb lib/l10n/app_localizations*.dart
git commit -m "fix(interpreter): код из ссылки ведёт ко входу — «Подключиться» вместо пустого старта" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 24c: Ассистент: `open_interpreter` только на мобильных

- Маршруты раздела есть только на мобильных, а инструмент предлагался и обрабатывался везде: на десктопе ассистент уводил бы на несуществующий маршрут. Теперь на десктопе инструмент отвечает «недоступно» и никуда не ведёт.

**Files:**
- Modify: `test/features/assistant/assistant_tools_schema_test.dart`, `lib/features/assistant/presentation/screens/assistant_screen.dart`, `lib/features/assistant/tools/assistant_tools_schema.dart`

- [ ] **Step 1: Тесты (падают)**

Патч к `test/features/assistant/assistant_tools_schema_test.dart`:

```diff
--- a/test/features/assistant/assistant_tools_schema_test.dart
+++ b/test/features/assistant/assistant_tools_schema_test.dart
@@ -64,6 +64,21 @@
     });
   });
 
+  group('open_interpreter schema', () {
+    // f2: the feature's routes exist only on mobile (LiveKit room +
+    // device-level earpiece/proximity plumbing has no desktop equivalent —
+    // see app_router.dart's `if (PlatformUtils.instance.isMobile)` route
+    // guard), so the tool itself should not be offered to the model
+    // elsewhere. `PlatformUtils.instance.isMobile` has no fake/override hook
+    // in this codebase and is `false` under `flutter test` on every host
+    // this repo builds on (same convention as
+    // interpreter_entry_button_test.dart), so this also doubles as "absent
+    // on desktop".
+    test('is not offered on this (desktop) test host', () {
+      expect(tools.where((t) => t['name'] == 'open_interpreter'), isEmpty);
+    });
+  });
+
   test('translator mode does not expose the pin tools (only its own two)', () {
     final translatorTools = assistantToolSchemas(translatorMode: true);
     final names = translatorTools.map((t) => t['name']).toSet();
```

Run: `flutter test test/features/assistant/assistant_tools_schema_test.dart`
Expected: `test/features/assistant/assistant_tools_schema_test.dart` — падают 1 из 6. Всего тестов 6, падающих 1.

- [ ] **Step 2: Код**

Патч к `lib/features/assistant/presentation/screens/assistant_screen.dart`:

```diff
--- a/lib/features/assistant/presentation/screens/assistant_screen.dart
+++ b/lib/features/assistant/presentation/screens/assistant_screen.dart
@@ -1244,6 +1244,28 @@
         return; // Skip the default sendEvent below — already sent
       }
       if (name == 'open_interpreter') {
+        // The schema already keeps this tool off non-mobile sessions (see
+        // assistant_tools_schema.dart), but answer gracefully instead of
+        // navigating to a `/dashboard/interpreter` route that doesn't exist
+        // there (app_router.dart only registers it when
+        // PlatformUtils.instance.isMobile) if it is ever called anyway.
+        if (!PlatformUtils.instance.isMobile) {
+          debugPrint('[Assistant] tool open_interpreter (callId=$callId) — not available on this platform');
+          _sendEvent({
+            'type': 'conversation.item.create',
+            'item': {
+              'type': 'function_call_output',
+              'call_id': callId,
+              'output': jsonEncode({
+                'error': 'not_available_on_this_platform',
+                'instruction':
+                    'Tell the user this feature is only available on the mobile app, not here.',
+              }),
+            },
+          });
+          _sendEvent({'type': 'response.create'});
+          return;
+        }
         Map<String, dynamic> args = const {};
         try {
           args = jsonDecode(argsJson) as Map<String, dynamic>;
```

Патч к `lib/features/assistant/tools/assistant_tools_schema.dart`:

```diff
--- a/lib/features/assistant/tools/assistant_tools_schema.dart
+++ b/lib/features/assistant/tools/assistant_tools_schema.dart
@@ -1,3 +1,5 @@
+import '../../../core/platform/platform_utils.dart';
+
 /// JSON tool schemas for the OpenAI Realtime session (flat format:
 /// `{'type': 'function', 'name': ..., 'description': ..., 'parameters': ...}`).
 /// Moved verbatim from assistant_screen.dart.
@@ -308,23 +310,31 @@
               'required': ['conversationId'],
             },
           },
-          {
-            'type': 'function',
-            'name': 'open_interpreter',
-            'description':
-                'Open "Разговор с переводом" — face-to-face interpreter for two people sitting together, each with their own phone, each hearing only the translation of the other (NOT the "one phone on the table" translator mode — that is enter_translator_mode). action="host" opens the start screen to begin a new session and show a QR code; action="join" opens the QR scanner to join a session someone else started. Use when the user asks to "поговорить с переводом", "разговор с переводчиком на два телефона", "включи перевод для разговора вдвоём, у нас по телефону", "сканировать код для разговора с переводом", or similar.',
-            'parameters': {
-              'type': 'object',
-              'properties': {
-                'action': {
-                  'type': 'string',
-                  'enum': ['host', 'join'],
-                  'description': '"host" to start a new session, "join" to scan a partner\'s code',
-                },
-              },
-              'required': ['action'],
-            },
-          },
+          // open_interpreter's routes exist only on mobile (LiveKit room +
+          // device-level earpiece/proximity plumbing has no desktop
+          // equivalent — see app_router.dart's own
+          // `if (PlatformUtils.instance.isMobile)` route guard), so the tool
+          // itself is not offered elsewhere. The handler in
+          // assistant_screen.dart also answers it with a graceful refusal
+          // instead of navigating, as a second line of defense.
+          if (PlatformUtils.instance.isMobile)
+            {
+              'type': 'function',
+              'name': 'open_interpreter',
+              'description':
+                  'Open "Разговор с переводом" — face-to-face interpreter for two people sitting together, each with their own phone, each hearing only the translation of the other (NOT the "one phone on the table" translator mode — that is enter_translator_mode). action="host" opens the start screen to begin a new session and show a QR code; action="join" opens the QR scanner to join a session someone else started. Use when the user asks to "поговорить с переводом", "разговор с переводчиком на два телефона", "включи перевод для разговора вдвоём, у нас по телефону", "сканировать код для разговора с переводом", or similar.',
+              'parameters': {
+                'type': 'object',
+                'properties': {
+                  'action': {
+                    'type': 'string',
+                    'enum': ['host', 'join'],
+                    'description': '"host" to start a new session, "join" to scan a partner\'s code',
+                  },
+                },
+                'required': ['action'],
+              },
+            },
           {
             'type': 'function',
             'name': 'send_message',
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter test/features/assistant 2>&1 | tail -1
```

Ожидается: `+346: All tests passed!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/assistant/assistant_tools_schema_test.dart lib/features/assistant/presentation/screens/assistant_screen.dart lib/features/assistant/tools/assistant_tools_schema.dart
git commit -m "fix(interpreter): open_interpreter только на мобильных" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 24d: Ссылка до входа — только на мобильных

- Код из ссылки, открытой до входа, запоминался и на десктопе, а после входа уводил на маршрут, которого там нет. Запоминание и продолжение — только на мобильных.

**Files:**
- Create: `test/core/router/post_login_redirect_test.dart`
- Modify: `lib/core/router/app_router.dart`, `lib/core/router/post_login_redirect.dart`

- [ ] **Step 1: Тесты (падают)**

`test/core/router/post_login_redirect_test.dart` целиком:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/core/di/service_locator.dart';
import 'package:taler_id_mobile/core/router/post_login_redirect.dart';
import 'package:taler_id_mobile/core/storage/secure_storage_service.dart';
import 'package:taler_id_mobile/core/utils/constants.dart';
import 'package:taler_id_mobile/features/interpreter/data/pending_interpreter_join.dart';
import 'package:taler_id_mobile/features/mail/domain/repositories/i_mail_repository.dart';
import 'package:taler_id_mobile/features/oauth/data/oauth_pending_request.dart';

class _MockOAuthPendingRequest extends Mock implements OAuthPendingRequest {}

class _MockSecureStorageService extends Mock implements SecureStorageService {}

class _MockMailRepository extends Mock implements IMailRepository {}

/// f3: `postLoginNavigate` consumed a pending face-to-face interpreter join
/// code regardless of platform, which on desktop would `context.go()` to
/// `/dashboard/interpreter/join/:code` — a route `app_router.dart` only
/// registers `if (PlatformUtils.instance.isMobile)`. `PlatformUtils.instance.
/// isMobile` has no fake/override hook in this codebase and is `false` under
/// `flutter test` on every host this repo builds on (same convention as
/// interpreter_entry_button_test.dart), so this test exercises exactly the
/// desktop path.
void main() {
  late _MockOAuthPendingRequest oauthPending;
  late PendingInterpreterJoin interpreterJoin;
  late _MockSecureStorageService storage;
  late _MockMailRepository mailRepo;

  setUp(() {
    oauthPending = _MockOAuthPendingRequest();
    interpreterJoin = PendingInterpreterJoin();
    storage = _MockSecureStorageService();
    mailRepo = _MockMailRepository();

    when(() => oauthPending.consume()).thenAnswer((_) async => null);
    when(() => storage.isOnboardingSeen).thenAnswer((_) async => true);
    when(() => storage.isMailSetupDismissed).thenAnswer((_) async => true);
    when(() => storage.isMailSetupConfirmed).thenAnswer((_) async => false);

    sl.registerSingleton<OAuthPendingRequest>(oauthPending);
    sl.registerSingleton<PendingInterpreterJoin>(interpreterJoin);
    sl.registerSingleton<SecureStorageService>(storage);
    sl.registerSingleton<IMailRepository>(mailRepo);
  });

  tearDown(() async {
    await sl.reset();
  });

  testWidgets(
      'a pending interpreter join code is ignored on this (desktop) test '
      'host — falls through to the normal default route instead of the '
      'mobile-only join route', (tester) async {
    interpreterJoin.save('ABCD2345');

    String? landedOn;
    final router = GoRouter(
      initialLocation: '/start',
      routes: [
        GoRoute(path: '/start', builder: (_, __) => const SizedBox()),
        GoRoute(
          path: RouteConstants.messenger,
          builder: (_, __) {
            landedOn = RouteConstants.messenger;
            return const SizedBox();
          },
        ),
        GoRoute(
          path: RouteConstants.interpreterJoin,
          builder: (_, state) {
            landedOn =
                '${RouteConstants.interpreter}/join/${state.pathParameters['code']}';
            return const SizedBox();
          },
        ),
      ],
    );

    await tester.pumpWidget(MaterialApp.router(routerConfig: router));
    await tester.pumpAndSettle();

    final context = router.routerDelegate.navigatorKey.currentContext!;
    await postLoginNavigate(context);
    await tester.pumpAndSettle();

    expect(landedOn, RouteConstants.messenger);
  });
}
```

Run: `flutter test test/core/router/post_login_redirect_test.dart`
Expected: `test/core/router/post_login_redirect_test.dart` — падают 1 из 1. Всего тестов 1, падающих 1.

- [ ] **Step 2: Код**

Патч к `lib/core/router/app_router.dart`:

```diff
--- a/lib/core/router/app_router.dart
+++ b/lib/core/router/app_router.dart
@@ -608,7 +608,12 @@
   // while logged out: same pattern as the native OAuth flow above — save the
   // code before sending the user to /login, so postLoginNavigate can resume
   // it, instead of just losing it to the generic protected-route check below.
-  if (state.matchedLocation.startsWith('${RouteConstants.interpreter}/join/')) {
+  // Mobile only — this route (and postLoginNavigate's resume of it) doesn't
+  // exist on desktop in the first place (app_router.dart's own
+  // `if (PlatformUtils.instance.isMobile)` route guard below), so saving the
+  // code here would just be lost work.
+  if (PlatformUtils.instance.isMobile &&
+      state.matchedLocation.startsWith('${RouteConstants.interpreter}/join/')) {
     try {
       final storage = sl<SecureStorageService>();
       final hasToken = await storage.hasRefreshToken;
```

Патч к `lib/core/router/post_login_redirect.dart`:

```diff
--- a/lib/core/router/post_login_redirect.dart
+++ b/lib/core/router/post_login_redirect.dart
@@ -22,11 +22,16 @@
     return;
   }
 
-  final pendingJoinCode = sl<PendingInterpreterJoin>().consume();
-  if (pendingJoinCode != null) {
-    if (!context.mounted) return;
-    context.go('${RouteConstants.interpreter}/join/$pendingJoinCode');
-    return;
+  // Mobile only — app_router.dart never registers the join route on desktop
+  // (`if (PlatformUtils.instance.isMobile)`), so consuming a pending code
+  // there would `context.go()` straight into a route that doesn't exist.
+  if (PlatformUtils.instance.isMobile) {
+    final pendingJoinCode = sl<PendingInterpreterJoin>().consume();
+    if (pendingJoinCode != null) {
+      if (!context.mounted) return;
+      context.go('${RouteConstants.interpreter}/join/$pendingJoinCode');
+      return;
+    }
   }
 
   final storage = sl<SecureStorageService>();
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter test/core/router 2>&1 | tail -1
```

Ожидается: `+263: All tests passed!`.

- [ ] **Step 4: Коммит**

```bash
git add test/core/router/post_login_redirect_test.dart lib/core/router/app_router.dart lib/core/router/post_login_redirect.dart
git commit -m "fix(interpreter): ожидающий код после входа — только на мобильных" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 24e: Закрытый BLoC завершает живой разговор

- Если экран исчез не через «Завершить» (программная смена маршрута), BLoC освобождал комнату у себя, но сервер об этом не узнавал — хост платил, пока сверка не заметит пропажу (~70 с). Теперь при закрытии в состоянии «хост с QR» или «разговор» уходит `end` (без ожидания, ошибки не важны: ручка идемпотентна).

**Files:**
- Modify: `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`, `lib/features/interpreter/presentation/bloc/interpreter_bloc.dart`

- [ ] **Step 1: Тесты (падают)**

Патч к `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`:

```diff
--- a/test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart
+++ b/test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart
@@ -961,14 +961,62 @@
     );
 
     test(
-        'closing the bloc tears down the room without ending the session on the server',
+        'closing the bloc while a session is live tears down the room AND '
+        'ends the session on the server — otherwise the host keeps being '
+        'billed until the ~70s reconciler notices', () async {
+      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
+      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
+      when(() => voice.getStatus())
+          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
+      when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
+      when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
+      when(() => repo.end('sess-1')).thenAnswer((_) async {});
+
+      bloc.add(const Started());
+      await Future.delayed(_tinyDelay);
+      bloc.add(const HostPressed());
+      await Future.delayed(_tinyDelay);
+      port.emit(const ParticipantJoined(_partnerIdentity));
+      await Future.delayed(_tinyDelay);
+      expect(bloc.state, isA<InterpreterActive>());
+
+      await bloc.close();
+
+      verify(() => device.leaveConversation()).called(1);
+      verify(() => repo.end('sess-1')).called(1);
+      expect(port.disconnected, isTrue);
+    });
+  });
+
+  group('f4: close() notifies the server while a session is live', () {
+    test('close while Hosting (no partner yet) ends the session once',
         () async {
       when(() => repo.catalog()).thenAnswer((_) async => _catalog());
       when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
       when(() => voice.getStatus())
           .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
       when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
+      when(() => repo.end('sess-1')).thenAnswer((_) async {});
+
+      bloc.add(const Started());
+      await Future.delayed(_tinyDelay);
+      bloc.add(const HostPressed());
+      await Future.delayed(_tinyDelay);
+      expect(bloc.state, isA<InterpreterHosting>());
+
+      await bloc.close();
+
+      verify(() => repo.end('sess-1')).called(1);
+    });
+
+    test('close while Active ends the session once', () async {
+      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
+      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
+      when(() => voice.getStatus())
+          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
+      when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
       when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
+      when(() => repo.end('sess-1')).thenAnswer((_) async {});
 
       bloc.add(const Started());
       await Future.delayed(_tinyDelay);
@@ -980,9 +1028,49 @@
 
       await bloc.close();
 
-      verify(() => device.leaveConversation()).called(1);
+      verify(() => repo.end('sess-1')).called(1);
+    });
+
+    test(
+        'close after the call already Ended (via EndPressed) does not end '
+        'the session again beyond what that flow already did', () async {
+      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
+      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
+      when(() => voice.getStatus())
+          .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
+      when(() => repo.create('ru')).thenAnswer((_) async => _hostedSession());
+      when(() => repo.get('sess-1')).thenAnswer((_) async => _activeView());
+      when(() => repo.end('sess-1')).thenAnswer((_) async {});
+
+      bloc.add(const Started());
+      await Future.delayed(_tinyDelay);
+      bloc.add(const HostPressed());
+      await Future.delayed(_tinyDelay);
+      port.emit(const ParticipantJoined(_partnerIdentity));
+      await Future.delayed(_tinyDelay);
+      bloc.add(const EndPressed());
+      await Future.delayed(_tinyDelay);
+      expect(bloc.state, isA<InterpreterEnded>());
+
+      await bloc.close();
+
+      // Exactly the one call EndPressed's own handler already made —
+      // close() must not pile another one on top of it.
+      verify(() => repo.end('sess-1')).called(1);
+    });
+
+    test('close while Choosing (no session ever started) never calls repo.end',
+        () async {
+      when(() => repo.catalog()).thenAnswer((_) async => _catalog());
+      when(() => langStore.initial(any(), any())).thenAnswer((_) async => 'ru');
+
+      bloc.add(const Started());
+      await Future.delayed(_tinyDelay);
+      expect(bloc.state, isA<InterpreterChoosing>());
+
+      await bloc.close();
+
       verifyNever(() => repo.end(any()));
-      expect(port.disconnected, isTrue);
     });
   });
 
```

Run: `flutter test test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`
Expected: `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart` — падают 3 из 43. Всего тестов 43, падающих 3.

- [ ] **Step 2: Код**

Патч к `lib/features/interpreter/presentation/bloc/interpreter_bloc.dart`:

```diff
--- a/lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
+++ b/lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
@@ -741,6 +741,22 @@
 
   @override
   Future<void> close() async {
+    final sessionId = _sessionId;
+    final current = state;
+    // The screen going away mid-call (a programmatic route change, not the
+    // «Завершить» button) must not leave the host billed until the ~70s
+    // reconciler notices — tell the server too, not just tear down locally.
+    // Fire-and-forget: close() must not block on the network, and the end
+    // route is idempotent, so a failure here is simply left to that same
+    // reconciler. Wrapped defensively — a call that throws synchronously
+    // (e.g. an unstubbed mock in a test that never exercises this path)
+    // must not stop teardown from running either.
+    if (sessionId != null &&
+        (current is InterpreterHosting || current is InterpreterActive)) {
+      try {
+        unawaited(repo.end(sessionId).catchError((_) {}));
+      } catch (_) {}
+    }
     await _teardownRoom();
     return super.close();
   }
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze lib/features/interpreter/presentation/bloc/interpreter_bloc.dart test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart
```

Ожидается: `+240: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
git commit -m "fix(interpreter): закрытый BLoC завершает живой разговор на сервере" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 24f: Мёртвый код из ссылки не застревает

- Код из ссылки возвращался на старт после каждой ошибки, и после «код истёк», «код уже использован», «это ваш код» и «код не найден» старт снова предлагал «Подключиться» с тем же мёртвым кодом, а «Начать» не появлялось, пока не выйти из раздела. Код живёт 5 минут, так что это реально. Теперь после этих четырёх ошибок старт возвращается без кода; после остальных (сеть, образец голоса, недоступность, средства хоста) код остаётся, чтобы можно было повторить.

**Files:**
- Modify: `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`, `lib/features/interpreter/presentation/bloc/interpreter_bloc.dart`, `lib/features/interpreter/presentation/bloc/interpreter_state.dart`

- [ ] **Step 1: Тесты (падают)**

Патч к `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`:

```diff
--- a/test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart
+++ b/test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart
@@ -634,6 +634,82 @@
     }
   });
 
+  group('a dead join code does not stick around', () {
+    const deadCodeKinds = [
+      InterpreterErrorKind.codeExpired,
+      InterpreterErrorKind.codeUsed,
+      InterpreterErrorKind.ownCode,
+      InterpreterErrorKind.codeNotFound,
+    ];
+
+    for (final kind in deadCodeKinds) {
+      blocTest<InterpreterBloc, InterpreterState>(
+        '${kind.name} drops the pending code from Failure.back, and '
+        'BackToStart lands on Choosing without it',
+        build: () {
+          when(() => repo.catalog()).thenAnswer((_) async => _catalog());
+          when(() => langStore.initial(any(), any()))
+              .thenAnswer((_) async => 'ru');
+          when(() => voice.getStatus())
+              .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
+          when(() => repo.join('JOIN99', 'ru'))
+              .thenThrow(InterpreterException(kind));
+          return bloc;
+        },
+        act: (b) async {
+          b.add(const Started(joinCode: 'JOIN99'));
+          await Future.delayed(_tinyDelay);
+          b.add(const JoinPressed('JOIN99'));
+          await Future.delayed(_tinyDelay);
+          b.add(const BackToStart());
+        },
+        expect: () => [
+          const InterpreterLoading(),
+          isA<InterpreterChoosing>()
+              .having((s) => s.joinCode, 'joinCode', 'JOIN99'),
+          const InterpreterWorking(InterpreterWorkKind.joining),
+          isA<InterpreterFailure>()
+              .having((s) => s.kind, 'kind', kind)
+              .having((s) => s.back?.joinCode, 'back.joinCode', isNull),
+          isA<InterpreterChoosing>()
+              .having((s) => s.joinCode, 'joinCode', isNull),
+        ],
+      );
+    }
+
+    blocTest<InterpreterBloc, InterpreterState>(
+      'a non-definitive failure (network) keeps the code so the guest can retry',
+      build: () {
+        when(() => repo.catalog()).thenAnswer((_) async => _catalog());
+        when(() => langStore.initial(any(), any()))
+            .thenAnswer((_) async => 'ru');
+        when(() => voice.getStatus())
+            .thenAnswer((_) async => const OwnerVoiceStatus(enrolled: true));
+        when(() => repo.join('JOIN99', 'ru')).thenThrow(
+            const InterpreterException(InterpreterErrorKind.network));
+        return bloc;
+      },
+      act: (b) async {
+        b.add(const Started(joinCode: 'JOIN99'));
+        await Future.delayed(_tinyDelay);
+        b.add(const JoinPressed('JOIN99'));
+        await Future.delayed(_tinyDelay);
+        b.add(const BackToStart());
+      },
+      expect: () => [
+        const InterpreterLoading(),
+        isA<InterpreterChoosing>()
+            .having((s) => s.joinCode, 'joinCode', 'JOIN99'),
+        const InterpreterWorking(InterpreterWorkKind.joining),
+        isA<InterpreterFailure>()
+            .having((s) => s.kind, 'kind', InterpreterErrorKind.network)
+            .having((s) => s.back?.joinCode, 'back.joinCode', 'JOIN99'),
+        isA<InterpreterChoosing>()
+            .having((s) => s.joinCode, 'joinCode', 'JOIN99'),
+      ],
+    );
+  });
+
   group('RetryPressed / BackToStart', () {
     blocTest<InterpreterBloc, InterpreterState>(
       'RetryPressed from a Failure returns to the Choosing it carries',
```

Run: `flutter test test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart`
Expected: `test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart` — падают 4 из 48. Всего тестов 48, падающих 4.

- [ ] **Step 2: Код**

Патч к `lib/features/interpreter/presentation/bloc/interpreter_bloc.dart`:

```diff
--- a/lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
+++ b/lib/features/interpreter/presentation/bloc/interpreter_bloc.dart
@@ -642,6 +642,19 @@
     emit(choosing);
   }
 
+  /// Backend codes that mean the join code itself is now dead, not just this
+  /// one attempt — offering it again on the start view (the deep-linked
+  /// code's whole reason for being there) would only repeat the same
+  /// definitive error, so [_emitRepoFailure] drops it from the Choosing it
+  /// falls back to. Every other code (network, voice print, unavailable,
+  /// host funds…) leaves the code in place so the guest can just retry.
+  static const _deadJoinCodeKinds = {
+    InterpreterErrorKind.codeExpired,
+    InterpreterErrorKind.codeUsed,
+    InterpreterErrorKind.ownCode,
+    InterpreterErrorKind.codeNotFound,
+  };
+
   /// Centralises what happens to a thrown repo/voice error: a bare
   /// `voice_print_required` reopens the gate when there is a pending
   /// action to resume; everything else — including `network`/`unknown` and
@@ -661,7 +674,15 @@
       emit(InterpreterNeedVoicePrint(then: pendingThen, code: pendingCode));
       return;
     }
-    emit(InterpreterFailure(kind: kind, back: back ?? _lastChoosing));
+    var effectiveBack = back ?? _lastChoosing;
+    if (_deadJoinCodeKinds.contains(kind) && effectiveBack?.joinCode != null) {
+      effectiveBack = effectiveBack!.withoutJoinCode();
+      // Kept in sync too: RetryPressed/BackToStart falls back to this very
+      // field whenever the caller passing `back` wasn't itself the current
+      // Failure's own `back` (e.g. a failure with no explicit `back` at all).
+      _lastChoosing = effectiveBack;
+    }
+    emit(InterpreterFailure(kind: kind, back: effectiveBack));
   }
 
   Future<void> _enterRoom({
```

Патч к `lib/features/interpreter/presentation/bloc/interpreter_state.dart`:

```diff
--- a/lib/features/interpreter/presentation/bloc/interpreter_state.dart
+++ b/lib/features/interpreter/presentation/bloc/interpreter_state.dart
@@ -65,6 +65,17 @@
         catalog: catalog,
         myLang: myLang ?? this.myLang,
         joinCode: joinCode,
+      );
+
+  /// Same catalog/language, but with no code left on screen — [copyWith]
+  /// has no way to force a nullable field back to `null`, and this is the
+  /// one place that needs to: a join code the server has just declared dead
+  /// (expired/used/own/not-found) must not keep coming back every time the
+  /// start view is reached, offering a retry that can only repeat the same
+  /// definitive error.
+  InterpreterChoosing withoutJoinCode() => InterpreterChoosing(
+        catalog: catalog,
+        myLang: myLang,
       );
 
   @override
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter 2>&1 | tail -1
flutter analyze lib/features/interpreter/presentation/bloc/interpreter_bloc.dart lib/features/interpreter/presentation/bloc/interpreter_state.dart test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart
```

Ожидается: `+245: All tests passed!`; `No issues found!`.

- [ ] **Step 4: Коммит**

```bash
git add test/features/interpreter/presentation/bloc/interpreter_bloc_test.dart lib/features/interpreter/presentation/bloc/interpreter_bloc.dart lib/features/interpreter/presentation/bloc/interpreter_state.dart
git commit -m "fix(interpreter): мёртвый код из ссылки не застревает на старте" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 24g: Ссылка на разговор на десктопе никуда не ведёт

- Вошедший пользователь десктопа, открыв `talerid://interp/<код>`, попадал на маршрут, которого на десктопе нет, — страница ошибки go_router. Разбор этой ссылки теперь только на мобильных, как и остальная фича.

**Files:**
- Modify: `test/core/router/deep_link_handler_test.dart`, `lib/core/router/deep_link_handler.dart`

- [ ] **Step 1: Тесты (падают)**

Патч к `test/core/router/deep_link_handler_test.dart`:

```diff
--- a/test/core/router/deep_link_handler_test.dart
+++ b/test/core/router/deep_link_handler_test.dart
@@ -9,7 +9,8 @@
 import 'package:taler_id_mobile/core/router/deep_link_handler.dart';
 
 void main() {
-  DeepLinkTarget? resolve(String url) => DeepLinkHandler.resolve(Uri.parse(url));
+  DeepLinkTarget? resolve(String url, {bool isMobile = true}) =>
+      DeepLinkHandler.resolve(Uri.parse(url), isMobile: isMobile);
 
   group('OAuth links', () {
     const hosts = [
@@ -72,18 +73,24 @@
     });
 
     test('interpreter join code over the custom scheme', () {
-      final t = resolve('talerid://interp/ABCD1234');
+      final t = resolve('talerid://interp/ABCD1234', isMobile: true);
       expect(t!.location, '/dashboard/interpreter/join/ABCD1234');
       expect(t.push, isFalse);
     });
 
     test('interpreter join link tolerates a trailing slash', () {
-      expect(resolve('talerid://interp/ABCD1234/')!.location,
+      expect(resolve('talerid://interp/ABCD1234/', isMobile: true)!.location,
           '/dashboard/interpreter/join/ABCD1234');
     });
 
     test('a talerid link to a different path is not an interpreter join', () {
-      expect(resolve('talerid://interp/code/extra'), isNull);
+      expect(resolve('talerid://interp/code/extra', isMobile: true), isNull);
+    });
+
+    test(
+        'desktop does not resolve an interpreter join link — the feature '
+        'is mobile-only (see InterpreterEntryButton)', () {
+      expect(resolve('talerid://interp/ABCD1234', isMobile: false), isNull);
     });
 
     test('an invite link without a token is not acted on', () {
```

Run: `flutter test test/core/router/deep_link_handler_test.dart`
Expected: `test/core/router/deep_link_handler_test.dart` — не запускается (нет ещё кода, который он импортирует). Всего тестов 0, падающих 0, не запустившихся файлов 1.

- [ ] **Step 2: Код**

Патч к `lib/core/router/deep_link_handler.dart`:

```diff
--- a/lib/core/router/deep_link_handler.dart
+++ b/lib/core/router/deep_link_handler.dart
@@ -3,6 +3,7 @@
 import 'package:go_router/go_router.dart';
 
 import '../../features/interpreter/domain/interpreter_code.dart';
+import '../platform/platform_utils.dart';
 import '../utils/constants.dart';
 
 /// Hosts whose OAuth links this app may act on. Mirrors the associated-domains
@@ -52,7 +53,7 @@
       return;
     }
 
-    final target = resolve(uri);
+    final target = resolve(uri, isMobile: PlatformUtils.instance.isMobile);
     if (target == null) return;
     // OAuth is pushed so the flow can be backed out of, returning the user to
     // wherever they were; the rest replace the location.
@@ -87,7 +88,18 @@
 
   /// Maps an incoming link to the in-app location it should open, or null when
   /// the app has nothing to do with it.
-  static DeepLinkTarget? resolve(Uri uri) {
+  ///
+  /// [isMobile] gates the interpreter branch below — kept as an injectable
+  /// parameter rather than this (static, pure) method reading
+  /// [PlatformUtils] itself, the same reason [InterpreterEntryButton] takes
+  /// the real platform check at its own call site: that global reads `false`
+  /// under `flutter test` on every host this repo builds on, which would
+  /// make the interpreter link silently stop resolving in every test, not
+  /// just the desktop ones. Defaults to `true` (the behaviour every other
+  /// branch here already has, since none of them are platform-gated) so
+  /// existing callers — including every test this method already had —
+  /// are unaffected unless they opt in.
+  static DeepLinkTarget? resolve(Uri uri, {bool isMobile = true}) {
     // OAuth native login (Universal Links / App Links):
     // https://<host>/oauth/auth?...
     //
@@ -147,9 +159,16 @@
 
     // Handle interpreter join links:
     // talerid://interp/{code}
-    final interpCode = codeFromScan(uri.toString());
-    if (interpCode != null) {
-      return DeepLinkTarget('/dashboard/interpreter/join/$interpCode');
+    //
+    // Mobile-only — the routes this resolves to don't exist on desktop (see
+    // InterpreterEntryButton, which hides the feature's own entry point the
+    // same way), so a logged-in desktop user opening one would otherwise
+    // land on go_router's error page instead of just not matching here.
+    if (isMobile) {
+      final interpCode = codeFromScan(uri.toString());
+      if (interpCode != null) {
+        return DeepLinkTarget('/dashboard/interpreter/join/$interpCode');
+      }
     }
 
     return null;
```

- [ ] **Step 3: Проверить**

```bash
flutter test test/features/interpreter test/core/router 2>&1 | tail -1
```

Ожидается: `+273: All tests passed!`.

- [ ] **Step 4: Коммит**

```bash
git add test/core/router/deep_link_handler_test.dart lib/core/router/deep_link_handler.dart
git commit -m "fix(interpreter): ссылка на разговор с переводом — только на мобильных" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 25: Выкатка на DEV и сборки для проверки

**Выполняет контроллер сам, не исполнитель-подагент.**

- [ ] **Step 1: Спросить пользователя**

Нужно явное «да» сразу на всё:
- пуш `feat/interpreter` в бэкенде (задачи 1–2), слияние в `dev`, пуш `dev`, деплой бэкенда на DEV;
- пуш `main` репозитория `taler_id_tests` (задача 3);
- пуш ветки `feat/interpreter` мобилки.

В `dev` мобилки ветка сейчас не сливается: `dev` собирает раздаваемый DEV-APK, а версию не поднимаем до релиза. Сборки для ручной проверки:
- Android — отдельный файл на бот-сервере, `http://77.73.131.137:8081/taler-id-dev-interpreter.apk`, не вместо `taler-id-dev.apk`;
- iPhone — `flutter run --release` на телефоне Дмитрия.

Без «да» — стоп.

- [ ] **Step 2: Бэкенд на DEV**

Повторить шаги 2, 3, 5 задачи 22 плана 2 для новых коммитов: пуш ветки, слияние в `dev` во временном worktree, деплой на DEV. Миграций нет.

Проверка с бот-сервера, из временного клона `taler_id_tests` (как в задаче 22 плана 2): `npm run test:interpreter-selftest` и `npm run test:interpreter`.

Ожидается: `60 passed, 0 failed` — прежние 58 и новые 14d, 14e.

- [ ] **Step 3: Android-сборка для проверки**

Dev-флейвор из ветки `feat/interpreter` на сборочном сервере `138.124.61.221`. Собирать во временном клоне, не в `~/taler_id_mobile`: этот чекаут собирает раздаваемые APK.

```bash
ssh dvolkov@77.73.131.137 'ssh prod-backend "D=\$(mktemp -d ~/tid-interp-apk.XXXX) && git clone -q --depth 1 -b feat/interpreter git@github.com:dvvolkovv/taler_id_mobile.git \$D && cd \$D && export PATH=\$HOME/flutter/bin:\$PATH && flutter pub get >/dev/null && flutter build apk --flavor dev --release -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol 2>&1 | tail -1 && cp build/app/outputs/flutter-apk/app-dev-release.apk ~/taler-id-dev-interpreter.apk; cd ~ && rm -rf \$D"'
ssh dvolkov@77.73.131.137 'scp prod-backend:~/taler-id-dev-interpreter.apk ~/builds/ && ssh prod-backend "rm -f ~/taler-id-dev-interpreter.apk" && ls -la ~/builds/taler-id-dev-interpreter.apk'
```

Подпись — debug-keystore сборочного хоста, как у `taler-id-dev.apk`. Поэтому APK ставится поверх установленного DEV-приложения: отпечаток `5508…4499` есть в `OUR_SIGNERS`.

- [ ] **Step 4: Эмулятор**

Пройти интеграционный UI-тест №2 из CLAUDE.md против DEV — проверка, что ничего вокруг не сломалось. Затем открыть раздел вручную:
- кнопка на вкладке «Звонки»;
- «Начать» → QR с отсчётом;
- «Новый код»;
- «Завершить».

---

### Task 26: Ручная проверка двумя людьми

**Пользователь с собеседником; контроллер готовит чек-лист и разбирает журналы.**

Нужны двое разных людей: один человек с двумя аккаунтами даёт почти немую сессию, его голос похож сам на себя примерно на 0,95. Телефоны: Android (APK из задачи 25) и iPhone (`flutter run --release`), оба на DEV, у обоих записан образец голоса.

Чек-лист (из спеки, раздел «Тестирование»):
- [ ] старт → QR → скан системной камерой и сканером раздела → вход;
- [ ] пара с синхронным движком (ru ↔ de) и пара с фразовым (ru ↔ sk);
- [ ] телефон у уха (экран гаснет), AirPods, проводные наушники; громкая связь не включается;
- [ ] своя речь в трубке не звучит, живой голос собеседника не звучит;
- [ ] выключенный микрофон, обрыв сети (авиарежим на 20 с), свёрнутое приложение (Android — уведомление foreground-сервиса);
- [ ] «Завершить» с каждой стороны; итоговый экран; у хоста — стоимость;
- [ ] ассистент: «начни разговор с переводом» и «отсканируй его код».

Журналы: `pm2 logs livekit-ai-agent` на DEV (без текста реплик), `GET /interpreter/sessions/:id` после конца разговора.

---

### Task 27: Контрольная точка перед TEST и PROD

Дать пользователю сводку по-русски:
- что проверено вручную;
- задержки на живой речи;
- что не так.

Затем спросить, как катить дальше. По CLAUDE.md путь такой: DEV → TEST → PROD, каждый шаг — отдельной командой пользователя.
1. Бэкенд и агент на TEST (`138.124.61.221`) и на PROD (DO app-ноды и `do-media`): миграции, `.env` (`INTERPRETER_ENABLED`, общий секрет), смоук `test:interpreter-selftest:prod` и `:talerid`.
2. Мобильный релиз по обычным правилам: поднять версию в `pubspec`, `/app/version` и `APP_RELEASES` (объявление — последним, когда на месте все платформы); сборки на все флейворы; TestFlight с заметками без эмодзи.
