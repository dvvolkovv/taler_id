# Разговор с переводом — план 2: бэкенд, биллинг, сквозные наборы

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Бэкенд ведёт разговоры с переводом:
- сессия с QR-кодом, вход по коду, данные собеседника;
- оплата хостом поминутно (новая статья прайса `interpreter`);
- запуск и остановка агента, его отчёт о завершении;
- периодическая сверка: кончились деньги, истёк срок, пропал агент, никто не отсканировал QR.

Вместе с этим — два улучшения агента из контрольной точки плана 1 и сквозные наборы `test:interpreter` и `test:interpreter-selftest`. Заканчивается выкаткой на DEV (только по «да» пользователя) и контрольной точкой перед планом 3 (мобилка).

**Architecture:** Новый Nest-модуль `src/interpreter/` из небольших файлов с узкими интерфейсами: языки (копия агентского списка с Jest-сверкой), образец голоса, код, клиент агента, обёртка LiveKit, сервис, сверка, guard секрета, контроллер. Сервис закрывает сессию одним путём для всех причин — условным переходом в `ENDED`, после которого побочные действия (стоп агента, закрытие биллинга, удаление комнаты) выполняет только тот, кто перевёл. Биллинг получает `assertCanStart` — проверку резерва без открытия сессии. Агент получает время по звуку во фразовом движке и сторож «речь есть, перевода нет».

**Tech Stack:**
- NestJS 11, Prisma 5.22 (PostgreSQL), Jest + ts-jest, class-validator, `@nestjs/schedule`.
- `livekit-server-sdk` 2.15 (`RoomServiceClient`, `AccessToken`, `TrackSource`).
- Redis (счётчик попыток входа).
- Агент: Node 20 на серверах, Node 26 локально, `node:test`.
- Сквозные наборы: `taler_id_tests` (TypeScript + ts-node, axios, `@livekit/rtc-node`), macOS `say` + `afconvert` для фикстур.

**Спека:** `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md` — синхронизирована с этим планом (раздел «Бэкенд» и таблицы ошибок, конфигурации и сбоев).

**Это план 2 из 3.** План 1 (агент и стенд) выполнен. План 3 — мобилка — пишется после контрольной точки в конце этого плана.

**Правила для исполнителя:**
- Бэкенд и агент — worktree `/Users/dmitry/taler-id/.worktrees/interpreter`, ветка `feat/interpreter`. Команды бэкенда — из корня worktree, команды агента — из `livekit-agent/`.
- В worktree свои `node_modules` (задача 0). Prisma-клиент генерируется в них, а не в общий `~/taler-id/node_modules`: иначе он перезапишет клиент основного чекаута.
- Локальной базы нет. Миграции пишутся руками; проверка — `DATABASE_URL=postgresql://u:p@localhost:5432/x npx prisma validate`, затем `npx prisma generate`.
- Тесты бэкенда: `npx jest src/interpreter src/billing src/voice/guards`. Полный `npx jest` содержит 4 давно падающих набора (`profile.service`, `mcp-server.factory`, `mcp/tools/*`) — к этой работе они не относятся.
- Типы: `npx tsc --noEmit -p tsconfig.build.json` — 0 ошибок. Конфиг без тестов: в `*.spec.ts` 64 давние ошибки типов.
- Тесты агента: `npm test` из `livekit-agent/` (Node 26, итог `ℹ pass N`) и `~/.nvm/versions/node/v20.20.2/bin/node --test` (Node 20, как на серверах, итог `# pass N`).
- Блок `diff` — патч от корня репозитория. Сохранить его в файл (программно, без перепечатывания) и применить `git apply <файл>` из корня worktree (для `taler_id_tests` — из `~/Downloads/taler_id_tests`). Не применился — стоп и отчёт.
- Блок «целиком» — файл слово в слово.
- Сквозные наборы — репозиторий `~/Downloads/taler_id_tests`, ветка `main`. В нём чужие правки: только `git add` перечисленных файлов, никогда `git add -A`.
- Каждый коммит — с двумя `-m`: сообщение и `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- Ничего не пушить и не деплоить без явного «да» пользователя (задача 22).
- Векторы образцов, токены, секреты и коды не печатать и не писать в логи.

## Уточнения спеки, внесённые вместе с этим планом

Спека уже синхронизирована (коммиты `5d3ef73`, `be75d6d`, `1a7e366`). Главное, в чём код бэкенда поправил её первоначальный текст:
1. **Коды ошибок — в `message`.** Глобальный фильтр пересобирает тело ответа; `code` он не сохранил бы. Таблица кодов — в спеке.
2. **Резерв проверяется без открытия биллинга.** `startSession` сразу начинает списание, поэтому при создании разговора — новый `GatingService.assertCanStart`.
3. **Исключения биллинга — обычные `Error`.** Без перехвата они стали бы `500`; сервис переводит их в `402`/`403` со своими кодами.
4. **Лимит попыток входа — счётчик в Redis на пользователя.** `@Throttle` в этом бэкенде считает по IP и срабатывает раньше проверки токена.
5. **`agentSeenAt`.** Сверка считает 60 с отсутствия агента от последнего раза, когда видела его в комнате.
6. **Новый старт заменяет свой QR.** Своя сессия в `waiting` закрывается как `hangup`, а не мешает начать заново.
7. **`RoomAccessGuard` закрыт для `interp-*`.** Иначе участник разговора своим токеном LiveKit мог бы включить в нём запись встречи.
8. **Почти одинаковые образцы** (косинус ≥ 0,99) отклоняются на бэкенде до открытия биллинга — `409 same_voice_print`.
9. **Завершение, отчёт агента, чтение сессии, сверка и самопроверка не зависят от выключателя.** Выключенная функция не должна держать платные разговоры и ломать смоук после деплоя.
10. **Агент:** время по звуку во фразовом движке; сторож `FATAL interpreter: no translation …`.
11. **По ревью кода** (раздел «Исправления по ревью», задачи 6b–20b): сверка закрывает биллинг, который не держит ни одна сессия; `agentSeenAt` только вперёд; ручки переводчика звонка, E2EE и музыки ожидания закрыты для `interp-*`; тело не того типа отвечает только кодом поля; в таблице ошибок — `same_voice_print` и `503` при создании.

## Карта файлов

**Бэкенд** (`src/interpreter/`, новый модуль):

| Файл | Что делает |
|---|---|
| `interpreter-languages.ts` | 81 язык агента, выбор движка для пары; Jest-сверка с `livekit-agent/*.js` |
| `voice-print.ts` | пригоден ли образец (192 конечных числа, ненулевая длина), «одинаковые образцы» |
| `interpreter-code.ts` | код QR: 8 символов без похожих, хэш, срок |
| `interpreter-agent.client.ts` | вызовы агента с секретом и таймаутами |
| `interpreter-livekit.service.ts` | комната, токен (только микрофон), агент в комнате? |
| `dto/*.ts` | тела запросов |
| `interpreter.service.ts` | создание, новый код, вход, чтение, завершение, отчёт агента, `close()` |
| `interpreter.reconciler.ts` | сверка раз в 10 с |
| `interpreter-secret.guard.ts` | `x-interpreter-secret` для отчёта агента |
| `interpreter.controller.ts`, `interpreter.module.ts` | ручки и модуль |

**Бэкенд, правки:** `src/billing/constants/feature-keys.ts`, `src/billing/services/{metering,gating}.service.ts` (+ спеки), `prisma/schema.prisma` + миграция `20261101120000_interpreter`, `src/app.module.ts`, `src/voice/guards/room-access.guard.ts` (+ спека), `.env.example`. По ревью: новый `src/voice/guards/not-interpreter-room.guard.ts` (+ спека) и `src/voice/voice.controller.ts`.

**Агент** (`livekit-agent/`): `realtime-phrase-session.js`, `phrase-session.js`, `translator-turns.js` (комментарий), `interpreter.js` и их тесты.

**Сквозные наборы** (`taler_id_tests`): `fixtures/interpreter/*`, `interpreter_test.ts`, `interpreter_selftest.ts`, `billing_test.ts`, `package.json`.

---

### Task 0: База

**Files:** нет изменений в коде.

- [ ] **Step 1: Ветка и зависимости бэкенда**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter && git branch --show-current && git status --short
npm ci --loglevel=error --no-audit --no-fund
DATABASE_URL=postgresql://u:p@localhost:5432/x npx prisma generate
```

Ожидается: ветка `feat/interpreter`, чистое дерево; `Generated Prisma Client` в `./node_modules/@prisma/client` worktree.

- [ ] **Step 2: Исходные числа**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
cd livekit-agent && npm test 2>&1 | grep -E "^ℹ (pass|fail)"
```

Ожидается:
- Jest: 7 наборов, 55 тестов, из них 5 падают — все в `src/billing/services/metering.service.spec.ts`. Это давняя поломка: фикстуры без `startedAt`, которое читает уборщик «зависших» сессий. Её чинит задача 1.
- `tsc-exit=0`.
- Агент: `ℹ pass 292`, `ℹ fail 0`.

---

### Task 1: Ключ `interpreter` в биллинге

Новая статья поминутного списания с потолком в 2 часа. Попутно чинится давняя поломка спеки метеринга: фикстуры сессий без `startedAt`, которое читает уборщик «зависших» сессий.

**Files:**
- Modify: `src/billing/constants/feature-keys.ts`, `src/billing/services/metering.service.ts`
- Modify: `src/billing/services/metering.service.spec.ts`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/billing/services/metering.service.spec.ts`:

```diff
--- a/src/billing/services/metering.service.spec.ts
+++ b/src/billing/services/metering.service.spec.ts
@@ -58,6 +58,7 @@
         userId: 'u1',
         featureKey: 'voice_assistant',
         status: 'active',
+        startedAt,
         lastMeteredAt: startedAt,
         totalSpentPlanck: 0n,
       },
@@ -112,6 +113,7 @@
         id: 's1',
         userId: 'u1',
         featureKey: 'voice_assistant',
+        startedAt: new Date(Date.now() - 10_000),
         lastMeteredAt: new Date(Date.now() - 10_000),
         totalSpentPlanck: 0n,
         contextRef: 'room42',
@@ -144,6 +146,7 @@
         id: 's1',
         userId: 'u1',
         featureKey: 'voice_assistant',
+        startedAt: new Date(Date.now() - 10_000),
         lastMeteredAt: new Date(Date.now() - 10_000),
         totalSpentPlanck: 0n,
       },
@@ -169,6 +172,7 @@
         id: 's1',
         userId: 'u1',
         featureKey: 'voice_assistant',
+        startedAt: new Date(Date.now() - 10_000),
         lastMeteredAt: new Date(Date.now() - 10_000),
         totalSpentPlanck: 0n,
       },
@@ -223,6 +227,7 @@
         userId: 'u1',
         featureKey: 'voice_assistant',
         status: 'active',
+        startedAt: new Date(Date.now() - 10_000),
         lastMeteredAt: new Date(Date.now() - 10_000),
         totalSpentPlanck: 0n,
       },
@@ -236,4 +241,68 @@
     expect(pricing.calculatePlanckCost).not.toHaveBeenCalled();
     expect(prisma.usageLog.create).not.toHaveBeenCalled();
   });
+
+  describe('interpreter', () => {
+    const now = new Date('2026-11-01T12:00:00Z');
+    const minutesAgo = (m: number) => new Date(now.getTime() - m * 60_000);
+    const conversation = (startedAt: Date) => ({
+      id: 's-int',
+      userId: 'host-1',
+      featureKey: 'interpreter',
+      status: 'active',
+      startedAt,
+      lastMeteredAt: minutesAgo(0.5),
+      totalSpentPlanck: 0n,
+      contextRef: 'interp-session-1',
+    });
+
+    beforeEach(() => {
+      jest.useFakeTimers({ now });
+      pricing.getConfig.mockResolvedValue({ billingEnforced: true });
+      pricing.calculatePlanckCost.mockResolvedValue(6_000_000n);
+      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
+      ledger.debit.mockResolvedValue({ id: 'tx1' });
+      ledger.getBalance.mockResolvedValue(999_999_999n);
+    });
+
+    afterEach(() => jest.useRealTimers());
+
+    it('meters the host by the minute', async () => {
+      // 90 minutes in: past a 1-hour cap, still inside the 2-hour one.
+      prisma.aiSession.findMany.mockResolvedValue([
+        conversation(minutesAgo(90)),
+      ]);
+
+      await service.tick();
+
+      expect(pricing.calculatePlanckCost).toHaveBeenCalledWith(
+        'interpreter',
+        0.5,
+      );
+      expect(ledger.debit).toHaveBeenCalledWith(
+        'host-1',
+        6_000_000n,
+        'SPEND',
+        expect.objectContaining({
+          featureKey: 'interpreter',
+          sessionId: 's-int',
+        }),
+      );
+      expect(gating.endSession).not.toHaveBeenCalled();
+    });
+
+    it('reaps a conversation older than 2 hours as terminated_stale', async () => {
+      prisma.aiSession.findMany.mockResolvedValue([
+        conversation(minutesAgo(121)),
+      ]);
+
+      await service.tick();
+
+      expect(gating.endSession).toHaveBeenCalledWith(
+        's-int',
+        'terminated_stale',
+      );
+      expect(ledger.debit).not.toHaveBeenCalled();
+    });
+  });
 });
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/billing/services/metering.service.spec.ts` — падают 2 из 8. Всего тестов 57, падающих 2.

- [ ] **Step 2: Код**

Патч к `src/billing/constants/feature-keys.ts`:

```diff
--- a/src/billing/constants/feature-keys.ts
+++ b/src/billing/constants/feature-keys.ts
@@ -5,6 +5,7 @@
   OUTBOUND_CALL: 'outbound_call',
   WHISPER_TRANSCRIBE: 'whisper_transcribe',
   MEETING_SUMMARY: 'meeting_summary',
+  INTERPRETER: 'interpreter',
 } as const;
 
 export type FeatureKey = (typeof FEATURE_KEYS)[keyof typeof FEATURE_KEYS];
```

Патч к `src/billing/services/metering.service.ts`:

```diff
--- a/src/billing/services/metering.service.ts
+++ b/src/billing/services/metering.service.ts
@@ -19,7 +19,12 @@
 // Minute-based features: cron debits elapsed time automatically.
 // whisper_transcribe is NOT here — it's a one-shot post-call debit owned by the transcription service.
 // web_search / meeting_summary are one-shot debits done by their owning service.
-const MINUTE_BASED = new Set(['voice_assistant', 'ai_twin', 'outbound_call']);
+const MINUTE_BASED = new Set([
+  'voice_assistant',
+  'ai_twin',
+  'outbound_call',
+  'interpreter',
+]);
 
 // Hard upper bound per session. If a client never calls closeVoiceSession
 // (app crash, network loss, old build without billingSessionId in the WS
@@ -31,6 +36,7 @@
   voice_assistant: 2,
   ai_twin: 1,
   outbound_call: 1,
+  interpreter: 2,
 };
 
 @Injectable()
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 7 наборов, 57 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/billing/constants/feature-keys.ts src/billing/services/metering.service.ts src/billing/services/metering.service.spec.ts
git commit -m "feat(billing): статья interpreter — поминутно, потолок 2 часа" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `GatingService.assertCanStart` — резерв без открытия биллинга

`startSession` сразу создаёт активную `AiSession`, и метеринг начинает списание. При создании разговора хоста нужно проверить заранее, а платить он начинает только со входа гостя. Поведение `startSession` не меняется.

**Files:**
- Modify: `src/billing/services/gating.service.ts`, `src/billing/services/gating.service.spec.ts`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/billing/services/gating.service.spec.ts`:

```diff
--- a/src/billing/services/gating.service.spec.ts
+++ b/src/billing/services/gating.service.spec.ts
@@ -131,6 +131,83 @@
     expect(s.id).toBe('sBoundary');
   });
 
+  it('startSession runs assertCanStart before opening the session', async () => {
+    const check = jest
+      .spyOn(service, 'assertCanStart')
+      .mockResolvedValue(undefined);
+    prisma.aiSession.create.mockResolvedValue({ id: 's4' });
+
+    await service.startSession('u1', 'interpreter', 'ctx-1');
+
+    expect(check).toHaveBeenCalledWith('u1', 'interpreter');
+    expect(check.mock.invocationCallOrder[0]).toBeLessThan(
+      prisma.aiSession.create.mock.invocationCallOrder[0],
+    );
+  });
+
+  describe('assertCanStart', () => {
+    it('passes without opening a session, so nothing is metered yet', async () => {
+      pricing.getConfig.mockResolvedValue(baseConfig);
+      prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
+      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
+      ledger.getBalance.mockResolvedValue(24_000_000n);
+
+      await expect(
+        service.assertCanStart('u1', 'interpreter'),
+      ).resolves.toBeUndefined();
+
+      expect(pricing.getMinReservePlanck).toHaveBeenCalledWith('interpreter');
+      expect(prisma.aiSession.create).not.toHaveBeenCalled();
+      expect(gateway.emitToUser).not.toHaveBeenCalled();
+    });
+
+    it('creates the wallet before reading the balance', async () => {
+      pricing.getConfig.mockResolvedValue(baseConfig);
+      prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
+      pricing.getMinReservePlanck.mockResolvedValue(1n);
+      ledger.getBalance.mockResolvedValue(1n);
+
+      await service.assertCanStart('u1', 'interpreter');
+
+      expect(wallet.getOrCreate).toHaveBeenCalledWith('u1');
+      expect(wallet.getOrCreate.mock.invocationCallOrder[0]).toBeLessThan(
+        ledger.getBalance.mock.invocationCallOrder[0],
+      );
+    });
+
+    it('throws FeatureDisabledException when the toggle is off', async () => {
+      pricing.getConfig.mockResolvedValue(baseConfig);
+      prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });
+
+      await expect(service.assertCanStart('u1', 'interpreter')).rejects.toThrow(
+        FeatureDisabledException,
+      );
+    });
+
+    it('throws InsufficientFundsException below the reserve', async () => {
+      pricing.getConfig.mockResolvedValue(baseConfig);
+      prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
+      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
+      ledger.getBalance.mockResolvedValue(23_999_999n);
+
+      await expect(service.assertCanStart('u1', 'interpreter')).rejects.toThrow(
+        InsufficientFundsException,
+      );
+    });
+
+    it('only logs when billing is not enforced', async () => {
+      pricing.getConfig.mockResolvedValue({ billingEnforced: false });
+      prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });
+      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
+      ledger.getBalance.mockResolvedValue(0n);
+
+      await expect(
+        service.assertCanStart('u1', 'interpreter'),
+      ).resolves.toBeUndefined();
+      expect(prisma.aiSession.create).not.toHaveBeenCalled();
+    });
+  });
+
   it('endSession marks completed and does NOT emit ai_session_terminated', async () => {
     prisma.aiSession.update.mockResolvedValue({
       id: 's1',
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/billing/services/gating.service.spec.ts` — падают 6 из 15. Всего тестов 63, падающих 6.

- [ ] **Step 2: Код**

Патч к `src/billing/services/gating.service.ts`:

```diff
--- a/src/billing/services/gating.service.ts
+++ b/src/billing/services/gating.service.ts
@@ -30,6 +30,41 @@
     featureKey: string,
     contextRef?: string,
   ): Promise<{ id: string }> {
+    await this.assertCanStart(userId, featureKey);
+
+    const session = await this.prisma.aiSession.create({
+      data: {
+        userId,
+        featureKey,
+        contextRef,
+        status: 'active',
+      },
+      select: { id: true },
+    });
+
+    // Notify all of this user's sockets that an AI session just became active.
+    // Mobile can use this to show a "session live" indicator or close any pre-session modal.
+    try {
+      this.gateway.emitToUser(userId, 'ai_session_started', {
+        sessionId: session.id,
+        featureKey,
+      });
+    } catch (err) {
+      this.log.warn(
+        `emitToUser ai_session_started failed for ${userId}: ${String(err)}`,
+      );
+    }
+
+    return session;
+  }
+
+  /**
+   * The checks of startSession without opening a session, so nothing is
+   * metered: for a feature that must refuse up front but bills only later
+   * (the interpreter checks the host when the QR is shown and opens billing
+   * when the guest joins). Throws the same exceptions as startSession.
+   */
+  async assertCanStart(userId: string, featureKey: string): Promise<void> {
     // Ensure a wallet exists before any balance check or session creation. This is
     // idempotent — if the wallet already exists, it's a single findUnique.
     await this.wallet.getOrCreate(userId);
@@ -59,31 +94,6 @@
         `[dry-run] insufficient funds for ${userId}/${featureKey}: need ${minReserve}, have ${balance}`,
       );
     }
-
-    const session = await this.prisma.aiSession.create({
-      data: {
-        userId,
-        featureKey,
-        contextRef,
-        status: 'active',
-      },
-      select: { id: true },
-    });
-
-    // Notify all of this user's sockets that an AI session just became active.
-    // Mobile can use this to show a "session live" indicator or close any pre-session modal.
-    try {
-      this.gateway.emitToUser(userId, 'ai_session_started', {
-        sessionId: session.id,
-        featureKey,
-      });
-    } catch (err) {
-      this.log.warn(
-        `emitToUser ai_session_started failed for ${userId}: ${String(err)}`,
-      );
-    }
-
-    return session;
   }
 
   async endSession(
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 7 наборов, 63 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/billing/services/gating.service.ts src/billing/services/gating.service.spec.ts
git commit -m "feat(billing): assertCanStart — проверка резерва без открытия сессии" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Модель `InterpreterSession`, миграция и строка прайса

Таблица разговоров, два enum-а и строка `AiPricebook`. SQL в миграции получен `prisma migrate diff` и обёрнут коротким `lock_timeout`, как в `20260930120000_partner_api`. Строка прайса — с `ON CONFLICT DO NOTHING`, чтобы не затереть цену, заведённую руками.

**Files:**
- Modify: `prisma/schema.prisma`
- Create: `prisma/migrations/20261101120000_interpreter/migration.sql`

- [ ] **Step 1: Код**

Патч к `prisma/schema.prisma`:

```diff
--- a/prisma/schema.prisma
+++ b/prisma/schema.prisma
@@ -51,6 +51,9 @@
   /// Партнёр, который завёл этот аккаунт (партнёрский API). Пока человек не задал пароль TalerID, аккаунт для этого партнёра «управляемый».
   createdByPartnerId   String?
   createdByPartner     Partner?              @relation(fields: [createdByPartnerId], references: [id], onDelete: Restrict)
+  /// Разговоры с переводом: где человек показал QR и где вошёл по чужому.
+  interpreterHosted    InterpreterSession[]  @relation("InterpreterHost")
+  interpreterJoined    InterpreterSession[]  @relation("InterpreterGuest")
 }
 
 model DeviceKey {
@@ -1202,3 +1205,49 @@
   @@unique([partnerId, userAId, userBId])
   @@index([userAId, userBId])
 }
+
+enum InterpreterStatus {
+  WAITING
+  ACTIVE
+  ENDED
+}
+
+enum InterpreterEndReason {
+  HANGUP
+  PARTNER_LEFT
+  NO_FUNDS
+  MAX_DURATION
+  TRANSLATION_FAILED
+  AGENT_LOST
+  EXPIRED
+}
+
+/// Разговор с переводом: двое рядом, у каждого свой телефон.
+/// Спека: docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
+model InterpreterSession {
+  id               String                @id @default(uuid())
+  roomName         String                @unique
+  hostId           String
+  guestId          String?
+  hostLang         String
+  guestLang        String?
+  /// sha256 кода из QR. Есть только у ожидающей сессии: вход гостя и завершение его стирают.
+  codeHash         String?               @unique
+  codeExpiresAt    DateTime?
+  status           InterpreterStatus     @default(WAITING)
+  /// AiSession хоста (interpreter): открывается при входе гостя, ожидание не тарифицируется.
+  billingSessionId String?               @db.Uuid
+  /// Когда сверка последний раз видела агента в комнате; отсюда отсчёт до agent_lost.
+  agentSeenAt      DateTime?
+  startedAt        DateTime?
+  endedAt          DateTime?
+  endReason        InterpreterEndReason?
+  createdAt        DateTime              @default(now())
+  updatedAt        DateTime              @updatedAt
+  host             User                  @relation("InterpreterHost", fields: [hostId], references: [id], onDelete: Cascade)
+  guest            User?                 @relation("InterpreterGuest", fields: [guestId], references: [id], onDelete: Cascade)
+
+  @@index([hostId, status])
+  @@index([guestId, status])
+  @@index([status, codeExpiresAt])
+}
```

`prisma/migrations/20261101120000_interpreter/migration.sql` целиком:

```sql
-- Разговор с переводом: двое рядом, у каждого свой телефон.
-- Спека: docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
--
-- Всё аддитивно: два enum'а, новая таблица и строка прайса. Старый код о них не
-- знает, поэтому миграцию можно накатить до рестарта нод.
--
-- Prisma гонит этот файл одной неявной транзакцией. Если `prisma migrate
-- deploy` упадёт по lock_timeout ниже — откатится весь файл, и перед повтором
-- нужно сначала снять пометку "failed":
--   npx prisma migrate resolve --rolled-back 20261101120000_interpreter

-- Короткий lock_timeout: внешние ключи на "User" ниже встают в очередь за живыми
-- записями в эту таблицу и, пока ждут, задерживают новые. Лучше упасть быстро и
-- повторить, чем подвесить прод. LOCAL — чтобы настройка закончилась вместе с
-- транзакцией этой миграции и не утекла в следующие на том же соединении.
SET LOCAL lock_timeout = '5s';

-- CreateEnum
CREATE TYPE "InterpreterStatus" AS ENUM ('WAITING', 'ACTIVE', 'ENDED');

-- CreateEnum
CREATE TYPE "InterpreterEndReason" AS ENUM ('HANGUP', 'PARTNER_LEFT', 'NO_FUNDS', 'MAX_DURATION', 'TRANSLATION_FAILED', 'AGENT_LOST', 'EXPIRED');

-- CreateTable
CREATE TABLE "InterpreterSession" (
    "id" TEXT NOT NULL,
    "roomName" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "guestId" TEXT,
    "hostLang" TEXT NOT NULL,
    "guestLang" TEXT,
    "codeHash" TEXT,
    "codeExpiresAt" TIMESTAMP(3),
    "status" "InterpreterStatus" NOT NULL DEFAULT 'WAITING',
    "billingSessionId" UUID,
    "agentSeenAt" TIMESTAMP(3),
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "endReason" "InterpreterEndReason",
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InterpreterSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "InterpreterSession_roomName_key" ON "InterpreterSession"("roomName");

-- CreateIndex
CREATE UNIQUE INDEX "InterpreterSession_codeHash_key" ON "InterpreterSession"("codeHash");

-- CreateIndex
CREATE INDEX "InterpreterSession_hostId_status_idx" ON "InterpreterSession"("hostId", "status");

-- CreateIndex
CREATE INDEX "InterpreterSession_guestId_status_idx" ON "InterpreterSession"("guestId", "status");

-- CreateIndex
CREATE INDEX "InterpreterSession_status_codeExpiresAt_idx" ON "InterpreterSession"("status", "codeExpiresAt");

-- AddForeignKey
ALTER TABLE "InterpreterSession" ADD CONSTRAINT "InterpreterSession_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InterpreterSession" ADD CONSTRAINT "InterpreterSession_guestId_fkey" FOREIGN KEY ("guestId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Статья прайса. Себестоимость $0.07/мин — два синхронных потока
-- gpt-realtime-translate по $0.034; наценка общая, ×2. Резерв — две минуты по
-- курсу сида (1 TAL = $11 700): 2 × $0.14 / 11 700 × 10¹² ≈ 24M planck.
-- Дальше цена правится админской ручкой прайса, без релиза.
-- ON CONFLICT: строку могли завести руками до миграции — её и подобранную цену не трогаем.
INSERT INTO "AiPricebook" (id, "featureKey", unit, "costUsdPerUnit", "markupMultiplier", "minReservePlanck", "updatedAt") VALUES
  ('pb_interpreter', 'interpreter', 'minute', 0.07, 2.0, 24000000, NOW())
ON CONFLICT ("featureKey") DO NOTHING;
```

- [ ] **Step 2: Проверить**

```bash
DATABASE_URL=postgresql://u:p@localhost:5432/x npx prisma validate && DATABASE_URL=postgresql://u:p@localhost:5432/x npx prisma generate
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 7 наборов, 63 тестов, все зелёные; `tsc-exit=0`, `The schema at prisma/schema.prisma is valid`.

- [ ] **Step 3: Коммит**

```bash
git add prisma/schema.prisma prisma/migrations/20261101120000_interpreter/migration.sql
git commit -m "feat(interpreter): модель InterpreterSession, миграция и строка прайса" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Языки и выбор движка

Копия 81 языка агента и правила выбора движка. Импортировать `livekit-agent/*.js` в бэкенд нельзя (сборка не кладёт его в `dist/`), поэтому — копия и спека, которая сверяет её с агентскими файлами.

**Files:**
- Create: `src/interpreter/interpreter-languages.ts`, `src/interpreter/interpreter-languages.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter-languages.spec.ts` целиком:

```ts
import {
  INTERPRETER_LANGUAGES,
  SIMULTANEOUS_SOURCES,
  SIMULTANEOUS_TARGETS,
  engineFor,
  isSupportedLang,
} from './interpreter-languages';

// The agent's own tables. They are outside jest's rootDir and outside dist/,
// which is why the backend keeps a copy — and this spec is that copy's check.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const agentNames = require('../../livekit-agent/lang-names.js') as {
  LANG_NAMES: Record<string, string>;
  SUPPORTED_LANGS: string[];
};
// eslint-disable-next-line @typescript-eslint/no-require-imports
const agentEngines = require('../../livekit-agent/interpreter-langs.js') as {
  SIMULTANEOUS_TARGETS: Set<string>;
  SIMULTANEOUS_SOURCES: Set<string>;
  chooseEngine: (sourceLang: string, targetLang: string) => string;
};

describe('interpreter languages: the copy matches the agent', () => {
  it('offers exactly the agent languages, in its order and with its names', () => {
    expect(INTERPRETER_LANGUAGES.map((l) => l.code)).toEqual(
      agentNames.SUPPORTED_LANGS,
    );
    expect(
      Object.fromEntries(INTERPRETER_LANGUAGES.map((l) => [l.code, l.name])),
    ).toEqual(agentNames.LANG_NAMES);
    expect(INTERPRETER_LANGUAGES).toHaveLength(81);
  });

  it('picks engines from the same two sets', () => {
    expect(SIMULTANEOUS_TARGETS).toEqual(agentEngines.SIMULTANEOUS_TARGETS);
    expect(SIMULTANEOUS_SOURCES).toEqual(agentEngines.SIMULTANEOUS_SOURCES);
  });

  it('chooses the agent engine for every pair a person can pick', () => {
    const mismatches: string[] = [];
    for (const { code: source } of INTERPRETER_LANGUAGES) {
      for (const { code: target } of INTERPRETER_LANGUAGES) {
        if (
          engineFor(source, target) !==
          agentEngines.chooseEngine(source, target)
        ) {
          mismatches.push(`${source}→${target}`);
        }
      }
    }
    expect(mismatches).toEqual([]);
  });
});

describe('isSupportedLang', () => {
  it('accepts a language the agent speaks', () => {
    expect(isSupportedLang('ru')).toBe(true);
    expect(isSupportedLang('zu')).toBe(true);
  });

  it('refuses regions, unknown codes, other cases and non-strings', () => {
    for (const code of ['pt-BR', 'xx', 'RU', '', 'dz', 42, null, undefined]) {
      expect(isSupportedLang(code)).toBe(false);
    }
  });
});

describe('engineFor', () => {
  it('is simultaneous when the model hears the speaker and speaks the listener language', () => {
    expect(engineFor('ru', 'de')).toBe('simultaneous');
    expect(engineFor('de', 'ru')).toBe('simultaneous');
  });

  it('falls back to phrases when the listener language is not a target', () => {
    expect(engineFor('ru', 'sk')).toBe('phrase');
  });

  it('falls back to phrases when the speaker language is not a source', () => {
    expect(engineFor('am', 'en')).toBe('phrase');
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter-languages.spec.ts` не запускается: `Cannot find module './interpreter-languages'`. Всего тестов 63, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter-languages.ts` целиком:

```ts
/**
 * Languages of the face-to-face interpreter, by ISO 639-1 code, and which
 * engine renders each pair.
 *
 * A copy of the agent's tables (livekit-agent/lang-names.js and
 * livekit-agent/interpreter-langs.js): the build does not put livekit-agent/
 * into dist/, so the backend cannot require them at run time.
 * interpreter-languages.spec.ts compares the copy with the originals. A code
 * the backend accepts and the agent refuses would only surface after the
 * host's billing had opened, as a 503 to the guest.
 */

export const INTERPRETER_LANGUAGES: ReadonlyArray<{
  code: string;
  name: string;
}> = [
  { code: 'af', name: 'Afrikaans' },
  { code: 'am', name: 'Amharic' },
  { code: 'ar', name: 'Arabic' },
  { code: 'az', name: 'Azerbaijani' },
  { code: 'be', name: 'Belarusian' },
  { code: 'bg', name: 'Bulgarian' },
  { code: 'bn', name: 'Bengali' },
  { code: 'bs', name: 'Bosnian' },
  { code: 'ca', name: 'Catalan' },
  { code: 'cs', name: 'Czech' },
  { code: 'cy', name: 'Welsh' },
  { code: 'da', name: 'Danish' },
  { code: 'de', name: 'German' },
  { code: 'el', name: 'Greek' },
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Spanish' },
  { code: 'et', name: 'Estonian' },
  { code: 'eu', name: 'Basque' },
  { code: 'fa', name: 'Persian' },
  { code: 'fi', name: 'Finnish' },
  { code: 'fr', name: 'French' },
  { code: 'ga', name: 'Irish' },
  { code: 'gl', name: 'Galician' },
  { code: 'gu', name: 'Gujarati' },
  { code: 'ha', name: 'Hausa' },
  { code: 'he', name: 'Hebrew' },
  { code: 'hi', name: 'Hindi' },
  { code: 'hr', name: 'Croatian' },
  { code: 'hu', name: 'Hungarian' },
  { code: 'hy', name: 'Armenian' },
  { code: 'id', name: 'Indonesian' },
  { code: 'is', name: 'Icelandic' },
  { code: 'it', name: 'Italian' },
  { code: 'ja', name: 'Japanese' },
  { code: 'jv', name: 'Javanese' },
  { code: 'ka', name: 'Georgian' },
  { code: 'kk', name: 'Kazakh' },
  { code: 'km', name: 'Khmer' },
  { code: 'kn', name: 'Kannada' },
  { code: 'ko', name: 'Korean' },
  { code: 'lo', name: 'Lao' },
  { code: 'lt', name: 'Lithuanian' },
  { code: 'lv', name: 'Latvian' },
  { code: 'mk', name: 'Macedonian' },
  { code: 'ml', name: 'Malayalam' },
  { code: 'mn', name: 'Mongolian' },
  { code: 'mr', name: 'Marathi' },
  { code: 'ms', name: 'Malay' },
  { code: 'mt', name: 'Maltese' },
  { code: 'my', name: 'Myanmar' },
  { code: 'ne', name: 'Nepali' },
  { code: 'nl', name: 'Dutch' },
  { code: 'no', name: 'Norwegian' },
  { code: 'pa', name: 'Punjabi' },
  { code: 'pl', name: 'Polish' },
  { code: 'ps', name: 'Pashto' },
  { code: 'pt', name: 'Portuguese' },
  { code: 'ro', name: 'Romanian' },
  { code: 'ru', name: 'Russian' },
  { code: 'si', name: 'Sinhala' },
  { code: 'sk', name: 'Slovak' },
  { code: 'sl', name: 'Slovenian' },
  { code: 'so', name: 'Somali' },
  { code: 'sq', name: 'Albanian' },
  { code: 'sr', name: 'Serbian' },
  { code: 'su', name: 'Sundanese' },
  { code: 'sv', name: 'Swedish' },
  { code: 'sw', name: 'Swahili' },
  { code: 'ta', name: 'Tamil' },
  { code: 'te', name: 'Telugu' },
  { code: 'tg', name: 'Tajik' },
  { code: 'th', name: 'Thai' },
  { code: 'tl', name: 'Filipino' },
  { code: 'tr', name: 'Turkish' },
  { code: 'uk', name: 'Ukrainian' },
  { code: 'ur', name: 'Urdu' },
  { code: 'uz', name: 'Uzbek' },
  { code: 'vi', name: 'Vietnamese' },
  { code: 'yo', name: 'Yoruba' },
  { code: 'zh', name: 'Chinese' },
  { code: 'zu', name: 'Zulu' },
];

const CODES: ReadonlySet<string> = new Set(
  INTERPRETER_LANGUAGES.map((l) => l.code),
);

export function isSupportedLang(code: unknown): code is string {
  return typeof code === 'string' && CODES.has(code);
}

export type EngineKind = 'simultaneous' | 'phrase';

/** Languages gpt-realtime-translate speaks: the listener's side of a pair. */
export const SIMULTANEOUS_TARGETS: ReadonlySet<string> = new Set(
  'en es pt fr ja ru zh de ko hi id vi it'.split(' '),
);

/**
 * Languages gpt-realtime-translate hears: the speaker's side of a pair. Wider
 * than INTERPRETER_LANGUAGES, as copied from OpenAI's list.
 */
export const SIMULTANEOUS_SOURCES: ReadonlySet<string> = new Set(
  (
    'af ar az be bg bn bs ca cs cy da de dz el en eo es et eu fa fi fr gl gu ' +
    'he hi hr ht hu hy id it ja jv ka kk ko ku la lt lv mi mk ml mn ms my ne ' +
    'nl nn no pa pl pt ro ru sk sl sn sq sr sv sw te th tl tr uk uz vi yo zh'
  ).split(' '),
);

/**
 * How speech in sourceLang reaches a listener in targetLang: simultaneously,
 * or phrase by phrase on the full realtime model when the translate model
 * cannot do the pair. Tells each side what to expect before the agent starts.
 */
export function engineFor(sourceLang: string, targetLang: string): EngineKind {
  return SIMULTANEOUS_TARGETS.has(targetLang) &&
    SIMULTANEOUS_SOURCES.has(sourceLang)
    ? 'simultaneous'
    : 'phrase';
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 8 наборов, 71 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter-languages.ts src/interpreter/interpreter-languages.spec.ts
git commit -m "feat(interpreter): языки и выбор движка, сверка с агентом" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Пригодность образца голоса

Агент отказывает паре без двух пригодных образцов, а к тому моменту биллинг уже открыт. Поэтому бэкенд проверяет то же заранее: 192 конечных числа с ненулевой длиной (сумма квадратов, не `Math.hypot`) и не почти одинаковые образцы у двоих.

**Files:**
- Create: `src/interpreter/voice-print.ts`, `src/interpreter/voice-print.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/voice-print.spec.ts` целиком:

```ts
import {
  SAME_PRINT_COSINE,
  VOICE_PRINT_DIM,
  hasUsableVoicePrint,
} from './voice-print';

// The agent's own rules, which these constants copy (see voice-print.ts).
// eslint-disable-next-line @typescript-eslint/no-require-imports
const agentRouting = require('../../livekit-agent/interpreter-routing.js') as {
  EMBEDDING_DIM: number;
  SAME_PRINT_COSINE: number;
};

const print = (value: number) => Array<number>(VOICE_PRINT_DIM).fill(value);

describe('voice print rules: the copy matches the agent', () => {
  it('uses the print length and same-print threshold of the agent', () => {
    expect(VOICE_PRINT_DIM).toBe(agentRouting.EMBEDDING_DIM);
    expect(SAME_PRINT_COSINE).toBe(agentRouting.SAME_PRINT_COSINE);
  });
});

describe('hasUsableVoicePrint', () => {
  it('accepts 192 finite numbers with a length', () => {
    expect(VOICE_PRINT_DIM).toBe(192);
    expect(hasUsableVoicePrint(print(0.07))).toBe(true);
    expect(hasUsableVoicePrint([1, ...print(0).slice(1)])).toBe(true);
  });

  it('refuses the empty default and anything that is not an array', () => {
    for (const e of [[], null, undefined, 'x', 42, { length: 192 }]) {
      expect(hasUsableVoicePrint(e)).toBe(false);
    }
  });

  it('refuses a print of the wrong length', () => {
    expect(hasUsableVoicePrint(print(0.1).slice(1))).toBe(false);
    expect(hasUsableVoicePrint([...print(0.1), 0.1])).toBe(false);
  });

  it('refuses non-finite and non-numeric elements, and holes', () => {
    for (const bad of [NaN, Infinity, -Infinity, '0.1', null]) {
      const e: unknown[] = print(0.1);
      e[100] = bad;
      expect(hasUsableVoicePrint(e)).toBe(false);
    }
    expect(hasUsableVoicePrint(new Array(VOICE_PRINT_DIM))).toBe(false);
  });

  it('refuses a print with no length: all zeros', () => {
    expect(hasUsableVoicePrint(print(0))).toBe(false);
  });

  it('refuses prints whose squares underflow or overflow, which Math.hypot would pass', () => {
    const tiny = print(1e-170);
    const huge = print(1e170);
    // The point of not using hypot: it rescales and reports a usable length.
    expect(Math.hypot(...tiny)).toBeGreaterThan(0);
    expect(Number.isFinite(Math.hypot(...huge))).toBe(true);

    expect(hasUsableVoicePrint(tiny)).toBe(false);
    expect(hasUsableVoicePrint(huge)).toBe(false);
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/voice-print.spec.ts` не запускается: `Cannot find module './voice-print'`. Всего тестов 71, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/voice-print.ts` целиком:

```ts
/** Length of an ECAPA voice print, as stored in Profile.ownerEmbedding. */
export const VOICE_PRINT_DIM = 192;

/**
 * Two prints at least this alike (cosine) leave the voice gate nothing to
 * tell apart: one person behind two accounts, or a broken enrollment.
 * Different people's prints sit far below it; a copy, rescaled or not, at 1.
 * Mirrors SAME_PRINT_COSINE in livekit-agent/interpreter-routing.js, which
 * refuses such a pair — but only after the host's billing has opened.
 */
export const SAME_PRINT_COSINE = 0.99;

/**
 * Whether the agent's voice gate can score speech against this print.
 *
 * The same rule as checkPerson in livekit-agent/interpreter-routing.js: the
 * agent refuses any other print, but by then the host's billing is open, so
 * the backend refuses first. A sum of squares, not Math.hypot: hypot rescales
 * internally and reports a usable length for prints whose squares underflow to
 * 0 or overflow to Infinity — the very prints the agent's cosine cannot use.
 */
export function hasUsableVoicePrint(e: unknown): e is number[] {
  if (!Array.isArray(e) || e.length !== VOICE_PRINT_DIM) return false;
  let sumOfSquares = 0;
  // An index loop, not every(): every() skips holes.
  for (let i = 0; i < VOICE_PRINT_DIM; i++) {
    const v: unknown = e[i];
    if (typeof v !== 'number' || !Number.isFinite(v)) return false;
    sumOfSquares += v * v;
  }
  return sumOfSquares > 0 && Number.isFinite(sumOfSquares);
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 9 наборов, 78 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/voice-print.ts src/interpreter/voice-print.spec.ts
git commit -m "feat(interpreter): пригодность образца голоса, сверка порогов с агентом" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Код для QR

8 символов из 32 без похожих (около 40 бит), живёт 5 минут; в базе — только sha256.

**Files:**
- Create: `src/interpreter/interpreter-code.ts`, `src/interpreter/interpreter-code.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter-code.spec.ts` целиком:

```ts
import { createHash } from 'crypto';
import {
  CODE_ALPHABET,
  CODE_LENGTH,
  CODE_TTL_MS,
  generateCode,
  hashCode,
  normalizeCode,
} from './interpreter-code';

describe('interpreter code', () => {
  it('is 8 characters of base32 without look-alikes, alive for 5 minutes', () => {
    expect(CODE_ALPHABET).toBe('ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
    expect(CODE_LENGTH).toBe(8);
    expect(CODE_TTL_MS).toBe(300_000);
  });

  it('generates codes from the alphabet only, and not the same code twice', () => {
    const codes = Array.from({ length: 500 }, () => generateCode());
    for (const code of codes) expect(code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it('normalizes what a person types: case, spaces and dashes', () => {
    expect(normalizeCode('abcd-efgh')).toBe('ABCDEFGH');
    expect(normalizeCode(' AB CD EF 23 ')).toBe('ABCDEF23');
  });

  it('refuses anything that cannot be a code', () => {
    for (const raw of [
      'ABCDEFG', // too short
      'ABCDEFGH2', // too long
      'ABCDEFGI', // I is not in the alphabet
      'ABCDEFG0', // nor is 0
      'ABCD_EFG',
      '',
      42,
      null,
      undefined,
    ]) {
      expect(normalizeCode(raw)).toBeNull();
    }
  });

  it('hashes a code as sha256 hex, so only the hash is stored', () => {
    expect(hashCode('ABCDEFGH')).toBe(
      createHash('sha256').update('ABCDEFGH').digest('hex'),
    );
    expect(hashCode('ABCDEFGH')).not.toContain('ABCDEFGH');
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter-code.spec.ts` не запускается: `Cannot find module './interpreter-code'`. Всего тестов 78, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter-code.ts` целиком:

```ts
import { createHash, randomInt } from 'crypto';

/**
 * The one-time code in the host's QR (talerid://interp/<code>). Base32 without
 * I, O, 0 and 1, so it can also be read off the screen and typed. Eight
 * characters are 40 bits: with a 5-minute life, one use and a per-user limit
 * on join attempts, guessing a live code is out of reach.
 */
export const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const CODE_LENGTH = 8;
export const CODE_TTL_MS = 5 * 60_000;

const CODE_SHAPE = new RegExp(`^[${CODE_ALPHABET}]{${CODE_LENGTH}}$`);

export function generateCode(): string {
  let code = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  }
  return code;
}

/** The code as generated, or null if the input cannot be one. */
export function normalizeCode(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const code = raw.toUpperCase().replace(/[\s-]/g, '');
  return CODE_SHAPE.test(code) ? code : null;
}

/** Only the hash is stored: a leaked row must not let anyone join. */
export function hashCode(code: string): string {
  return createHash('sha256').update(code).digest('hex');
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 10 наборов, 83 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter-code.ts src/interpreter/interpreter-code.spec.ts
git commit -m "feat(interpreter): код для QR — генерация, нормализация, хэш" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Клиент агента

Вызовы `/interpreter/start|stop|selftest` с секретом `x-interpreter-secret` и таймаутами. Без секрета запрос не уходит: в теле старта — образцы голоса обоих. Тело запроса не попадает ни в ошибки, ни в логи.

**Files:**
- Create: `src/interpreter/interpreter-agent.client.ts`, `src/interpreter/interpreter-agent.client.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter-agent.client.spec.ts` целиком:

```ts
import { Logger } from '@nestjs/common';
import {
  AgentCallError,
  AgentStartBody,
  InterpreterAgentClient,
} from './interpreter-agent.client';

// Digits that appear nowhere but in the voice prints.
const MARK = 0.987654321;
const startBody: AgentStartBody = {
  sessionId: 's-1',
  roomName: 'interp-1',
  participants: [
    { userId: 'host-1', lang: 'ru', embedding: Array(192).fill(MARK) },
    { userId: 'guest-1', lang: 'de', embedding: Array(192).fill(-MARK) },
  ],
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

describe('InterpreterAgentClient', () => {
  const saved = {
    url: process.env.AI_AGENT_URL,
    secret: process.env.INTERPRETER_SHARED_SECRET,
  };
  let client: InterpreterAgentClient;
  let fetchFn: jest.Mock;
  let timeout: jest.SpyInstance;
  let logs: jest.SpyInstance[];

  beforeEach(() => {
    process.env.AI_AGENT_URL = 'http://agent.test:3100/';
    process.env.INTERPRETER_SHARED_SECRET = 'shh';
    client = new InterpreterAgentClient();
    fetchFn = jest.fn();
    client.fetchFn = fetchFn;
    timeout = jest.spyOn(AbortSignal, 'timeout');
    logs = (['log', 'warn', 'error'] as const).map((level) =>
      jest.spyOn(Logger.prototype, level).mockImplementation(() => undefined),
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
    for (const [key, value] of [
      ['AI_AGENT_URL', saved.url],
      ['INTERPRETER_SHARED_SECRET', saved.secret],
    ] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  /** Neither the error nor anything logged may carry a voice print. */
  const expectNoVoicePrint = (err?: unknown) => {
    const seen = JSON.stringify([
      err instanceof Error ? [err.message, err.stack] : err,
      logs.map((spy) => spy.mock.calls),
    ]);
    expect(seen).not.toContain('987654321');
  };

  describe('start', () => {
    it('posts both participants with the secret and a 35 s timeout', async () => {
      fetchFn.mockResolvedValue(json({ status: 'started' }));

      await client.start(startBody);

      const [url, init] = fetchFn.mock.calls[0];
      expect(url).toBe('http://agent.test:3100/interpreter/start');
      expect(init.method).toBe('POST');
      expect(init.headers).toEqual({
        'Content-Type': 'application/json',
        'x-interpreter-secret': 'shh',
      });
      expect(JSON.parse(init.body)).toEqual(startBody);
      expect(timeout).toHaveBeenCalledWith(35_000);
      expect(init.signal).toBe(timeout.mock.results[0].value);
    });

    it('accepts a start that is already running', async () => {
      fetchFn.mockResolvedValue(json({ status: 'already_running' }));
      await expect(client.start(startBody)).resolves.toBeUndefined();
    });

    it('turns a refusal into an AgentCallError with the agent status', async () => {
      fetchFn.mockResolvedValue(
        json({ error: 'participants have the same voice print' }, 400),
      );

      const err = await client.start(startBody).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(AgentCallError);
      expect((err as AgentCallError).status).toBe(400);
      expectNoVoicePrint(err);
    });

    it('reports an agent it could not reach as status 0', async () => {
      fetchFn.mockRejectedValue(
        Object.assign(new TypeError('fetch failed'), {
          cause: { code: 'ECONNREFUSED' },
        }),
      );

      const err = await client.start(startBody).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(AgentCallError);
      expect((err as AgentCallError).status).toBe(0);
      expect((err as AgentCallError).message).toContain('ECONNREFUSED');
      expectNoVoicePrint(err);
    });

    it('does not send the voice prints without the secret', async () => {
      delete process.env.INTERPRETER_SHARED_SECRET;

      await expect(client.start(startBody)).rejects.toBeInstanceOf(
        AgentCallError,
      );
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('defaults to the agent on localhost', async () => {
      delete process.env.AI_AGENT_URL;
      fetchFn.mockResolvedValue(json({ status: 'started' }));

      await client.start(startBody);

      expect(fetchFn.mock.calls[0][0]).toBe(
        'http://localhost:3100/interpreter/start',
      );
    });
  });

  describe('stop', () => {
    it('posts the room with the secret and a 10 s timeout', async () => {
      fetchFn.mockResolvedValue(json({ status: 'stopped' }));

      await client.stop('interp-1');

      const [url, init] = fetchFn.mock.calls[0];
      expect(url).toBe('http://agent.test:3100/interpreter/stop');
      expect(init.method).toBe('POST');
      expect(init.headers['x-interpreter-secret']).toBe('shh');
      expect(JSON.parse(init.body)).toEqual({ roomName: 'interp-1' });
      expect(timeout).toHaveBeenCalledWith(10_000);
    });

    it('never throws: the session is closing either way', async () => {
      fetchFn.mockRejectedValueOnce(new TypeError('fetch failed'));
      await expect(client.stop('interp-1')).resolves.toBeUndefined();

      fetchFn.mockResolvedValueOnce(json({ error: 'boom' }, 500));
      await expect(client.stop('interp-1')).resolves.toBeUndefined();

      delete process.env.INTERPRETER_SHARED_SECRET;
      await expect(client.stop('interp-1')).resolves.toBeUndefined();

      expect(logs[1]).toHaveBeenCalledTimes(3);
    });
  });

  describe('selftest', () => {
    it('passes the agent answer through with its status', async () => {
      fetchFn.mockResolvedValue(
        json({ ok: false, reason: 'phrase: 404' }, 500),
      );

      await expect(client.selftest()).resolves.toEqual({
        status: 500,
        body: { ok: false, reason: 'phrase: 404' },
      });
      const [url, init] = fetchFn.mock.calls[0];
      expect(url).toBe('http://agent.test:3100/interpreter/selftest');
      expect(init.method).toBe('GET');
      expect(init.body).toBeUndefined();
      expect(init.headers['x-interpreter-secret']).toBe('shh');
      expect(timeout).toHaveBeenCalledWith(25_000);
    });

    it('answers 503 when the agent cannot be reached', async () => {
      fetchFn.mockRejectedValue(
        new DOMException('The operation timed out.', 'TimeoutError'),
      );

      await expect(client.selftest()).resolves.toEqual({
        status: 503,
        body: { ok: false, reason: expect.stringContaining('unreachable') },
      });
    });
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter-agent.client.spec.ts` не запускается: `Cannot find module './interpreter-agent.client'`. Всего тестов 83, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter-agent.client.ts` целиком:

```ts
import { Injectable, Logger } from '@nestjs/common';

export interface AgentParticipant {
  userId: string;
  lang: string;
  embedding: number[];
}

export interface AgentStartBody {
  sessionId: string;
  roomName: string;
  participants: [AgentParticipant, AgentParticipant];
}

/**
 * The agent could not be reached or refused. Carries no part of the request
 * on purpose: a start request holds both people's voice prints.
 */
export class AgentCallError extends Error {
  constructor(
    /** The agent's HTTP status, 0 when there was no answer. */
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'AgentCallError';
  }
}

const DEFAULT_AGENT_URL = 'http://localhost:3100';
// The agent bounds its LiveKit connect at 15 s and then publishes two tracks;
// a start answered after we gave up would leave it running unasked.
const START_TIMEOUT_MS = 35_000;
const STOP_TIMEOUT_MS = 10_000;
// The selftest opens both engines' OpenAI sessions in parallel, 10 s each at most.
const SELFTEST_TIMEOUT_MS = 25_000;

/**
 * The backend's side of the agent's interpreter routes
 * (livekit-agent/interpreter-routes.js). Every call carries
 * INTERPRETER_SHARED_SECRET and has its own timeout: unlike the older agent
 * calls, these sit on a person's request or on the reconciler's tick.
 */
@Injectable()
export class InterpreterAgentClient {
  private readonly log = new Logger(InterpreterAgentClient.name);

  /** The HTTP call itself; specs replace it. */
  fetchFn: typeof fetch = (input, init) => fetch(input, init);

  /** Resolves once the agent is in the room; any other outcome throws AgentCallError. */
  async start(body: AgentStartBody): Promise<void> {
    const res = await this.call(
      'POST',
      '/interpreter/start',
      START_TIMEOUT_MS,
      body,
    );
    discardBody(res);
    if (!res.ok) {
      throw new AgentCallError(
        res.status,
        `agent refused start: ${res.status}`,
      );
    }
  }

  /** Best effort: the session is closing either way, so failures are only logged. */
  async stop(roomName: string): Promise<void> {
    const body = { roomName };
    try {
      const res = await this.call(
        'POST',
        '/interpreter/stop',
        STOP_TIMEOUT_MS,
        body,
      );
      discardBody(res);
      if (!res.ok) {
        this.log.warn(`stop for ${roomName}: agent answered ${res.status}`);
      }
    } catch (e) {
      this.log.warn(`stop for ${roomName} failed: ${errorText(e)}`);
    }
  }

  /** The agent's own answer and status; 503 when there was none. */
  async selftest(): Promise<{ status: number; body: unknown }> {
    try {
      const res = await this.call(
        'GET',
        '/interpreter/selftest',
        SELFTEST_TIMEOUT_MS,
      );
      return { status: res.status, body: await res.json() };
    } catch (e) {
      return { status: 503, body: { ok: false, reason: errorText(e) } };
    }
  }

  /** Returns any answer as is; throws AgentCallError(0) when there is none. */
  private async call(
    method: 'GET' | 'POST',
    path: string,
    timeoutMs: number,
    body?: object,
  ): Promise<Response> {
    const secret = process.env.INTERPRETER_SHARED_SECRET;
    // The agent would refuse anyway, but a start must not carry voice prints
    // out of the backend on a request that cannot be authorised.
    if (!secret) {
      throw new AgentCallError(0, 'INTERPRETER_SHARED_SECRET is not set');
    }
    const base = (process.env.AI_AGENT_URL || DEFAULT_AGENT_URL).replace(
      /\/+$/,
      '',
    );
    try {
      return await this.fetchFn(base + path, {
        method,
        headers: {
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          'x-interpreter-secret': secret,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new AgentCallError(0, `agent unreachable: ${errorText(e)}`);
    }
  }
}

/** fetch resolves on the headers; an unread body would keep the socket busy. */
function discardBody(res: Response): void {
  void res.body?.cancel().catch(() => undefined);
}

/** Why a call failed: fetch names the cause (refused, timed out), never the request. */
function errorText(e: unknown): string {
  if (!(e instanceof Error)) return String(e);
  const code = (e.cause as { code?: unknown } | undefined)?.code;
  return typeof code === 'string' ? `${e.message} (${code})` : e.message;
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 11 наборов, 93 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter-agent.client.ts src/interpreter/interpreter-agent.client.spec.ts
git commit -m "feat(interpreter): клиент агента — секрет, таймауты, без образцов в ошибках" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Комната и токен LiveKit

Комната `interp-<uuid>` на 4 места, токен только на микрофон и без данных, проверка «агент в комнате?» с таймаутом 2 с. Сбой LiveKit — `null`, а не «агента нет»: по неизвестному ничего не закрывается.

**Files:**
- Create: `src/interpreter/interpreter-livekit.service.ts`, `src/interpreter/interpreter-livekit.service.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter-livekit.service.spec.ts` целиком:

```ts
import { Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { RoomServiceClient } from 'livekit-server-sdk';
import { LK_API_SECRET } from '../common/livekit-credentials';
import { makeParticipantIdentity } from '../common/participant-identity';
import { InterpreterLivekitService } from './interpreter-livekit.service';

jest.mock('livekit-server-sdk', () => ({
  ...jest.requireActual('livekit-server-sdk'),
  RoomServiceClient: jest.fn(),
}));

describe('InterpreterLivekitService', () => {
  const savedWsUrl = process.env.LIVEKIT_WS_URL;
  let svc: InterpreterLivekitService;
  let rooms: { createRoom: jest.Mock; deleteRoom: jest.Mock };
  let presence: { listParticipants: jest.Mock };

  beforeEach(() => {
    jest.mocked(RoomServiceClient).mockClear();
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    svc = new InterpreterLivekitService();
    rooms = {
      createRoom: jest.fn().mockResolvedValue({}),
      deleteRoom: jest.fn().mockResolvedValue(undefined),
    };
    presence = { listParticipants: jest.fn() };
    svc.rooms = rooms as unknown as RoomServiceClient;
    svc.presence = presence as unknown as RoomServiceClient;
  });

  afterEach(() => {
    jest.restoreAllMocks();
    if (savedWsUrl === undefined) delete process.env.LIVEKIT_WS_URL;
    else process.env.LIVEKIT_WS_URL = savedWsUrl;
  });

  it('polls presence on its own client with a 2-second timeout', () => {
    const calls = jest.mocked(RoomServiceClient).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls.filter((args) => args[3]?.requestTimeout === 2)).toHaveLength(
      1,
    );
  });

  it('creates a room for two people, the agent and a reconnect', async () => {
    await svc.createRoom('interp-1');

    expect(rooms.createRoom).toHaveBeenCalledWith({
      name: 'interp-1',
      emptyTimeout: 300,
      departureTimeout: 60,
      maxParticipants: 4,
    });
  });

  it('issues a token that publishes only a microphone and carries the language', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await svc.issueToken({
      roomName: 'interp-1',
      userId: 'user-1',
      loginSessionId: 'login-1',
      lang: 'de',
      name: 'Anna',
    });
    const after = Math.floor(Date.now() / 1000);

    const claims = jwt.verify(token, LK_API_SECRET, {
      algorithms: ['HS256'],
    }) as jwt.JwtPayload;
    // A person plus a device, as in calls: two phones of one account do not kick each other.
    expect(claims.sub).toBe(makeParticipantIdentity('user-1', 'login-1'));
    expect(claims.sub).toMatch(/^user-1#[0-9a-f]{8}$/);
    expect(claims.name).toBe('Anna');
    expect(JSON.parse(claims.metadata as string)).toEqual({ lang: 'de' });
    expect(claims.video).toEqual({
      roomJoin: true,
      room: 'interp-1',
      canPublish: true,
      canPublishSources: ['microphone'],
      canSubscribe: true,
      canPublishData: false,
    });
    expect(claims.exp).toBeGreaterThanOrEqual(before + 4 * 3600);
    expect(claims.exp).toBeLessThanOrEqual(after + 4 * 3600);
  });

  it('sees the agent among the participants', async () => {
    presence.listParticipants.mockResolvedValue([
      { identity: 'user-1#abcd1234' },
      { identity: 'voice-interpreter' },
    ]);

    await expect(svc.agentPresent('interp-1')).resolves.toBe(true);
    expect(presence.listParticipants).toHaveBeenCalledWith('interp-1');
  });

  it('reports the agent absent from a room without it, or without anyone', async () => {
    presence.listParticipants.mockResolvedValueOnce([
      { identity: 'user-1#abcd1234' },
    ]);
    await expect(svc.agentPresent('interp-1')).resolves.toBe(false);

    presence.listParticipants.mockResolvedValueOnce([]);
    await expect(svc.agentPresent('interp-1')).resolves.toBe(false);
  });

  it('does not know when LiveKit cannot answer', async () => {
    presence.listParticipants.mockRejectedValue(new Error('timeout'));

    await expect(svc.agentPresent('interp-1')).resolves.toBeNull();
  });

  it('deletes a room best-effort', async () => {
    rooms.deleteRoom.mockRejectedValue(new Error('unavailable'));

    await expect(svc.deleteRoom('interp-1')).resolves.toBeUndefined();
    expect(rooms.deleteRoom).toHaveBeenCalledWith('interp-1');
  });

  it('reads the connect URL at call time', () => {
    delete process.env.LIVEKIT_WS_URL;
    expect(svc.wsUrl).toBe('ws://localhost:7880');

    process.env.LIVEKIT_WS_URL = 'wss://livekit.example';
    expect(svc.wsUrl).toBe('wss://livekit.example');
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter-livekit.service.spec.ts` не запускается: `Cannot find module './interpreter-livekit.service'`. Всего тестов 93, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter-livekit.service.ts` целиком:

```ts
import { Injectable, Logger } from '@nestjs/common';
import {
  AccessToken,
  RoomServiceClient,
  TrackSource,
} from 'livekit-server-sdk';
import { LK_API_KEY, LK_API_SECRET } from '../common/livekit-credentials';
import { makeParticipantIdentity } from '../common/participant-identity';

// Interpreter rooms live on the main SFU, the one the agent connects to.
const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';

/** The agent's identity in an interpreter room (livekit-agent/interpreter.js). */
export const AGENT_IDENTITY = 'voice-interpreter';

export interface InterpreterTokenRequest {
  roomName: string;
  userId: string;
  /** The JWT's session_id: one identity per device, as in calls. */
  loginSessionId?: string;
  lang: string;
  name?: string;
}

@Injectable()
export class InterpreterLivekitService {
  private readonly log = new Logger(InterpreterLivekitService.name);

  /** Creates and deletes rooms. */
  rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  /**
   * Asks whether the agent is in a room. The reconciler asks this of every
   * live conversation each 10 s; with the SDK's 60-second default timeout an
   * SFU that stopped answering would hold every tick for a minute per room.
   */
  presence = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET, {
    requestTimeout: 2,
  });

  get wsUrl(): string {
    return process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
  }

  async createRoom(roomName: string): Promise<void> {
    await this.rooms.createRoom({
      name: roomName,
      emptyTimeout: 300,
      // Kept open as long as the agent waits for someone to come back.
      departureTimeout: 60,
      // Two people, the agent, and a phone reconnecting before LiveKit has
      // dropped its previous connection.
      maxParticipants: 4,
    });
  }

  /**
   * Only a microphone and no data: whatever reaches the other phone comes
   * from the agent, never straight from this person.
   */
  issueToken(req: InterpreterTokenRequest): Promise<string> {
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: makeParticipantIdentity(req.userId, req.loginSessionId),
      name: req.name,
      metadata: JSON.stringify({ lang: req.lang }),
      ttl: '4h',
    });
    at.addGrant({
      roomJoin: true,
      room: req.roomName,
      canPublish: true,
      canPublishSources: [TrackSource.MICROPHONE],
      canSubscribe: true,
      canPublishData: false,
    });
    return at.toJwt();
  }

  /**
   * null when LiveKit did not answer. listParticipants resolves [] for a room
   * that is gone, so only a rejection is "unknown" — and nothing may be closed
   * because of an unknown.
   */
  async agentPresent(roomName: string): Promise<boolean | null> {
    try {
      const participants = await this.presence.listParticipants(roomName);
      return participants.some((p) => p.identity === AGENT_IDENTITY);
    } catch (e) {
      this.log.warn(`listParticipants(${roomName}) failed: ${String(e)}`);
      return null;
    }
  }

  /** Best effort: LiveKit closes an empty room by itself after departureTimeout. */
  async deleteRoom(roomName: string): Promise<void> {
    try {
      await this.rooms.deleteRoom(roomName);
    } catch (e) {
      this.log.warn(`deleteRoom(${roomName}) failed: ${String(e)}`);
    }
  }
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 12 наборов, 101 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter-livekit.service.ts src/interpreter/interpreter-livekit.service.spec.ts
git commit -m "feat(interpreter): комната и токен LiveKit, присутствие агента" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Тела запросов

Коды ошибок валидации — в `message`, как во всём бэкенде.

**Files:**
- Create: `src/interpreter/dto/agent-ended.dto.ts`, `src/interpreter/dto/create-interpreter-session.dto.ts`, `src/interpreter/dto/join-interpreter-session.dto.ts`, `src/interpreter/dto/interpreter-dtos.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/dto/interpreter-dtos.spec.ts` целиком:

```ts
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { AgentEndedDto } from './agent-ended.dto';
import { CreateInterpreterSessionDto } from './create-interpreter-session.dto';
import { JoinInterpreterSessionDto } from './join-interpreter-session.dto';

async function messages(
  cls: new () => object,
  plain: Record<string, unknown>,
): Promise<string[]> {
  const errors = await validate(plainToInstance(cls, plain));
  return errors.flatMap((e) => Object.values(e.constraints ?? {}));
}

describe('interpreter DTOs', () => {
  it('take a bare language code; any other shape is unsupported_language', async () => {
    expect(await messages(CreateInterpreterSessionDto, { lang: 'ru' })).toEqual(
      [],
    );
    for (const lang of ['pt-BR', 'RU', 'russian', '']) {
      expect(await messages(CreateInterpreterSessionDto, { lang })).toEqual([
        'unsupported_language',
      ]);
    }
    expect(
      await messages(JoinInterpreterSessionDto, {
        code: 'ABCDEFGH',
        lang: 'x',
      }),
    ).toEqual(['unsupported_language']);
  });

  it('take the code as typed, within a sane length', async () => {
    expect(
      await messages(JoinInterpreterSessionDto, {
        code: 'abcd-efgh',
        lang: 'de',
      }),
    ).toEqual([]);
    expect(
      await messages(JoinInterpreterSessionDto, {
        code: 'A'.repeat(33),
        lang: 'de',
      }),
    ).toHaveLength(1);
    expect(
      await messages(JoinInterpreterSessionDto, { code: 42, lang: 'de' }),
    ).not.toEqual([]);
  });

  it('take only the endings the agent reports', async () => {
    for (const reason of ['partner_left', 'agent_lost', 'translation_failed']) {
      expect(await messages(AgentEndedDto, { reason })).toEqual([]);
    }
    expect(await messages(AgentEndedDto, { reason: 'hangup' })).toHaveLength(1);
    expect(await messages(AgentEndedDto, {})).toHaveLength(1);
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/dto/interpreter-dtos.spec.ts` не запускается: `Cannot find module './agent-ended.dto'`. Всего тестов 101, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/dto/agent-ended.dto.ts` целиком:

```ts
import { IsIn } from 'class-validator';

/** Why the agent stopped by itself (livekit-agent/interpreter.js). */
export const AGENT_END_REASONS = [
  'partner_left',
  'agent_lost',
  'translation_failed',
] as const;

export type AgentEndReason = (typeof AGENT_END_REASONS)[number];

export class AgentEndedDto {
  @IsIn(AGENT_END_REASONS)
  reason!: AgentEndReason;
}
```

`src/interpreter/dto/create-interpreter-session.dto.ts` целиком:

```ts
import { IsString, Matches } from 'class-validator';

export class CreateInterpreterSessionDto {
  /** The host's language; whether the agent speaks it is the service's check. */
  @IsString()
  @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
  lang!: string;
}
```

`src/interpreter/dto/join-interpreter-session.dto.ts` целиком:

```ts
import { IsString, Matches, MaxLength } from 'class-validator';

export class JoinInterpreterSessionDto {
  /** As scanned or typed: the service normalizes case, spaces and dashes. */
  @IsString()
  @MaxLength(32)
  code!: string;

  /** The guest's language; whether the agent speaks it is the service's check. */
  @IsString()
  @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
  lang!: string;
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 13 наборов, 104 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/dto/
git commit -m "feat(interpreter): тела запросов" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Сервис разговора

Создание, новый код, вход, чтение, завершение, отчёт агента и общий `close()`. Порядок проверок и действий при входе — как в спеке: биллинг хоста → условный захват кода → старт агента; любой сбой после открытия биллинга его закрывает. `close()` переводит сессию в `ENDED` условно, и побочные действия выполняет только тот вызов, который её перевёл; каждое — отдельно, со своим логом.

**Files:**
- Create: `src/interpreter/interpreter.service.ts`, `src/interpreter/interpreter.service.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter.service.spec.ts` целиком:

```ts
import { HttpException, Logger } from '@nestjs/common';
import { FeatureDisabledException } from '../billing/exceptions/feature-disabled.exception';
import { InsufficientFundsException } from '../billing/exceptions/insufficient-funds.exception';
import { AgentCallError } from './interpreter-agent.client';
import { hashCode } from './interpreter-code';
import { InterpreterService } from './interpreter.service';

const NOW = new Date('2026-11-01T12:00:00Z');
const HOST = 'host-1';
const GUEST = 'guest-1';
const STRANGER = 'stranger-1';
const hostUser = { sub: HOST, session_id: 'login-host' };
const guestUser = { sub: GUEST, session_id: 'login-guest' };
const CODE = 'ABCDEFGH';
const PRINT_A = Array<number>(192).fill(0.1);
const PRINT_B = Array.from({ length: 192 }, (_, i) => (i % 2 ? 0.1 : -0.1));

const waitingRow = (over: Record<string, unknown> = {}) => ({
  id: 'sess-1',
  roomName: 'interp-room-1',
  hostId: HOST,
  guestId: null as string | null,
  hostLang: 'ru',
  guestLang: null as string | null,
  codeHash: hashCode(CODE) as string | null,
  codeExpiresAt: new Date(NOW.getTime() + 60_000) as Date | null,
  status: 'WAITING',
  billingSessionId: null as string | null,
  agentSeenAt: null as Date | null,
  startedAt: null as Date | null,
  endedAt: null as Date | null,
  endReason: null as string | null,
  ...over,
});

const activeRow = (over: Record<string, unknown> = {}) =>
  waitingRow({
    guestId: GUEST,
    guestLang: 'de',
    codeHash: null,
    codeExpiresAt: null,
    status: 'ACTIVE',
    billingSessionId: 'bill-1',
    startedAt: NOW,
    agentSeenAt: NOW,
    ...over,
  });

type Row = ReturnType<typeof waitingRow>;

/** Matches the where clauses the service uses: equality, { not }, OR. */
const matches = (
  row: Record<string, unknown>,
  where: Record<string, any>,
): boolean =>
  Object.entries(where).every(([key, want]) =>
    key === 'OR'
      ? (want as Record<string, any>[]).some((w) => matches(row, w))
      : want !== null && typeof want === 'object' && 'not' in want
        ? row[key] !== want.not
        : row[key] === want,
  );

function setup() {
  const rows: Row[] = [];
  const profiles: Record<string, any> = {
    [HOST]: {
      firstName: 'Anna',
      avatarUrl: 'https://cdn.test/anna.png',
      ownerEmbedding: PRINT_A,
    },
    [GUEST]: { firstName: 'Boris', avatarUrl: null, ownerEmbedding: PRINT_B },
  };
  // jest.fn over a tiny in-memory table: conditional updates behave as in the DB.
  const prisma = {
    interpreterSession: {
      findUnique: jest.fn(
        async ({ where }: any) => rows.find((r) => matches(r, where)) ?? null,
      ),
      findFirst: jest.fn(
        async ({ where }: any) => rows.find((r) => matches(r, where)) ?? null,
      ),
      findMany: jest.fn(async ({ where }: any) =>
        rows.filter((r) => matches(r, where)),
      ),
      create: jest.fn(async ({ data }: any) => {
        const row = waitingRow({ id: 'sess-new', ...data });
        rows.push(row);
        return { id: row.id };
      }),
      updateMany: jest.fn(async ({ where, data }: any) => {
        const hit = rows.filter((r) => matches(r, where));
        for (const r of hit) Object.assign(r, data);
        return { count: hit.length };
      }),
    },
    profile: {
      findUnique: jest.fn(async ({ where }: any) => profiles[where.userId]),
    },
    aiSession: {
      findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
    },
  };
  const gating = {
    assertCanStart: jest.fn().mockResolvedValue(undefined),
    startSession: jest.fn().mockResolvedValue({ id: 'bill-1' }),
    endSession: jest.fn().mockResolvedValue(undefined),
  };
  const redis = {
    incr: jest.fn().mockResolvedValue(1),
    expire: jest.fn().mockResolvedValue(undefined),
  };
  const agent = {
    start: jest.fn().mockResolvedValue(undefined),
    stop: jest.fn().mockResolvedValue(undefined),
    selftest: jest.fn(),
  };
  const livekit = {
    wsUrl: 'wss://lk.test',
    createRoom: jest.fn().mockResolvedValue(undefined),
    issueToken: jest.fn(async ({ userId }: any) => `lk-token:${userId}`),
    deleteRoom: jest.fn().mockResolvedValue(undefined),
  };
  const service = new InterpreterService(
    prisma as any,
    gating as any,
    redis as any,
    agent as any,
    livekit as any,
  );
  return { service, rows, profiles, prisma, gating, redis, agent, livekit };
}

/** [status, code] of the HttpException a call rejects with. */
async function failure(call: Promise<unknown>): Promise<[number, string]> {
  const e = await call.then(
    () => {
      throw new Error('expected the call to fail');
    },
    (err: unknown) => err,
  );
  if (!(e instanceof HttpException)) throw e;
  return [e.getStatus(), (e.getResponse() as { message: string }).message];
}

const savedFlag = process.env.INTERPRETER_ENABLED;

beforeEach(() => {
  jest.useFakeTimers({ now: NOW });
  process.env.INTERPRETER_ENABLED = 'true';
  for (const level of ['log', 'warn', 'error'] as const) {
    jest.spyOn(Logger.prototype, level).mockImplementation(() => undefined);
  }
});

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

afterAll(() => {
  if (savedFlag === undefined) delete process.env.INTERPRETER_ENABLED;
  else process.env.INTERPRETER_ENABLED = savedFlag;
});

describe('languages', () => {
  it('lists the languages and tells whether the feature is on', () => {
    const { service } = setup();
    expect(service.languages().enabled).toBe(true);
    expect(service.languages().languages).toHaveLength(81);
    expect(service.languages().languages[0]).toEqual({
      code: 'af',
      name: 'Afrikaans',
    });

    for (const value of ['false', 'TRUE', '1', '']) {
      process.env.INTERPRETER_ENABLED = value;
      expect(service.languages().enabled).toBe(false);
    }
  });
});

describe('create', () => {
  it('checks in order: switch, language, voice print, conversation, funds', async () => {
    const { service, rows, profiles, gating, livekit, prisma } = setup();
    profiles[HOST].ownerEmbedding = [];
    rows.push(activeRow({ id: 'other', hostId: 'someone', guestId: HOST }));
    gating.assertCanStart.mockRejectedValue(
      new InsufficientFundsException('interpreter', 24_000_000n, 0n),
    );

    process.env.INTERPRETER_ENABLED = 'false';
    expect(await failure(service.create(hostUser, 'xx'))).toEqual([
      403,
      'interpreter_disabled',
    ]);
    process.env.INTERPRETER_ENABLED = 'true';
    expect(await failure(service.create(hostUser, 'xx'))).toEqual([
      400,
      'unsupported_language',
    ]);
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      409,
      'voice_print_required',
    ]);
    profiles[HOST].ownerEmbedding = PRINT_A;
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      409,
      'already_in_session',
    ]);
    rows.length = 0;
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      402,
      'insufficient_funds',
    ]);
    gating.assertCanStart.mockRejectedValue(
      new FeatureDisabledException('interpreter'),
    );
    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      403,
      'feature_disabled',
    ]);

    expect(gating.assertCanStart).toHaveBeenCalledWith(HOST, 'interpreter');
    expect(livekit.createRoom).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.create).not.toHaveBeenCalled();
  });

  it('opens a waiting session with a hashed code, without billing yet', async () => {
    const { service, prisma, gating, livekit } = setup();

    const created = await service.create(hostUser, 'ru');

    expect(created.code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(created.roomName).toMatch(/^interp-[0-9a-f-]{36}$/);
    expect(livekit.createRoom).toHaveBeenCalledWith(created.roomName);
    expect(prisma.interpreterSession.create).toHaveBeenCalledWith({
      data: {
        roomName: created.roomName,
        hostId: HOST,
        hostLang: 'ru',
        codeHash: hashCode(created.code),
        codeExpiresAt: new Date(NOW.getTime() + 5 * 60_000),
      },
      select: { id: true },
    });
    expect(livekit.issueToken).toHaveBeenCalledWith({
      roomName: created.roomName,
      userId: HOST,
      loginSessionId: 'login-host',
      lang: 'ru',
      name: 'Anna',
    });
    expect(created).toEqual({
      sessionId: 'sess-new',
      code: created.code,
      expiresAt: new Date(NOW.getTime() + 5 * 60_000),
      roomName: created.roomName,
      token: 'lk-token:host-1',
      livekitWsUrl: 'wss://lk.test',
    });
    expect(gating.startSession).not.toHaveBeenCalled();
  });

  it("replaces the host's own waiting session: its QR stops working", async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(waitingRow({ id: 'old', roomName: 'interp-old' }));

    await service.create(hostUser, 'ru');

    expect(rows[0]).toMatchObject({
      status: 'ENDED',
      endReason: 'HANGUP',
      codeHash: null,
      endedAt: NOW,
    });
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-old');
    expect(agent.stop).not.toHaveBeenCalled();
    expect(gating.endSession).not.toHaveBeenCalled();
  });

  it('answers 503 when LiveKit cannot create the room', async () => {
    const { service, livekit, prisma } = setup();
    livekit.createRoom.mockRejectedValue(new Error('twirp error'));

    expect(await failure(service.create(hostUser, 'ru'))).toEqual([
      503,
      'interpreter_unavailable',
    ]);
    expect(prisma.interpreterSession.create).not.toHaveBeenCalled();
  });
});

describe('newCode', () => {
  it('gives the host a new code and retires the old one', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    const fresh = await service.newCode(HOST, 'sess-1');

    expect(fresh.code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(fresh.expiresAt).toEqual(new Date(NOW.getTime() + 5 * 60_000));
    expect(rows[0].codeHash).toBe(hashCode(fresh.code));
    expect(rows[0].codeHash).not.toBe(hashCode(CODE));
  });

  it('is for the host of a session that is still waiting', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());
    expect(await failure(service.newCode(GUEST, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
    expect(await failure(service.newCode(HOST, 'sess-x'))).toEqual([
      404,
      'session_not_found',
    ]);

    rows[0] = activeRow();
    expect(await failure(service.newCode(HOST, 'sess-1'))).toEqual([
      409,
      'not_waiting',
    ]);
  });

  it('does not re-arm a session a guest joined meanwhile', async () => {
    const { service, rows, prisma } = setup();
    rows.push(waitingRow());
    prisma.interpreterSession.updateMany.mockResolvedValueOnce({ count: 0 });

    expect(await failure(service.newCode(HOST, 'sess-1'))).toEqual([
      409,
      'not_waiting',
    ]);
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: { id: 'sess-1', status: 'WAITING' },
      data: { codeHash: expect.any(String), codeExpiresAt: expect.any(Date) },
    });
  });

  it('is off with the switch', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());
    process.env.INTERPRETER_ENABLED = 'false';
    expect(await failure(service.newCode(HOST, 'sess-1'))).toEqual([
      403,
      'interpreter_disabled',
    ]);
  });
});

describe('join', () => {
  it('checks in order before anything is opened', async () => {
    const { service, rows, profiles, redis, prisma, gating } = setup();
    rows.push(waitingRow({ codeExpiresAt: new Date(NOW.getTime() - 1) }));
    rows.push(activeRow({ id: 'other', hostId: GUEST, guestId: 'someone' }));
    profiles[GUEST].ownerEmbedding = [];
    profiles[HOST].ownerEmbedding = [];
    redis.incr.mockResolvedValue(11);

    process.env.INTERPRETER_ENABLED = 'false';
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      403,
      'interpreter_disabled',
    ]);
    expect(redis.incr).not.toHaveBeenCalled();
    process.env.INTERPRETER_ENABLED = 'true';
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      429,
      'too_many_attempts',
    ]);
    redis.incr.mockResolvedValue(2);
    expect(await failure(service.join(guestUser, 'nope', 'xx'))).toEqual([
      404,
      'code_not_found',
    ]);
    expect(await failure(service.join(guestUser, 'ZZZZZZZZ', 'xx'))).toEqual([
      404,
      'code_not_found',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      410,
      'code_expired',
    ]);
    rows[0].codeExpiresAt = new Date(NOW.getTime() + 60_000);
    expect(await failure(service.join(hostUser, CODE, 'xx'))).toEqual([
      409,
      'own_code',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'xx'))).toEqual([
      400,
      'unsupported_language',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'ru'))).toEqual([
      400,
      'same_language',
    ]);
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'voice_print_required',
    ]);
    profiles[GUEST].ownerEmbedding = PRINT_B;
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'already_in_session',
    ]);
    rows.pop();
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'host_voice_print_required',
    ]);
    profiles[HOST].ownerEmbedding = PRINT_B;
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'same_voice_print',
    ]);

    expect(gating.startSession).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.updateMany).not.toHaveBeenCalled();
  });

  describe('two prints the voice gate could not tell apart', () => {
    /** A unit print at cosine c from tilted(1). */
    const tilted = (c: number) => {
      const print = Array<number>(192).fill(0);
      print[0] = c;
      print[1] = Math.sqrt(1 - c * c);
      return print;
    };

    it.each([
      ['the same print', PRINT_A, PRINT_A],
      ['a rescaled copy', PRINT_A, PRINT_A.map((v) => v * 3)],
      ['prints at cosine 0.995', tilted(1), tilted(0.995)],
    ])('refuses %s before billing opens', async (_, hostPrint, guestPrint) => {
      const { service, rows, profiles, gating, agent } = setup();
      rows.push(waitingRow());
      profiles[HOST].ownerEmbedding = hostPrint;
      profiles[GUEST].ownerEmbedding = guestPrint;

      expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
        409,
        'same_voice_print',
      ]);
      expect(gating.startSession).not.toHaveBeenCalled();
      expect(agent.start).not.toHaveBeenCalled();
      expect(rows[0]).toMatchObject({
        status: 'WAITING',
        codeHash: hashCode(CODE),
      });
    });

    it.each([
      ['two different people', PRINT_A, PRINT_B],
      ['prints at cosine 0.985', tilted(1), tilted(0.985)],
    ])('lets %s through', async (_, hostPrint, guestPrint) => {
      const { service, rows, profiles, gating } = setup();
      rows.push(waitingRow());
      profiles[HOST].ownerEmbedding = hostPrint;
      profiles[GUEST].ownerEmbedding = guestPrint;

      await expect(service.join(guestUser, CODE, 'de')).resolves.toEqual(
        expect.objectContaining({ sessionId: 'sess-1' }),
      );
      expect(gating.startSession).toHaveBeenCalled();
    });
  });

  it('does not find a code whose session is no longer waiting', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ codeHash: hashCode(CODE) }));

    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      404,
      'code_not_found',
    ]);
  });

  it('counts attempts per person in a one-minute window', async () => {
    const { service, redis } = setup();

    await failure(service.join(guestUser, 'nope', 'de'));
    expect(redis.incr).toHaveBeenCalledWith('interp:join:guest-1');
    expect(redis.expire).toHaveBeenCalledWith('interp:join:guest-1', 60);

    redis.incr.mockResolvedValue(2);
    await failure(service.join(guestUser, 'nope', 'de'));
    expect(redis.expire).toHaveBeenCalledTimes(1);
  });

  it('accepts the code as a person types it', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    await expect(service.join(guestUser, 'abcd-efgh', 'de')).resolves.toEqual(
      expect.objectContaining({ sessionId: 'sess-1' }),
    );
  });

  it('opens billing, claims the code, then starts the agent', async () => {
    const { service, rows, gating, prisma, agent, livekit } = setup();
    rows.push(waitingRow());

    const joined = await service.join(guestUser, CODE, 'de');

    expect(gating.startSession).toHaveBeenCalledWith(
      HOST,
      'interpreter',
      'sess-1',
    );
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: { id: 'sess-1', status: 'WAITING', codeHash: hashCode(CODE) },
      data: {
        guestId: GUEST,
        guestLang: 'de',
        billingSessionId: 'bill-1',
        status: 'ACTIVE',
        startedAt: NOW,
        agentSeenAt: NOW,
        codeHash: null,
        codeExpiresAt: null,
      },
    });
    expect(agent.start).toHaveBeenCalledWith({
      sessionId: 'sess-1',
      roomName: 'interp-room-1',
      participants: [
        { userId: HOST, lang: 'ru', embedding: PRINT_A },
        { userId: GUEST, lang: 'de', embedding: PRINT_B },
      ],
    });
    const order = [
      gating.startSession,
      prisma.interpreterSession.updateMany,
      agent.start,
    ].map((fn) => fn.mock.invocationCallOrder[0]);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(livekit.issueToken).toHaveBeenCalledWith({
      roomName: 'interp-room-1',
      userId: GUEST,
      loginSessionId: 'login-guest',
      lang: 'de',
      name: 'Boris',
    });
    expect(joined).toEqual({
      sessionId: 'sess-1',
      roomName: 'interp-room-1',
      token: 'lk-token:guest-1',
      livekitWsUrl: 'wss://lk.test',
      partner: {
        firstName: 'Anna',
        avatarUrl: 'https://cdn.test/anna.png',
        lang: 'ru',
      },
      directions: { toMe: 'simultaneous', fromMe: 'simultaneous' },
    });
  });

  it('reports each direction from the guest side', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    // Slovak is not a language the translate model speaks, but one it hears.
    const joined = await service.join(guestUser, CODE, 'sk');

    expect(joined.directions).toEqual({
      toMe: 'phrase',
      fromMe: 'simultaneous',
    });
  });

  it("ends the guest's own waiting session", async () => {
    const { service, rows, livekit } = setup();
    rows.push(waitingRow());
    rows.push(
      waitingRow({
        id: 'guest-own',
        roomName: 'interp-guest-own',
        hostId: GUEST,
        codeHash: hashCode('ZZZZZZZZ'),
      }),
    );

    await service.join(guestUser, CODE, 'de');

    expect(rows[1]).toMatchObject({ status: 'ENDED', endReason: 'HANGUP' });
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-guest-own');
  });

  it("maps the host's billing refusal and leaves the code valid", async () => {
    const { service, rows, gating, agent } = setup();
    rows.push(waitingRow());

    gating.startSession.mockRejectedValueOnce(
      new InsufficientFundsException('interpreter', 24_000_000n, 0n),
    );
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      402,
      'host_insufficient_funds',
    ]);
    gating.startSession.mockRejectedValueOnce(
      new FeatureDisabledException('interpreter'),
    );
    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      403,
      'host_feature_disabled',
    ]);

    expect(rows[0]).toMatchObject({
      status: 'WAITING',
      codeHash: hashCode(CODE),
    });
    expect(agent.start).not.toHaveBeenCalled();
  });

  it('closes the billing again when another guest claimed the code first', async () => {
    const { service, rows, prisma, gating, agent } = setup();
    rows.push(waitingRow());
    prisma.interpreterSession.updateMany.mockResolvedValueOnce({ count: 0 });

    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      409,
      'code_used',
    ]);
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'failed');
    expect(agent.start).not.toHaveBeenCalled();
  });

  it('closes the billing again when the claim itself fails', async () => {
    const { service, rows, prisma, gating } = setup();
    rows.push(waitingRow());
    prisma.interpreterSession.updateMany.mockRejectedValueOnce(
      new Error('db down'),
    );

    await expect(service.join(guestUser, CODE, 'de')).rejects.toThrow(
      'db down',
    );
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'failed');
  });

  it('ends the session as translation_failed when the agent does not start', async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(waitingRow());
    agent.start.mockRejectedValue(new AgentCallError(503, 'agent refused'));

    expect(await failure(service.join(guestUser, CODE, 'de'))).toEqual([
      503,
      'interpreter_unavailable',
    ]);
    expect(rows[0]).toMatchObject({
      status: 'ENDED',
      endReason: 'TRANSLATION_FAILED',
    });
    expect(agent.stop).toHaveBeenCalledWith('interp-room-1');
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'failed');
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');
  });
});

describe('get', () => {
  it('shows a waiting session without partner or directions', async () => {
    const { service, rows } = setup();
    rows.push(waitingRow());

    await expect(service.get(HOST, 'sess-1')).resolves.toEqual({
      status: 'waiting',
      endReason: null,
      partner: null,
      directions: null,
      startedAt: null,
    });
  });

  it('shows each side the other one', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ guestLang: 'sk' }));

    await expect(service.get(HOST, 'sess-1')).resolves.toEqual({
      status: 'active',
      endReason: null,
      partner: { firstName: 'Boris', avatarUrl: null, lang: 'sk' },
      directions: { toMe: 'simultaneous', fromMe: 'phrase' },
      startedAt: NOW,
    });
    await expect(service.get(GUEST, 'sess-1')).resolves.toEqual(
      expect.objectContaining({
        partner: {
          firstName: 'Anna',
          avatarUrl: 'https://cdn.test/anna.png',
          lang: 'ru',
        },
        directions: { toMe: 'phrase', fromMe: 'simultaneous' },
      }),
    );
  });

  it('tells why a session ended', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ status: 'ENDED', endReason: 'TRANSLATION_FAILED' }));

    await expect(service.get(GUEST, 'sess-1')).resolves.toEqual(
      expect.objectContaining({
        status: 'ended',
        endReason: 'translation_failed',
      }),
    );
  });

  it('is only for the two participants', async () => {
    const { service, rows } = setup();
    rows.push(activeRow());

    expect(await failure(service.get(STRANGER, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
    expect(await failure(service.get(HOST, 'sess-x'))).toEqual([
      404,
      'session_not_found',
    ]);
  });

  it('still answers a participant with the switch off, so the app learns why it ended', async () => {
    const { service, rows } = setup();
    rows.push(activeRow({ status: 'ENDED', endReason: 'AGENT_LOST' }));
    process.env.INTERPRETER_ENABLED = 'false';

    await expect(service.get(HOST, 'sess-1')).resolves.toEqual(
      expect.objectContaining({ status: 'ended', endReason: 'agent_lost' }),
    );
    expect(await failure(service.get(STRANGER, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
  });
});

describe('end', () => {
  it('lets either participant hang up, once', async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(activeRow());

    await expect(service.end(GUEST, 'sess-1')).resolves.toEqual({
      status: 'ended',
    });
    expect(rows[0]).toMatchObject({ status: 'ENDED', endReason: 'HANGUP' });
    expect(agent.stop).toHaveBeenCalledWith('interp-room-1');
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');

    await expect(service.end(HOST, 'sess-1')).resolves.toEqual({
      status: 'ended',
    });
    expect(agent.stop).toHaveBeenCalledTimes(1);
    expect(gating.endSession).toHaveBeenCalledTimes(1);
  });

  it('is only for the two participants', async () => {
    const { service, rows } = setup();
    rows.push(activeRow());

    expect(await failure(service.end(STRANGER, 'sess-1'))).toEqual([
      404,
      'session_not_found',
    ]);
    expect(rows[0].status).toBe('ACTIVE');
  });

  it('still works with the switch off, so billing stops at once', async () => {
    const { service, rows, gating } = setup();
    rows.push(activeRow());
    process.env.INTERPRETER_ENABLED = 'false';

    await service.end(HOST, 'sess-1');

    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
  });
});

describe('agentEnded', () => {
  it.each([
    ['partner_left', 'PARTNER_LEFT', 'completed'],
    ['agent_lost', 'AGENT_LOST', 'failed'],
    ['translation_failed', 'TRANSLATION_FAILED', 'failed'],
  ] as const)(
    'ends the session as %s without stopping the agent that reported it',
    async (reason, endReason, billing) => {
      const { service, rows, agent, gating, livekit } = setup();
      rows.push(activeRow());

      await expect(service.agentEnded('sess-1', reason)).resolves.toEqual({
        ok: true,
      });
      expect(rows[0]).toMatchObject({ status: 'ENDED', endReason });
      expect(agent.stop).not.toHaveBeenCalled();
      expect(gating.endSession).toHaveBeenCalledWith('bill-1', billing);
      expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');
    },
  );

  it('answers ok for an unknown or already ended session, changing nothing', async () => {
    const { service, rows, gating, livekit } = setup();
    rows.push(activeRow({ status: 'ENDED', endReason: 'HANGUP' }));

    await expect(service.agentEnded('sess-x', 'agent_lost')).resolves.toEqual({
      ok: true,
    });
    await expect(service.agentEnded('sess-1', 'agent_lost')).resolves.toEqual({
      ok: true,
    });
    expect(rows[0].endReason).toBe('HANGUP');
    expect(gating.endSession).not.toHaveBeenCalled();
    expect(livekit.deleteRoom).not.toHaveBeenCalled();
  });
});

describe('close', () => {
  it('leaves billing alone when metering already ended it', async () => {
    const { service, rows, gating, prisma } = setup();
    rows.push(activeRow(), activeRow({ id: 'sess-2', roomName: 'r-2' }));

    await service.close(rows[0], 'NO_FUNDS', { stopAgent: true });
    await service.close(rows[1], 'MAX_DURATION', { stopAgent: true });

    expect(prisma.aiSession.findUnique).not.toHaveBeenCalled();
    expect(gating.endSession).not.toHaveBeenCalled();
  });

  it('does not overwrite a billing session that is no longer active', async () => {
    const { service, rows, gating, prisma } = setup();
    rows.push(activeRow());
    prisma.aiSession.findUnique.mockResolvedValue({
      status: 'terminated_no_funds',
    });

    await service.close(rows[0], 'HANGUP', { stopAgent: true });

    expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
      where: { id: 'bill-1' },
      select: { status: true },
    });
    expect(gating.endSession).not.toHaveBeenCalled();
  });

  it('runs every cleanup step even when the ones before it fail', async () => {
    const { service, rows, agent, gating, livekit } = setup();
    rows.push(activeRow());
    agent.stop.mockRejectedValue(new Error('agent down'));
    gating.endSession.mockRejectedValue(new Error('db hiccup'));
    livekit.deleteRoom.mockRejectedValue(new Error('sfu down'));

    await expect(
      service.close(rows[0], 'HANGUP', { stopAgent: true }),
    ).resolves.toBeUndefined();
    expect(gating.endSession).toHaveBeenCalled();
    expect(livekit.deleteRoom).toHaveBeenCalled();
  });

  it('cleans up after the row as it ended, not the caller copy', async () => {
    // The caller read the session while it was waiting; a guest joined
    // before the close landed, and that join opened billing.
    const { service, rows, agent, gating } = setup();
    rows.push(activeRow());
    const staleCopy = waitingRow();

    await service.close(staleCopy, 'HANGUP', { stopAgent: true });

    expect(agent.stop).toHaveBeenCalledWith('interp-room-1');
    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
  });

  it("falls back to the caller's copy when the row cannot be re-read", async () => {
    const { service, rows, prisma, gating } = setup();
    rows.push(activeRow());
    prisma.interpreterSession.findUnique.mockRejectedValueOnce(
      new Error('db hiccup'),
    );

    await service.close(activeRow(), 'HANGUP', { stopAgent: true });

    expect(gating.endSession).toHaveBeenCalledWith('bill-1', 'completed');
  });

  it('never stops an agent for a session that was never active', async () => {
    const { service, rows, agent, livekit } = setup();
    rows.push(waitingRow());

    await service.close(rows[0], 'EXPIRED', { stopAgent: true });

    expect(agent.stop).not.toHaveBeenCalled();
    expect(livekit.deleteRoom).toHaveBeenCalledWith('interp-room-1');
  });
});

describe('selftest', () => {
  it("passes the agent's answer through", async () => {
    const { service, agent } = setup();
    agent.selftest.mockResolvedValue({ status: 200, body: { ok: true } });

    await expect(service.selftest()).resolves.toEqual({
      status: 200,
      body: { ok: true },
    });
  });

  it('still reaches the agent with the switch off, for the post-deploy smoke', async () => {
    const { service, agent } = setup();
    agent.selftest.mockResolvedValue({ status: 200, body: { ok: true } });
    process.env.INTERPRETER_ENABLED = 'false';

    await expect(service.selftest()).resolves.toEqual({
      status: 200,
      body: { ok: true },
    });
    expect(agent.selftest).toHaveBeenCalledTimes(1);
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter.service.spec.ts` не запускается: `Cannot find module './interpreter.service'`. Всего тестов 104, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter.service.ts` целиком:

```ts
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  GoneException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { InterpreterEndReason, InterpreterSession } from '@prisma/client';
import { randomUUID } from 'crypto';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';
import { FeatureDisabledException } from '../billing/exceptions/feature-disabled.exception';
import { InsufficientFundsException } from '../billing/exceptions/insufficient-funds.exception';
import {
  GatingService,
  type SessionTerminationReason,
} from '../billing/services/gating.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { cosine } from '../voice-gate/cosine';
import type { AgentEndReason } from './dto/agent-ended.dto';
import { InterpreterAgentClient } from './interpreter-agent.client';
import {
  CODE_TTL_MS,
  generateCode,
  hashCode,
  normalizeCode,
} from './interpreter-code';
import {
  type EngineKind,
  INTERPRETER_LANGUAGES,
  engineFor,
  isSupportedLang,
} from './interpreter-languages';
import { InterpreterLivekitService } from './interpreter-livekit.service';
import { SAME_PRINT_COSINE, hasUsableVoicePrint } from './voice-print';

/** The JWT payload fields this module reads. */
export interface InterpreterUser {
  sub: string;
  session_id?: string;
}

export interface Directions {
  /** How the partner's speech reaches me. */
  toMe: EngineKind;
  /** How my speech reaches the partner. */
  fromMe: EngineKind;
}

export interface Partner {
  firstName: string | null;
  avatarUrl: string | null;
  lang: string;
}

/** What close() needs to clean up after a session. */
export type ClosableSession = Pick<
  InterpreterSession,
  'id' | 'roomName' | 'startedAt' | 'billingSessionId'
>;

const CLOSABLE = {
  id: true,
  roomName: true,
  startedAt: true,
  billingSessionId: true,
} as const;

// Enough for typos and rescans; with 40-bit codes living 5 minutes, nowhere
// near enough to guess one.
const JOIN_ATTEMPTS_PER_MINUTE = 10;

/** How an ending closes the host's billing; null where metering already closed it. */
const BILLING_END: Record<
  InterpreterEndReason,
  SessionTerminationReason | null
> = {
  HANGUP: 'completed',
  PARTNER_LEFT: 'completed',
  EXPIRED: 'completed',
  TRANSLATION_FAILED: 'failed',
  AGENT_LOST: 'failed',
  NO_FUNDS: null,
  MAX_DURATION: null,
};

const AGENT_END: Record<AgentEndReason, InterpreterEndReason> = {
  partner_left: 'PARTNER_LEFT',
  agent_lost: 'AGENT_LOST',
  translation_failed: 'TRANSLATION_FAILED',
};

/**
 * Face-to-face interpreter sessions: the host shows a QR, the guest scans it,
 * the agent translates each one's speech for the other. See
 * docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md.
 *
 * Voice prints go to the agent and nowhere else: not into responses, errors
 * or logs. Codes are stored as hashes only.
 */
@Injectable()
export class InterpreterService {
  private readonly log = new Logger(InterpreterService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly gating: GatingService,
    private readonly redis: RedisService,
    private readonly agent: InterpreterAgentClient,
    private readonly livekit: InterpreterLivekitService,
  ) {}

  languages(): {
    enabled: boolean;
    languages: ReadonlyArray<{ code: string; name: string }>;
  } {
    return { enabled: isEnabled(), languages: INTERPRETER_LANGUAGES };
  }

  /** The host's side: a waiting session, its room and a code for the QR. */
  async create(
    user: InterpreterUser,
    lang: string,
  ): Promise<{
    sessionId: string;
    code: string;
    expiresAt: Date;
    roomName: string;
    token: string;
    livekitWsUrl: string;
  }> {
    this.assertEnabled();
    if (!isSupportedLang(lang)) {
      throw new BadRequestException('unsupported_language');
    }
    const profile = await this.voiceProfile(user.sub);
    if (!profile || !hasUsableVoicePrint(profile.ownerEmbedding)) {
      throw new ConflictException('voice_print_required');
    }
    await this.assertNotInConversation(user.sub);
    // Refused here rather than when the guest is already scanning the code.
    // Billing itself opens only on join: waiting on the QR screen is free.
    await withBillingCodes(
      () => this.gating.assertCanStart(user.sub, FEATURE_KEYS.INTERPRETER),
      'insufficient_funds',
      'feature_disabled',
    );

    // Starting over replaces the QR on screen; the old one must stop working.
    await this.closeWaiting(user.sub);

    const roomName = `interp-${randomUUID()}`;
    try {
      await this.livekit.createRoom(roomName);
    } catch (e) {
      this.log.warn(`creating room ${roomName} failed: ${String(e)}`);
      throw new ServiceUnavailableException('interpreter_unavailable');
    }
    const code = generateCode();
    const expiresAt = new Date(Date.now() + CODE_TTL_MS);
    const session = await this.prisma.interpreterSession.create({
      data: {
        roomName,
        hostId: user.sub,
        hostLang: lang,
        codeHash: hashCode(code),
        codeExpiresAt: expiresAt,
      },
      select: { id: true },
    });
    const token = await this.livekit.issueToken({
      roomName,
      userId: user.sub,
      loginSessionId: user.session_id,
      lang,
      name: profile.firstName ?? undefined,
    });
    this.log.log(`session ${session.id} waiting in ${roomName} (${lang})`);
    return {
      sessionId: session.id,
      code,
      expiresAt,
      roomName,
      token,
      livekitWsUrl: this.livekit.wsUrl,
    };
  }

  /** A fresh code for the host's QR; the previous one stops working. */
  async newCode(
    userId: string,
    sessionId: string,
  ): Promise<{ code: string; expiresAt: Date }> {
    this.assertEnabled();
    const session = await this.prisma.interpreterSession.findUnique({
      where: { id: sessionId },
      select: { hostId: true, status: true },
    });
    if (!session || session.hostId !== userId) {
      throw new NotFoundException('session_not_found');
    }
    if (session.status !== 'WAITING') {
      throw new ConflictException('not_waiting');
    }
    const code = generateCode();
    const expiresAt = new Date(Date.now() + CODE_TTL_MS);
    // Conditional: a guest who joined in the meantime made it ACTIVE.
    const { count } = await this.prisma.interpreterSession.updateMany({
      where: { id: sessionId, status: 'WAITING' },
      data: { codeHash: hashCode(code), codeExpiresAt: expiresAt },
    });
    if (count === 0) throw new ConflictException('not_waiting');
    return { code, expiresAt };
  }

  /** The guest's side: opens the host's billing, claims the code, starts the agent. */
  async join(
    user: InterpreterUser,
    rawCode: string,
    lang: string,
  ): Promise<{
    sessionId: string;
    roomName: string;
    token: string;
    livekitWsUrl: string;
    partner: Partner;
    directions: Directions;
  }> {
    this.assertEnabled();
    await this.limitJoinAttempts(user.sub);
    const code = normalizeCode(rawCode);
    if (!code) throw new NotFoundException('code_not_found');
    const session = await this.prisma.interpreterSession.findUnique({
      where: { codeHash: hashCode(code) },
    });
    if (!session || session.status !== 'WAITING') {
      throw new NotFoundException('code_not_found');
    }
    if (
      !session.codeExpiresAt ||
      session.codeExpiresAt.getTime() <= Date.now()
    ) {
      throw new GoneException('code_expired');
    }
    if (session.hostId === user.sub) throw new ConflictException('own_code');
    if (!isSupportedLang(lang)) {
      throw new BadRequestException('unsupported_language');
    }
    if (lang === session.hostLang) {
      throw new BadRequestException('same_language');
    }
    const guest = await this.voiceProfile(user.sub);
    if (!guest || !hasUsableVoicePrint(guest.ownerEmbedding)) {
      throw new ConflictException('voice_print_required');
    }
    await this.assertNotInConversation(user.sub);
    // The agent refuses a pair without two usable prints, and by then billing is open.
    const host = await this.voiceProfile(session.hostId);
    if (!host || !hasUsableVoicePrint(host.ownerEmbedding)) {
      throw new ConflictException('host_voice_print_required');
    }
    // The agent refuses this pair too (same cosine, same threshold), but only
    // after step 1 below has opened the host's billing.
    if (
      cosine(host.ownerEmbedding, guest.ownerEmbedding) >= SAME_PRINT_COSINE
    ) {
      throw new ConflictException('same_voice_print');
    }
    // Minted up front: once billing is open, only the agent may still fail.
    const token = await this.livekit.issueToken({
      roomName: session.roomName,
      userId: user.sub,
      loginSessionId: user.session_id,
      lang,
      name: guest.firstName ?? undefined,
    });

    // 1. The host pays from the moment the guest is in. Refused, the session
    //    stays as it was and the code keeps working.
    const billing = await withBillingCodes(
      () =>
        this.gating.startSession(
          session.hostId,
          FEATURE_KEYS.INTERPRETER,
          session.id,
        ),
      'host_insufficient_funds',
      'host_feature_disabled',
    );

    // 2. Claim the code. Conditional, so of two guests scanning one code only
    //    one gets in, and a code the host replaced meanwhile no longer works.
    const now = new Date();
    let claimed = false;
    try {
      const { count } = await this.prisma.interpreterSession.updateMany({
        where: {
          id: session.id,
          status: 'WAITING',
          codeHash: session.codeHash,
        },
        data: {
          guestId: user.sub,
          guestLang: lang,
          billingSessionId: billing.id,
          status: 'ACTIVE',
          startedAt: now,
          // The agent is not in the room yet; this starts its 60 s to get there.
          agentSeenAt: now,
          codeHash: null,
          codeExpiresAt: null,
        },
      });
      claimed = count === 1;
    } finally {
      // Billing from step 1 must not outlive a claim that failed or threw.
      if (!claimed) {
        await this.attempt(`session ${session.id}: closing billing`, () =>
          this.gating.endSession(billing.id, 'failed'),
        );
      }
    }
    if (!claimed) throw new ConflictException('code_used');
    await this.closeWaiting(user.sub);

    // 3. Start the agent.
    try {
      await this.agent.start({
        sessionId: session.id,
        roomName: session.roomName,
        participants: [
          {
            userId: session.hostId,
            lang: session.hostLang,
            embedding: host.ownerEmbedding,
          },
          { userId: user.sub, lang, embedding: guest.ownerEmbedding },
        ],
      });
    } catch (e) {
      this.log.warn(`session ${session.id}: agent did not start: ${String(e)}`);
      await this.attempt(`session ${session.id}: closing`, () =>
        this.close(
          { ...session, billingSessionId: billing.id, startedAt: now },
          'TRANSLATION_FAILED',
          { stopAgent: true },
        ),
      );
      throw new ServiceUnavailableException('interpreter_unavailable');
    }

    this.log.log(`session ${session.id} active: ${session.hostLang}↔${lang}`);
    return {
      sessionId: session.id,
      roomName: session.roomName,
      token,
      livekitWsUrl: this.livekit.wsUrl,
      partner: {
        firstName: host.firstName,
        avatarUrl: host.avatarUrl,
        lang: session.hostLang,
      },
      directions: {
        toMe: engineFor(session.hostLang, lang),
        fromMe: engineFor(lang, session.hostLang),
      },
    };
  }

  /**
   * A participant's view of the session. The host learns about the guest from
   * LiveKit; this is the fallback, and the only source of why it ended. Not
   * behind the switch: turned off mid-conversation, it must still say why.
   */
  async get(
    userId: string,
    sessionId: string,
  ): Promise<{
    status: string;
    endReason: string | null;
    partner: Partner | null;
    directions: Directions | null;
    startedAt: Date | null;
  }> {
    const s = await this.participantSession(userId, sessionId);
    const status = s.status.toLowerCase();
    const endReason = s.endReason?.toLowerCase() ?? null;
    if (!s.guestId || !s.guestLang) {
      return {
        status,
        endReason,
        partner: null,
        directions: null,
        startedAt: s.startedAt,
      };
    }
    const iAmHost = s.hostId === userId;
    const myLang = iAmHost ? s.hostLang : s.guestLang;
    const partnerLang = iAmHost ? s.guestLang : s.hostLang;
    const profile = await this.prisma.profile.findUnique({
      where: { userId: iAmHost ? s.guestId : s.hostId },
      select: { firstName: true, avatarUrl: true },
    });
    return {
      status,
      endReason,
      partner: {
        firstName: profile?.firstName ?? null,
        avatarUrl: profile?.avatarUrl ?? null,
        lang: partnerLang,
      },
      directions: {
        toMe: engineFor(partnerLang, myLang),
        fromMe: engineFor(myLang, partnerLang),
      },
      startedAt: s.startedAt,
    };
  }

  /**
   * Either participant hangs up; repeating it changes nothing. Not behind the
   * switch: turning the feature off must not keep running sessions billing.
   */
  async end(userId: string, sessionId: string): Promise<{ status: 'ended' }> {
    const s = await this.participantSession(userId, sessionId);
    await this.close(s, 'HANGUP', { stopAgent: true });
    return { status: 'ended' };
  }

  /**
   * The agent stopped by itself. It retries after a network error or a 5xx,
   * so an unknown or already ended session is still answered ok. Not behind
   * the switch, for the same reason as end().
   */
  async agentEnded(
    sessionId: string,
    reason: AgentEndReason,
  ): Promise<{ ok: true }> {
    const s = await this.prisma.interpreterSession.findUnique({
      where: { id: sessionId },
      select: CLOSABLE,
    });
    // The agent is already gone: nothing to stop.
    if (s) await this.close(s, AGENT_END[reason], { stopAgent: false });
    return { ok: true };
  }

  /**
   * The agent's selftest: both engines' OpenAI sessions. Not behind the
   * switch: the post-deploy smoke runs it on TEST and PROD while it is off.
   */
  async selftest(): Promise<{ status: number; body: unknown }> {
    return this.agent.selftest();
  }

  /**
   * Ends a session. Only the call that moves it to ENDED cleans up, so a
   * hang-up racing the agent's report or the reconciler cleans up once. Each
   * cleanup step runs even when the one before it failed.
   *
   * @param opts.stopAgent false when the agent itself reported the end.
   */
  async close(
    session: ClosableSession,
    reason: InterpreterEndReason,
    opts: { stopAgent: boolean },
  ): Promise<void> {
    const { count } = await this.prisma.interpreterSession.updateMany({
      where: { id: session.id, status: { not: 'ENDED' } },
      data: {
        status: 'ENDED',
        endReason: reason,
        endedAt: new Date(),
        codeHash: null,
      },
    });
    if (count === 0) return;
    this.log.log(`session ${session.id} ended: ${reason}`);

    const ended = await this.asEnded(session);
    // startedAt is set only by the join that made the session ACTIVE.
    if (opts.stopAgent && ended.startedAt) {
      await this.attempt(`session ${ended.id}: stopping the agent`, () =>
        this.agent.stop(ended.roomName),
      );
    }
    const billingId = ended.billingSessionId;
    const billingEnd = BILLING_END[reason];
    if (billingId && billingEnd) {
      await this.attempt(`session ${ended.id}: closing billing`, () =>
        this.endBillingIfActive(billingId, billingEnd),
      );
    }
    await this.attempt(`session ${ended.id}: deleting the room`, () =>
      this.livekit.deleteRoom(ended.roomName),
    );
  }

  /**
   * The session as it ended, read after the transition. The caller's copy can
   * be stale: read while WAITING, it misses a guest who joined just before the
   * close landed — and that join opened billing.
   */
  private async asEnded(session: ClosableSession): Promise<ClosableSession> {
    try {
      const row = await this.prisma.interpreterSession.findUnique({
        where: { id: session.id },
        select: CLOSABLE,
      });
      return row ?? session;
    } catch (e) {
      this.log.warn(
        `session ${session.id}: re-reading it failed, cleaning up from the caller's copy: ${String(e)}`,
      );
      return session;
    }
  }

  /** Metering may have closed it already; endSession would overwrite that status. */
  private async endBillingIfActive(
    billingSessionId: string,
    reason: SessionTerminationReason,
  ): Promise<void> {
    const billing = await this.prisma.aiSession.findUnique({
      where: { id: billingSessionId },
      select: { status: true },
    });
    if (billing?.status === 'active') {
      await this.gating.endSession(billingSessionId, reason);
    }
  }

  /** Ends the QR sessions a person was showing. Never throws: it is cleanup. */
  private async closeWaiting(userId: string): Promise<void> {
    await this.attempt(`closing waiting sessions of ${userId}`, async () => {
      const waiting = await this.prisma.interpreterSession.findMany({
        where: { hostId: userId, status: 'WAITING' },
        select: CLOSABLE,
      });
      // stopAgent only matters if a guest joined one of them just now.
      for (const s of waiting) {
        await this.close(s, 'HANGUP', { stopAgent: true });
      }
    });
  }

  /** Runs one cleanup step; a failure is logged and the caller goes on. */
  private async attempt(
    what: string,
    step: () => Promise<unknown>,
  ): Promise<void> {
    try {
      await step();
    } catch (e) {
      this.log.error(`${what} failed: ${String(e)}`);
    }
  }

  private async participantSession(
    userId: string,
    sessionId: string,
  ): Promise<InterpreterSession> {
    const s = await this.prisma.interpreterSession.findUnique({
      where: { id: sessionId },
    });
    if (!s || (s.hostId !== userId && s.guestId !== userId)) {
      throw new NotFoundException('session_not_found');
    }
    return s;
  }

  /** One conversation at a time. A waiting QR does not count: it gets replaced. */
  private async assertNotInConversation(userId: string): Promise<void> {
    const active = await this.prisma.interpreterSession.findFirst({
      where: {
        status: 'ACTIVE',
        OR: [{ hostId: userId }, { guestId: userId }],
      },
      select: { id: true },
    });
    if (active) throw new ConflictException('already_in_session');
  }

  private voiceProfile(userId: string) {
    return this.prisma.profile.findUnique({
      where: { userId },
      select: { firstName: true, avatarUrl: true, ownerEmbedding: true },
    });
  }

  /** Per person, not per IP: @Throttle runs before the JWT is read. */
  private async limitJoinAttempts(userId: string): Promise<void> {
    const key = `interp:join:${userId}`;
    const attempts = await this.redis.incr(key);
    if (attempts === 1) await this.redis.expire(key, 60);
    if (attempts > JOIN_ATTEMPTS_PER_MINUTE) {
      throw new HttpException(
        { message: 'too_many_attempts' },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private assertEnabled(): void {
    if (!isEnabled()) throw new ForbiddenException('interpreter_disabled');
  }
}

function isEnabled(): boolean {
  return process.env.INTERPRETER_ENABLED === 'true';
}

/**
 * Billing refuses with plain Errors, which would surface as 500s. Maps them to
 * this module's codes; the host_ variants tell the guest whose wallet it was.
 */
async function withBillingCodes<T>(
  call: () => Promise<T>,
  insufficientFunds: string,
  featureDisabled: string,
): Promise<T> {
  try {
    return await call();
  } catch (e) {
    if (e instanceof InsufficientFundsException) {
      throw new HttpException(
        { message: insufficientFunds },
        HttpStatus.PAYMENT_REQUIRED,
      );
    }
    if (e instanceof FeatureDisabledException) {
      throw new ForbiddenException(featureDisabled);
    }
    throw e;
  }
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 14 наборов, 149 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter.service.ts src/interpreter/interpreter.service.spec.ts
git commit -m "feat(interpreter): сервис разговора — создание, вход, завершение, close()" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Сверка раз в 10 секунд

Закрывает то, что никто другой не закроет: биллинг, закрытый метерингом (`no_funds`, `max_duration`), агент, пропавший без отчёта (рестарт, деплой), QR, который никто не отсканировал. Проход не начинается, пока не закончился предыдущий, и никогда не бросает.

**Files:**
- Create: `src/interpreter/interpreter.reconciler.ts`, `src/interpreter/interpreter.reconciler.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter.reconciler.spec.ts` целиком:

```ts
import { Logger } from '@nestjs/common';
import { InterpreterReconciler } from './interpreter.reconciler';

const NOW = new Date('2026-11-01T12:00:00Z');
const secondsAgo = (s: number) => new Date(NOW.getTime() - s * 1000);

const active = (over: Record<string, unknown> = {}) => ({
  id: 'sess-1',
  roomName: 'interp-room-1',
  billingSessionId: 'bill-1' as string | null,
  startedAt: secondsAgo(600) as Date | null,
  agentSeenAt: secondsAgo(10) as Date | null,
  ...over,
});

function setup(rows: { active?: unknown[]; waiting?: unknown[] } = {}) {
  const prisma = {
    interpreterSession: {
      findMany: jest.fn(async ({ where }: any) =>
        where.status === 'ACTIVE' ? (rows.active ?? []) : (rows.waiting ?? []),
      ),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    aiSession: {
      findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
    },
  };
  const livekit = { agentPresent: jest.fn().mockResolvedValue(true) };
  const interpreter = { close: jest.fn().mockResolvedValue(undefined) };
  const reconciler = new InterpreterReconciler(
    prisma as any,
    livekit as any,
    interpreter as any,
  );
  return { reconciler, prisma, livekit, interpreter };
}

beforeEach(() => {
  jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
});

afterEach(() => jest.restoreAllMocks());

describe('InterpreterReconciler: active sessions', () => {
  it.each([
    ['terminated_no_funds', 'NO_FUNDS'],
    ['terminated_stale', 'MAX_DURATION'],
    ['failed', 'TRANSLATION_FAILED'],
  ])(
    'ends a session whose billing metering closed as %s',
    async (billing, reason) => {
      const row = active();
      const { reconciler, prisma, livekit, interpreter } = setup({
        active: [row],
      });
      prisma.aiSession.findUnique.mockResolvedValue({ status: billing });

      await reconciler.runOnce(NOW);

      expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
        where: { id: 'bill-1' },
        select: { status: true },
      });
      expect(interpreter.close).toHaveBeenCalledWith(row, reason, {
        stopAgent: true,
      });
      expect(livekit.agentPresent).not.toHaveBeenCalled();
    },
  );

  it('notes when it last saw the agent in the room', async () => {
    const { reconciler, prisma, livekit, interpreter } = setup({
      active: [active()],
    });

    await reconciler.runOnce(NOW);

    expect(livekit.agentPresent).toHaveBeenCalledWith('interp-room-1');
    expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
      where: { id: 'sess-1', status: 'ACTIVE' },
      data: { agentSeenAt: NOW },
    });
    expect(interpreter.close).not.toHaveBeenCalled();
  });

  it('ends a session the agent has been missing from for over 60 s', async () => {
    const lost = active({ agentSeenAt: secondsAgo(61) });
    const { reconciler, livekit, interpreter } = setup({ active: [lost] });
    livekit.agentPresent.mockResolvedValue(false);

    await reconciler.runOnce(NOW);

    expect(interpreter.close).toHaveBeenCalledWith(lost, 'AGENT_LOST', {
      stopAgent: true,
    });
  });

  it('gives the agent 60 s, counted from the join when it was never seen', async () => {
    const { reconciler, livekit, interpreter, prisma } = setup({
      active: [
        active({ agentSeenAt: secondsAgo(60) }),
        active({ id: 'sess-2', agentSeenAt: null, startedAt: secondsAgo(30) }),
      ],
    });
    livekit.agentPresent.mockResolvedValue(false);

    await reconciler.runOnce(NOW);

    expect(interpreter.close).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.updateMany).not.toHaveBeenCalled();
  });

  it('decides nothing when LiveKit does not answer', async () => {
    const { reconciler, livekit, interpreter, prisma } = setup({
      active: [active({ agentSeenAt: secondsAgo(3600) })],
    });
    livekit.agentPresent.mockResolvedValue(null);

    await reconciler.runOnce(NOW);

    expect(interpreter.close).not.toHaveBeenCalled();
    expect(prisma.interpreterSession.updateMany).not.toHaveBeenCalled();
  });
});

describe('InterpreterReconciler: waiting sessions', () => {
  it('ends a waiting session whose code expired over 5 minutes ago', async () => {
    const stale = { id: 'sess-w', roomName: 'interp-w' };
    const { reconciler, prisma, interpreter } = setup({ waiting: [stale] });

    await reconciler.runOnce(NOW);

    expect(prisma.interpreterSession.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          status: 'WAITING',
          codeExpiresAt: { lt: new Date(NOW.getTime() - 5 * 60_000) },
        },
      }),
    );
    expect(interpreter.close).toHaveBeenCalledWith(stale, 'EXPIRED', {
      stopAgent: false,
    });
  });
});

describe('InterpreterReconciler: robustness', () => {
  it('goes on with the other sessions when one fails', async () => {
    const { reconciler, livekit, interpreter } = setup({
      active: [active(), active({ id: 'sess-2', roomName: 'interp-room-2' })],
      waiting: [{ id: 'sess-w', roomName: 'interp-w' }],
    });
    livekit.agentPresent
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(false);
    interpreter.close.mockRejectedValue(new Error('db down'));

    await expect(reconciler.runOnce(NOW)).resolves.toBeUndefined();
    expect(livekit.agentPresent).toHaveBeenCalledTimes(2);
    expect(interpreter.close).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'sess-w' }),
      'EXPIRED',
      { stopAgent: false },
    );
  });

  it('never throws, even when the sessions cannot be loaded', async () => {
    const { reconciler, prisma } = setup();
    prisma.interpreterSession.findMany.mockRejectedValue(new Error('db down'));

    await expect(reconciler.tick()).resolves.toBeUndefined();
  });

  it('skips a tick while the previous one is still running', async () => {
    const { reconciler, prisma } = setup();
    let release!: () => void;
    prisma.interpreterSession.findMany.mockReturnValueOnce(
      new Promise((resolve) => (release = () => resolve([]))),
    );

    const first = reconciler.tick();
    await reconciler.tick();
    expect(prisma.interpreterSession.findMany).toHaveBeenCalledTimes(1);

    release();
    await first;
    await reconciler.tick();
    expect(prisma.interpreterSession.findMany).toHaveBeenCalledTimes(4);
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter.reconciler.spec.ts` не запускается: `Cannot find module './interpreter.reconciler'`. Всего тестов 149, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter.reconciler.ts` целиком:

```ts
import { Injectable, Logger } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import type { InterpreterEndReason } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { InterpreterLivekitService } from './interpreter-livekit.service';
import { InterpreterService } from './interpreter.service';

// As long as the agent waits for a person who left. A room without the agent
// for that long means it was restarted or redeployed: it will not report.
const AGENT_LOST_AFTER_MS = 60_000;
// After a code expires the host can still ask for a new one this long.
const WAITING_GRACE_MS = 5 * 60_000;

const SESSION_FIELDS = {
  id: true,
  roomName: true,
  billingSessionId: true,
  startedAt: true,
  agentSeenAt: true,
} as const;

type ReconciledSession = {
  id: string;
  roomName: string;
  billingSessionId: string | null;
  startedAt: Date | null;
  agentSeenAt: Date | null;
};

/**
 * Ends the sessions nobody else will end: billing closed by metering (no
 * funds, the 2-hour cap), an agent gone without reporting (restart, deploy),
 * a QR nobody scanned. Every end goes through InterpreterService.close, the
 * same path as a hang-up. Runs on every app node; close() makes that safe.
 */
@Injectable()
export class InterpreterReconciler {
  private readonly log = new Logger(InterpreterReconciler.name);
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly livekit: InterpreterLivekitService,
    private readonly interpreter: InterpreterService,
  ) {}

  @Interval(10_000)
  async tick(): Promise<void> {
    // An SFU that answers slowly can make a pass outlast the interval.
    if (this.running) return;
    this.running = true;
    try {
      await this.runOnce();
    } finally {
      this.running = false;
    }
  }

  /** One pass. Never throws: each session is handled on its own. */
  async runOnce(now = new Date()): Promise<void> {
    await this.forEach(
      'active sessions',
      () =>
        this.prisma.interpreterSession.findMany({
          where: { status: 'ACTIVE' },
          select: SESSION_FIELDS,
        }),
      (s) => this.reconcileActive(s, now),
    );
    await this.forEach(
      'expired codes',
      () =>
        this.prisma.interpreterSession.findMany({
          where: {
            status: 'WAITING',
            codeExpiresAt: { lt: new Date(now.getTime() - WAITING_GRACE_MS) },
          },
          select: SESSION_FIELDS,
        }),
      (s) => this.interpreter.close(s, 'EXPIRED', { stopAgent: false }),
    );
  }

  private async reconcileActive(
    s: ReconciledSession,
    now: Date,
  ): Promise<void> {
    if (s.billingSessionId) {
      const billing = await this.prisma.aiSession.findUnique({
        where: { id: s.billingSessionId },
        select: { status: true },
      });
      if (billing?.status !== 'active') {
        await this.interpreter.close(s, endedByBilling(billing?.status), {
          stopAgent: true,
        });
        return;
      }
    }

    const present = await this.livekit.agentPresent(s.roomName);
    // LiveKit did not answer: nothing is known, so nothing is decided.
    if (present === null) return;
    if (present) {
      await this.prisma.interpreterSession.updateMany({
        where: { id: s.id, status: 'ACTIVE' },
        data: { agentSeenAt: now },
      });
      return;
    }
    const lastSeen = s.agentSeenAt ?? s.startedAt;
    if (lastSeen && now.getTime() - lastSeen.getTime() > AGENT_LOST_AFTER_MS) {
      // Stopped anyway: the agent may still hold the session while it
      // tries to get back into the room.
      await this.interpreter.close(s, 'AGENT_LOST', { stopAgent: true });
    }
  }

  private async forEach(
    what: string,
    load: () => Promise<ReconciledSession[]>,
    handle: (s: ReconciledSession) => Promise<void>,
  ): Promise<void> {
    let sessions: ReconciledSession[];
    try {
      sessions = await load();
    } catch (e) {
      this.log.warn(`loading ${what} failed: ${String(e)}`);
      return;
    }
    for (const s of sessions) {
      try {
        await handle(s);
      } catch (e) {
        this.log.warn(`session ${s.id}: reconciling failed: ${String(e)}`);
      }
    }
  }
}

function endedByBilling(status: string | undefined): InterpreterEndReason {
  if (status === 'terminated_no_funds') return 'NO_FUNDS';
  if (status === 'terminated_stale') return 'MAX_DURATION';
  // Ended some other way, or gone: the conversation cannot go on unbilled.
  return 'TRANSLATION_FAILED';
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 15 наборов, 160 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter.reconciler.ts src/interpreter/interpreter.reconciler.spec.ts
git commit -m "feat(interpreter): сверка — no_funds, max_duration, agent_lost, expired" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Секрет отчёта агента

По образцу `RecorderSecretGuard`: постоянное время сравнения, `401` при пустом или неверном секрете.

**Files:**
- Create: `src/interpreter/interpreter-secret.guard.ts`, `src/interpreter/interpreter-secret.guard.spec.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter-secret.guard.spec.ts` целиком:

```ts
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { InterpreterSecretGuard } from './interpreter-secret.guard';

function ctxWithHeaders(headers: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers }) }),
  } as unknown as ExecutionContext;
}

describe('InterpreterSecretGuard', () => {
  let guard: InterpreterSecretGuard;
  const origEnv = process.env.INTERPRETER_SHARED_SECRET;

  beforeEach(() => {
    guard = new InterpreterSecretGuard();
    process.env.INTERPRETER_SHARED_SECRET = 'test-secret-value';
  });

  afterAll(() => {
    if (origEnv === undefined) delete process.env.INTERPRETER_SHARED_SECRET;
    else process.env.INTERPRETER_SHARED_SECRET = origEnv;
  });

  it('allows request with correct secret', () => {
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': 'test-secret-value' });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('rejects request with wrong secret', () => {
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': 'wrong' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it('rejects a secret of the right length that differs', () => {
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': 'test-secret-valuf' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it('rejects request without header', () => {
    expect(() => guard.canActivate(ctxWithHeaders({}))).toThrow(
      UnauthorizedException,
    );
  });

  it('fails closed when secret is not configured', () => {
    delete process.env.INTERPRETER_SHARED_SECRET;
    const ctx = ctxWithHeaders({ 'x-interpreter-secret': '' });
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter-secret.guard.spec.ts` не запускается: `Cannot find module './interpreter-secret.guard'`. Всего тестов 160, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter-secret.guard.ts` целиком:

```ts
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { timingSafeEqual } from 'crypto';
import type { Request } from 'express';

/**
 * The agent's calls back into the backend (agent-ended). The agent is not a
 * user, so it proves itself with INTERPRETER_SHARED_SECRET, the same secret
 * the backend sends it, in x-interpreter-secret.
 */
@Injectable()
export class InterpreterSecretGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const expected = process.env.INTERPRETER_SHARED_SECRET;
    // Unset must not mean "an empty header matches".
    if (!expected) {
      throw new UnauthorizedException('interpreter_secret_not_configured');
    }

    const raw = req.headers['x-interpreter-secret'];
    const header = Array.isArray(raw) ? raw[0] : raw;
    if (typeof header !== 'string') {
      throw new UnauthorizedException('bad_interpreter_secret');
    }

    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new UnauthorizedException('bad_interpreter_secret');
    }
    return true;
  }
}
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 16 наборов, 165 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter-secret.guard.ts src/interpreter/interpreter-secret.guard.spec.ts
git commit -m "feat(interpreter): guard секрета отчёта агента" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: Ручки, модуль и регистрация

`sessions/join` объявлен раньше `sessions/:id/*`. Отчёт агента — под секретом и без троттлинга: все отчёты идут с одного адреса агента, и потерянный стоит хосту денег. Модуль регистрируется в `AppModule`.

**Files:**
- Create: `src/interpreter/interpreter.controller.ts`, `src/interpreter/interpreter.module.ts` и их спеки
- Modify: `src/app.module.ts`

- [ ] **Step 1: Тесты (падают)**

`src/interpreter/interpreter.controller.spec.ts` целиком:

```ts
import { ParseUUIDPipe, RequestMethod } from '@nestjs/common';
import {
  GUARDS_METADATA,
  HTTP_CODE_METADATA,
  METHOD_METADATA,
  PATH_METADATA,
  ROUTE_ARGS_METADATA,
} from '@nestjs/common/constants';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { InterpreterSecretGuard } from './interpreter-secret.guard';
import { InterpreterController } from './interpreter.controller';

const ROUTES = [
  ['languages', 'GET', 'languages'],
  ['create', 'POST', 'sessions'],
  ['join', 'POST', 'sessions/join'],
  ['newCode', 'POST', 'sessions/:id/code'],
  ['get', 'GET', 'sessions/:id'],
  ['end', 'POST', 'sessions/:id/end'],
  ['selftest', 'GET', 'selftest'],
  ['agentEnded', 'POST', 'internal/sessions/:id/agent-ended'],
] as const;

const handler = (name: (typeof ROUTES)[number][0]) =>
  InterpreterController.prototype[name];

describe('InterpreterController routes', () => {
  it('lives under /interpreter', () => {
    expect(Reflect.getMetadata(PATH_METADATA, InterpreterController)).toBe(
      'interpreter',
    );
  });

  it.each(ROUTES)('%s is %s %s', (name, method, path) => {
    expect(Reflect.getMetadata(METHOD_METADATA, handler(name))).toBe(
      RequestMethod[method],
    );
    expect(Reflect.getMetadata(PATH_METADATA, handler(name))).toBe(path);
  });

  it('puts every route a person calls behind the JWT guard', () => {
    for (const [name] of ROUTES.filter(([n]) => n !== 'agentEnded')) {
      expect(Reflect.getMetadata(GUARDS_METADATA, handler(name))).toEqual([
        JwtAuthGuard,
      ]);
    }
  });

  it('lets only the agent report an end, unthrottled, answered 200', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, handler('agentEnded'))).toEqual(
      [InterpreterSecretGuard],
    );
    for (const name of ['short', 'medium', 'long']) {
      expect(
        Reflect.getMetadata(`THROTTLER:SKIP${name}`, handler('agentEnded')),
      ).toBe(true);
    }
    expect(Reflect.getMetadata(HTTP_CODE_METADATA, handler('agentEnded'))).toBe(
      200,
    );
  });

  it.each(['newCode', 'get', 'end', 'agentEnded'] as const)(
    '%s takes the session id as a UUID',
    (name) => {
      const args: Record<string, { data?: unknown; pipes: unknown[] }> =
        Reflect.getMetadata(ROUTE_ARGS_METADATA, InterpreterController, name);
      const id = Object.values(args).find((a) => a.data === 'id');
      expect(id?.pipes).toContain(ParseUUIDPipe);
    },
  );
});

describe('InterpreterController handlers', () => {
  const user = { sub: 'user-1', session_id: 'login-1' };
  const ID = '0f8fad5b-d9cb-469f-a165-70867728950e';
  let service: Record<string, jest.Mock>;
  let controller: InterpreterController;

  beforeEach(() => {
    service = {
      languages: jest.fn().mockReturnValue({ enabled: true, languages: [] }),
      create: jest.fn().mockResolvedValue('created'),
      join: jest.fn().mockResolvedValue('joined'),
      newCode: jest.fn().mockResolvedValue('code'),
      get: jest.fn().mockResolvedValue('view'),
      end: jest.fn().mockResolvedValue({ status: 'ended' }),
      agentEnded: jest.fn().mockResolvedValue({ ok: true }),
      selftest: jest.fn(),
    };
    controller = new InterpreterController(service as any);
  });

  it('hands each request to the service', async () => {
    expect(controller.languages()).toEqual({ enabled: true, languages: [] });
    await expect(controller.create(user, { lang: 'ru' })).resolves.toBe(
      'created',
    );
    expect(service.create).toHaveBeenCalledWith(user, 'ru');
    await expect(
      controller.join(user, { code: 'abcd-efgh', lang: 'de' }),
    ).resolves.toBe('joined');
    expect(service.join).toHaveBeenCalledWith(user, 'abcd-efgh', 'de');
    await controller.newCode(user, ID);
    expect(service.newCode).toHaveBeenCalledWith('user-1', ID);
    await controller.get(user, ID);
    expect(service.get).toHaveBeenCalledWith('user-1', ID);
    await controller.end(user, ID);
    expect(service.end).toHaveBeenCalledWith('user-1', ID);
    await controller.agentEnded(ID, { reason: 'partner_left' });
    expect(service.agentEnded).toHaveBeenCalledWith(ID, 'partner_left');
  });

  it("answers the selftest with the agent's own status and body", async () => {
    service.selftest.mockResolvedValue({
      status: 500,
      body: { ok: false, reason: 'phrase: 404' },
    });
    const res = { status: jest.fn() };

    await expect(controller.selftest(res as any)).resolves.toEqual({
      ok: false,
      reason: 'phrase: 404',
    });
    expect(res.status).toHaveBeenCalledWith(500);
  });
});
```

`src/interpreter/interpreter.module.spec.ts` целиком:

```ts
import { Test } from '@nestjs/testing';
import { BillingModule } from '../billing/billing.module';
import { GatingService } from '../billing/services/gating.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { InterpreterController } from './interpreter.controller';
import { InterpreterModule } from './interpreter.module';
import { InterpreterReconciler } from './interpreter.reconciler';

// The real BillingModule pulls in the whole app's module graph, which jest
// cannot load (oidc.module.ts imports './….js' paths). Its providers are
// stubbed below anyway.
jest.mock('../billing/billing.module', () => ({
  BillingModule: class BillingModule {},
}));

describe('InterpreterModule', () => {
  it('takes billing from BillingModule', () => {
    expect(Reflect.getMetadata('imports', InterpreterModule)).toContain(
      BillingModule,
    );
  });

  it('wires its own providers, given the app-wide ones', async () => {
    // Only what the module gets from outside is stubbed: a class imported
    // with `import type` would compile, yet leave Nest nothing to inject.
    const moduleRef = await Test.createTestingModule({
      controllers: Reflect.getMetadata('controllers', InterpreterModule),
      providers: [
        ...Reflect.getMetadata('providers', InterpreterModule),
        { provide: PrismaService, useValue: {} },
        { provide: RedisService, useValue: {} },
        { provide: GatingService, useValue: {} },
      ],
    }).compile();

    expect(moduleRef.get(InterpreterController)).toBeInstanceOf(
      InterpreterController,
    );
    expect(moduleRef.get(InterpreterReconciler)).toBeInstanceOf(
      InterpreterReconciler,
    );
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter.controller.spec.ts` не запускается: `Cannot find module './interpreter.controller'`; `src/interpreter/interpreter.module.spec.ts` не запускается: `Cannot find module './interpreter.controller'`. Всего тестов 165, падающих 0.

- [ ] **Step 2: Код**

`src/interpreter/interpreter.controller.ts` целиком:

```ts
import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import type { Response } from 'express';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { AgentEndedDto } from './dto/agent-ended.dto';
import { CreateInterpreterSessionDto } from './dto/create-interpreter-session.dto';
import { JoinInterpreterSessionDto } from './dto/join-interpreter-session.dto';
import { InterpreterSecretGuard } from './interpreter-secret.guard';
import {
  InterpreterService,
  type InterpreterUser,
} from './interpreter.service';

/**
 * Face-to-face interpreter. Each route checks that the caller takes part in
 * the session it names — in the service, which answers 404 to anyone else.
 */
@Controller('interpreter')
export class InterpreterController {
  constructor(private readonly interpreter: InterpreterService) {}

  @Get('languages')
  @UseGuards(JwtAuthGuard)
  languages() {
    return this.interpreter.languages();
  }

  @Post('sessions')
  @UseGuards(JwtAuthGuard)
  create(
    @CurrentUser() user: InterpreterUser,
    @Body() dto: CreateInterpreterSessionDto,
  ) {
    return this.interpreter.create(user, dto.lang);
  }

  // Ahead of the sessions/:id routes, so that "join" is never taken for an id.
  @Post('sessions/join')
  @UseGuards(JwtAuthGuard)
  join(
    @CurrentUser() user: InterpreterUser,
    @Body() dto: JoinInterpreterSessionDto,
  ) {
    return this.interpreter.join(user, dto.code, dto.lang);
  }

  @Post('sessions/:id/code')
  @UseGuards(JwtAuthGuard)
  newCode(
    @CurrentUser() user: InterpreterUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.interpreter.newCode(user.sub, id);
  }

  @Get('sessions/:id')
  @UseGuards(JwtAuthGuard)
  get(
    @CurrentUser() user: InterpreterUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.interpreter.get(user.sub, id);
  }

  @Post('sessions/:id/end')
  @UseGuards(JwtAuthGuard)
  end(
    @CurrentUser() user: InterpreterUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.interpreter.end(user.sub, id);
  }

  /**
   * Post-deploy smoke of both engines, with the agent's own status. Behind
   * auth, unlike translator/selftest: every call opens OpenAI sessions.
   */
  @Get('selftest')
  @UseGuards(JwtAuthGuard)
  async selftest(@Res({ passthrough: true }) res: Response) {
    const { status, body } = await this.interpreter.selftest();
    res.status(status);
    return body;
  }

  /**
   * The agent reports that it stopped by itself. Not throttled: all reports
   * come from the agent's single address, and a lost one costs the host money.
   */
  @Post('internal/sessions/:id/agent-ended')
  @UseGuards(InterpreterSecretGuard)
  @SkipThrottle({ short: true, medium: true, long: true })
  @HttpCode(200)
  agentEnded(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AgentEndedDto,
  ) {
    return this.interpreter.agentEnded(id, dto.reason);
  }
}
```

`src/interpreter/interpreter.module.ts` целиком:

```ts
import { Module } from '@nestjs/common';
import { BillingModule } from '../billing/billing.module';
import { InterpreterAgentClient } from './interpreter-agent.client';
import { InterpreterLivekitService } from './interpreter-livekit.service';
import { InterpreterSecretGuard } from './interpreter-secret.guard';
import { InterpreterController } from './interpreter.controller';
import { InterpreterReconciler } from './interpreter.reconciler';
import { InterpreterService } from './interpreter.service';

/**
 * Face-to-face interpreter: two people side by side, each on their own phone.
 * Prisma and Redis come from their global modules; the reconciler's
 * @Interval needs the ScheduleModule registered in AppModule.
 */
@Module({
  imports: [BillingModule],
  controllers: [InterpreterController],
  providers: [
    InterpreterService,
    InterpreterReconciler,
    InterpreterAgentClient,
    InterpreterLivekitService,
    InterpreterSecretGuard,
  ],
})
export class InterpreterModule {}
```

Патч к `src/app.module.ts`:

```diff
--- a/src/app.module.ts
+++ b/src/app.module.ts
@@ -35,6 +35,7 @@
 import { PartnerModule } from './partner/partner.module';
 import { PartnerApiModule } from './partner-api/partner-api.module';
 import { SystemChannelModule } from './system-channel/system-channel.module';
+import { InterpreterModule } from './interpreter/interpreter.module';
 import { ScheduleModule } from '@nestjs/schedule';
 import configuration from './config/configuration';
 
@@ -128,6 +129,7 @@
     PartnerModule,
     PartnerApiModule,
     SystemChannelModule,
+    InterpreterModule,
   ],
   controllers: [AppController],
   providers: [
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 184 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter.controller.ts src/interpreter/interpreter.controller.spec.ts src/interpreter/interpreter.module.ts src/interpreter/interpreter.module.spec.ts src/app.module.ts
git commit -m "feat(interpreter): ручки /interpreter/*, модуль и регистрация" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: `RoomAccessGuard` закрыт для комнат разговора

Guard пускает любой токен LiveKit своей комнаты на ручки записи встречи, публичного переводчика и чата. У обоих участников разговора такой токен есть — значит, любой из них мог бы включить в комнате запись встречи. Комнатам `interp-*` ни одна из этих ручек не нужна.

**Files:**
- Modify: `src/voice/guards/room-access.guard.ts`, `src/voice/guards/room-access.guard.spec.ts`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/voice/guards/room-access.guard.spec.ts`:

```diff
--- a/src/voice/guards/room-access.guard.spec.ts
+++ b/src/voice/guards/room-access.guard.spec.ts
@@ -83,6 +83,18 @@
     expect(req.roomActor).toBe('guest-1');
   });
 
+  it('rejects interpreter rooms, even with a LiveKit grant for one', async () => {
+    // Both people in an interpreter room hold a grant for it; none of the
+    // routes behind this guard (recorder, translator, chat) belongs there.
+    const room = 'interp-0f8fad5b-d9cb-469f-a165-70867728950e';
+    const err = await guard
+      .canActivate(ctxFor(room, `Bearer ${livekitToken(room)}`))
+      .catch((e: unknown) => e);
+
+    expect(err).toBeInstanceOf(ForbiddenException);
+    expect((err as ForbiddenException).message).toBe('interpreter_room');
+  });
+
   it('rejects a LiveKit grant for a different room', async () => {
     // The core of the finding: knowing a room name must not be enough.
     const ctx = ctxFor('call-victim', `Bearer ${livekitToken('call-mine')}`);
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/voice/guards/room-access.guard.spec.ts` — падают 1 из 15. Всего тестов 185, падающих 1.

- [ ] **Step 2: Код**

Патч к `src/voice/guards/room-access.guard.ts`:

```diff
--- a/src/voice/guards/room-access.guard.ts
+++ b/src/voice/guards/room-access.guard.ts
@@ -53,6 +53,14 @@
     const req = ctx.switchToHttp().getRequest();
     const roomName: string | undefined = req.params?.roomName;
     if (!roomName) throw new ForbiddenException('room not specified');
+    // Interpreter rooms (src/interpreter) hold two people and the agent, and
+    // both people have a LiveKit grant for the room — which alone passes this
+    // guard. None of the routes behind it (recorder, public translator, room
+    // chat) belongs in such a room: a recorder there would capture the very
+    // speech the agent keeps off the other phone.
+    if (roomName.startsWith('interp-')) {
+      throw new ForbiddenException('interpreter_room');
+    }
 
     const auth = req.headers['authorization'];
     const token =
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 185 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/voice/guards/room-access.guard.ts src/voice/guards/room-access.guard.spec.ts
git commit -m "fix(voice): комнатные ручки закрыты для комнат разговора с переводом" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: `.env.example`

Выключатель и общий секрет с агентом — с объяснением, что делает выключатель и чего не трогает.

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Код**

Патч к `.env.example`:

```diff
--- a/.env.example
+++ b/.env.example
@@ -150,3 +150,18 @@
 # Пусто, не число или отрицательное — дефолт 5000. Ровно 0 — не «не задано»,
 # а явный выключатель: любая попытка завести НОВЫЙ аккаунт отвечает 429.
 PARTNER_ACCOUNTS_PER_DAY=5000
+
+# ── Разговор с переводом (двое рядом) — docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md ──
+# Выключатель. При false GET /interpreter/languages отвечает enabled=false (приложение
+# прячет кнопку), а новый разговор не начать: создание, вход и новый код — 403
+# interpreter_disabled. Идущие разговоры он не трогает — завершение, чтение сессии и
+# сверка работают, — как и GET /interpreter/selftest для смоука после деплоя.
+INTERPRETER_ENABLED=false
+# Общий секрет с livekit-ai-agent в обе стороны (заголовок x-interpreter-secret):
+# бэкенд шлёт агенту образцы голоса обоих, агент сообщает о завершении. Одинаковый
+# в .env бэкенда (на всех нодах) и агента. Пустой — агенту ничего не уходит, его
+# колбэки отклоняются.
+INTERPRETER_SHARED_SECRET=
+# Адрес livekit-ai-agent, общий с переводчиком звонков и записью встреч.
+# По умолчанию http://localhost:3100.
+# AI_AGENT_URL=http://localhost:3100
```

- [ ] **Step 2: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 185 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 3: Коммит**

```bash
git add .env.example
git commit -m "docs(interpreter): INTERPRETER_ENABLED и INTERPRETER_SHARED_SECRET в .env.example" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: Фразовый движок: время по звуку, а не по часам

Фильтр голоса отдаёт звук кусками по 500 мс, а нарезчик реплик мерил тишину по часам: реплика закрывалась только на третьем тихом куске, через 1,5 с тишины вместо 0,6 с. На стенде фразовое направление отвечало через 7–7,5 с от начала фразы. Теперь обёртка режет кусок на кадры по 20 мс и подаёт каждый со временем по звуку (`sendAudio(base64, atMs)`). Переводчик в звонках шлёт без `atMs` и живёт по часам, как раньше.

**Files:**
- Modify: `livekit-agent/realtime-phrase-session.js`, `livekit-agent/phrase-session.js`, `livekit-agent/translator-turns.js` (комментарий)
- Modify: `livekit-agent/realtime-phrase-session.test.js`, `livekit-agent/phrase-session.test.js`

- [ ] **Step 1: Тесты (падают)**

Патч к `livekit-agent/phrase-session.test.js`:

```diff
--- a/livekit-agent/phrase-session.test.js
+++ b/livekit-agent/phrase-session.test.js
@@ -34,6 +34,16 @@
 const loud = () => chunk(3000);
 const quiet = () => chunk(0);
 const firstSample = (msg) => Buffer.from(msg.audio, 'base64').readInt16LE(0);
+// A 500 ms chunk goes in as 25 frames of 20 ms: one value per frame.
+const framed = (...values) => values.flatMap((v) => new Array(25).fill(v));
+
+/** How many 20 ms frames went in before the first commit, the frame that made the cut included. */
+function framesBeforeCommit(fake) {
+  const kinds = fake.sent.map((m) => m.type);
+  const cut = kinds.indexOf('input_audio_buffer.commit');
+  assert.ok(cut >= 0, 'nothing was committed');
+  return kinds.slice(0, cut).filter((k) => k === 'input_audio_buffer.append').length;
+}
 
 test('it runs the given model with the known source language', () => {
   const { fake } = session();
@@ -139,7 +149,7 @@
   at(1500, quiet()); // open, not yet confirmed: used to be dropped, splicing a gap into the phrase
   now = 1800;
   fake.serverSends({ type: 'session.updated' });
-  assert.deepStrictEqual(appends(fake).map(firstSample), [0, 3000, 3000, 0]);
+  assert.deepStrictEqual(appends(fake).map(firstSample), framed(0, 3000, 3000, 0));
   assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
   // The turn-taker heard the replay: live silence ends that phrase as usual
   // (before the fix it never saw the speech and nothing was ever committed).
@@ -153,7 +163,57 @@
   for (let i = 1; i <= 12; i++) s.sendAudio(chunk(i)); // 6 s of handshake
   fake.open();
   fake.serverSends({ type: 'session.updated' });
-  assert.deepStrictEqual(appends(fake).map(firstSample), [5, 6, 7, 8, 9, 10, 11, 12]);
+  assert.deepStrictEqual(appends(fake).map(firstSample), framed(5, 6, 7, 8, 9, 10, 11, 12));
+});
+
+// ── pauses measured in audio, not in the gate's 500 ms deliveries ──
+
+test('a pause is cut after 600 ms of audio: inside the second quiet chunk, not on the third', (t) => {
+  // The wall clock stands still: only the audio can tell how long the pause is.
+  // Before, every chunk was one reading of Date.now(), so here the pause never
+  // grew at all; on the bench the cut came only with a third quiet chunk.
+  t.mock.method(Date, 'now', () => 0);
+  const { s, fake } = session();
+  fake.serverSends({ type: 'session.updated' });
+  const commits = () => fake.sentOfType('input_audio_buffer.commit').length;
+  s.sendAudio(loud());
+  s.sendAudio(loud());
+  s.sendAudio(quiet());
+  assert.strictEqual(commits(), 0, '500 ms of silence is still inside the phrase');
+  s.sendAudio(quiet());
+  assert.strictEqual(commits(), 1);
+  // 50 frames of speech, 30 of silence (600 ms) and the frame that ends the wait.
+  assert.strictEqual(framesBeforeCommit(fake), 50 + 30 + 1);
+  assert.ok(appends(fake).every((m) => Buffer.from(m.audio, 'base64').length === 960), 'in 20 ms frames');
+});
+
+test('someone who does not pause is cut after 7 s of their audio', (t) => {
+  t.mock.method(Date, 'now', () => 0);
+  const lines = [];
+  t.mock.method(console, 'log', (...args) => lines.push(args.join(' ')));
+  const { s, fake } = session();
+  fake.serverSends({ type: 'session.updated' });
+  for (let i = 0; i < 14; i++) s.sendAudio(loud()); // 7 s
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
+  s.sendAudio(loud());
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
+  assert.strictEqual(framesBeforeCommit(fake), 350 + 1, 'cut on the frame that starts 7 s into the speech');
+  assert.ok(lines.some((l) => l.endsWith('Committing (force)')), lines.join('\n'));
+});
+
+test('audio that waited for the session counts on the audio clock too', (t) => {
+  t.mock.method(Date, 'now', () => 0);
+  const { s, fake } = session({}, { open: false });
+  s.sendAudio(loud());
+  s.sendAudio(quiet()); // the handshake is still running: the pause begins in the queue
+  fake.open();
+  fake.serverSends({ type: 'session.updated' });
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
+  s.sendAudio(quiet());
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
+  // 25 frames of speech; 30 of silence, 500 ms of it from the queue and 100 ms
+  // live; and the frame that ends the wait.
+  assert.strictEqual(framesBeforeCommit(fake), 25 + 30 + 1);
 });
 
 test('a throwing callback is logged, not thrown into the socket or passed off as a parse error', () => {
```

Патч к `livekit-agent/realtime-phrase-session.test.js`:

```diff
--- a/livekit-agent/realtime-phrase-session.test.js
+++ b/livekit-agent/realtime-phrase-session.test.js
@@ -226,3 +226,30 @@
   inCall.fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'Добрый день' });
   assert.ok(lines.some((l) => l.endsWith('heard: "Добрый день"')));
 });
+
+// 20 ms of PCM16 at one level, the frame the interpreter's phrase adapter sends.
+const frame20 = (level) => Buffer.from(new Int16Array(480).fill(level).buffer).toString('base64');
+
+test('a frame sent with its time is judged on that time, not on the wall clock', (t) => {
+  t.mock.method(Date, 'now', () => 0); // the wall clock stands still
+  const { ws, fake } = open('ru', 'sk');
+  fake.serverSends({ type: 'session.updated' });
+  let at = 0;
+  for (; at < 1000; at += 20) ws.sendAudio(frame20(1000), at);
+  for (; at < 1600; at += 20) ws.sendAudio(frame20(0), at);
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
+  ws.sendAudio(frame20(0), at); // 600 ms after the pause began
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
+});
+
+test('a frame sent without a time is judged on Date.now(), as the in-call translator sends it', (t) => {
+  let now = 0;
+  t.mock.method(Date, 'now', () => now);
+  const { ws, fake } = open('ru', 'sk');
+  fake.serverSends({ type: 'session.updated' });
+  for (; now < 1000; now += 20) ws.sendAudio(frame20(1000));
+  for (let i = 0; i < 50; i++) ws.sendAudio(frame20(0)); // a second of frames while the wall clock stands still
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
+  for (const end = now + 600; now <= end; now += 20) ws.sendAudio(frame20(0));
+  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
+});
```

Run: `cd /Users/dmitry/taler-id/.worktrees/interpreter/livekit-agent && npm test 2>&1 | grep -E "^ℹ (pass|fail)"`
Expected: `ℹ fail 6` — падают только новые и изменённые тесты этой задачи.

- [ ] **Step 2: Код**

Патч к `livekit-agent/realtime-phrase-session.js`:

```diff
--- a/livekit-agent/realtime-phrase-session.js
+++ b/livekit-agent/realtime-phrase-session.js
@@ -20,6 +20,14 @@
  *                 (default true: the in-call translator logs them as before)
  * wsFactory must return a new socket that is still connecting: its 'open'
  * event is what sends the session.update.
+ *
+ * The socket comes back with sendAudio(base64Audio, atMs): one frame of 24 kHz
+ * PCM16, appended and judged speech or silence for the turn-taker. atMs is the
+ * frame's time in ms on the caller's own clock. A caller whose audio arrives
+ * in bursts passes its audio clock, so that a 600 ms pause is 600 ms of audio
+ * and not however long the bursts took to arrive. Without it the frame is
+ * timed by Date.now(), as the in-call translator, which streams live, has
+ * always had it.
  */
 const WebSocket = require('ws');
 const { createTurnTaker } = require('./translator-turns');
@@ -286,7 +294,7 @@
     },
   });
 
-  ws.sendAudio = (base64Audio) => {
+  ws.sendAudio = (base64Audio, atMs) => {
     const msg = JSON.stringify({ type: 'input_audio_buffer.append', audio: base64Audio });
     if (ready && ws.readyState === WebSocket.OPEN) {
       ws.send(msg);
@@ -299,7 +307,7 @@
 
     // Amplitude-based speech/silence detection (replaces server_vad)
     const rms = getFrameRMS(base64Audio);
-    ws._turns.feed(rms >= SPEECH_RMS_THRESHOLD, Date.now());
+    ws._turns.feed(rms >= SPEECH_RMS_THRESHOLD, atMs ?? Date.now());
   };
 
   return ws;
```

Патч к `livekit-agent/phrase-session.js`:

```diff
--- a/livekit-agent/phrase-session.js
+++ b/livekit-agent/phrase-session.js
@@ -17,12 +17,15 @@
 const { createRealtimeSession } = require('./realtime-phrase-session');
 
 const SAMPLE_RATE = 24000;
+const SAMPLES_PER_MS = SAMPLE_RATE / 1000;
+const FRAME_SAMPLES = 480; // 20 ms: what the engine is handed, and judges, at a time
 const HANDSHAKE_TIMEOUT_MS = 10000;
 const READY_TIMEOUT_MS = 10000;
 const MAX_BUFFERED_BYTES = 1 << 20; // ~16 s of base64 audio at 64 KB/s
 // Audio that waits for the session, as in translate-session.js: at most 4 s,
-// older audio is dropped. It goes out through the engine's own path once the
-// session is ready, so the turn-taker hears it as well.
+// older audio is dropped. It is kept as samples and goes out through the same
+// framed path once the session is ready, so the turn-taker hears it and the
+// audio clock counts it.
 const MAX_QUEUED_SAMPLES = 4 * SAMPLE_RATE;
 
 const defaultWsFactory = (url, options) => new WebSocket(url, { ...options, handshakeTimeout: HANDSHAKE_TIMEOUT_MS });
@@ -74,8 +77,9 @@
   let dropped = false; // fail() decided; frames already read must not count
   let ended = false; // the socket has closed
   let readyTimer = null;
-  let queue = [];
+  let queue = []; // Int16Array chunks waiting for the session
   let queuedSamples = 0;
+  let audioMs = 0; // this session's audio clock: how much audio the engine has been handed
   const live = () => !closedByUs && !dropped && !ended;
 
   function forget() {
@@ -96,6 +100,20 @@
     try {
       ws.terminate();
     } catch (_) { /* already closed */ }
+  }
+
+  // The gate hands audio over 500 ms at a time. Sent whole, each chunk was a
+  // single wall-clock reading for the turn-taker, so a pause ended only with
+  // the third quiet chunk: ~1.5 s of silence where it waits for 0.6 s (on the
+  // bench the phrase direction answered 7–7.5 s after the phrase began). Cut
+  // into 20 ms frames, each stamped with the audio that came before it, the
+  // pause is measured in audio, however the chunks arrive.
+  function append(int16) {
+    for (let i = 0; i < int16.length; i += FRAME_SAMPLES) {
+      const frame = int16.subarray(i, i + FRAME_SAMPLES);
+      ws.sendAudio(toBase64(frame), audioMs);
+      audioMs += frame.length / SAMPLES_PER_MS;
+    }
   }
 
   const ws = createRealtimeSession(
@@ -117,7 +135,7 @@
         ready = true;
         const waiting = queue;
         forget();
-        for (const { b64 } of waiting) ws.sendAudio(b64);
+        for (const int16 of waiting) append(int16);
         onReady();
       },
       // Before the session is confirmed nothing but our session.update has
@@ -154,12 +172,14 @@
           fail(`${ws.bufferedAmount} bytes not taken by the server`);
           return;
         }
-        ws.sendAudio(toBase64(int16));
+        append(int16);
         return;
       }
-      queue.push({ b64: toBase64(int16), samples: int16.length });
+      // A copy: the samples are read only once the session is ready, and the
+      // buffer is the caller's.
+      queue.push(int16.slice());
       queuedSamples += int16.length;
-      while (queuedSamples > MAX_QUEUED_SAMPLES && queue.length > 1) queuedSamples -= queue.shift().samples;
+      while (queuedSamples > MAX_QUEUED_SAMPLES && queue.length > 1) queuedSamples -= queue.shift().length;
     },
     close() {
       if (closedByUs) return;
```

Патч к `livekit-agent/translator-turns.js`:

```diff
--- a/livekit-agent/translator-turns.js
+++ b/livekit-agent/translator-turns.js
@@ -68,7 +68,11 @@
       return hasSpeech;
     },
 
-    /** One audio frame's worth of "was this speech", on the wall clock. */
+    /**
+     * One audio frame's worth of "was this speech", at nowMs on the caller's
+     * clock: the wall clock for a live stream, the audio's own clock for
+     * audio that arrives in bursts.
+     */
     feed(isSpeech, nowMs) {
       if (isSpeech) {
         if (!hasSpeech) {
```

- [ ] **Step 3: Проверить на обоих Node**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter/livekit-agent
npm test 2>&1 | grep -E "^ℹ (pass|fail)"
~/.nvm/versions/node/v20.20.2/bin/node --test 2>&1 | grep -E "^# (pass|fail)"
```

Ожидается: `ℹ pass 297`, `ℹ fail 0`; `# pass 297`, `# fail 0`.

- [ ] **Step 4: Коммит**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter/livekit-agent
git add realtime-phrase-session.js realtime-phrase-session.test.js phrase-session.js phrase-session.test.js translator-turns.js
git commit -m "feat(interpreter): фразовый движок режет реплики по времени звука, а не по часам" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 17: Сторож «речь есть, перевода нет»

Если OpenAI начинает отказывать уже после подтверждения сессии (квота, ошибка модели), движок остаётся подключённым и молчит, а хост платит. Сторож считает речь, пропущенную фильтром, с последнего отклика движка; на `INTERPRETER_NO_TRANSLATION_FATAL_MS` (по умолчанию 60 с) пишет одну строку `FATAL interpreter: …` для мониторинга. Разговор не останавливает: речь уже на языке слушателя тоже законно остаётся без перевода.

**Files:**
- Modify: `livekit-agent/interpreter.js`, `livekit-agent/interpreter.test.js`

- [ ] **Step 1: Тесты (падают)**

Патч к `livekit-agent/interpreter.test.js`:

```diff
--- a/livekit-agent/interpreter.test.js
+++ b/livekit-agent/interpreter.test.js
@@ -140,8 +140,9 @@
   return { rtc, made, deps };
 }
 
-// 400 ms of loud speech in 10 ms frames at 24 kHz: four 100 ms chunks.
-const speechFrames = (n = 40) => Array.from({ length: n }, () => new Int16Array(240).fill(3000));
+// 400 ms of loud speech in 10 ms frames at 24 kHz: four 100 ms chunks. `level`
+// lets a test that needs two voices tell them apart by their samples.
+const speechFrames = (n = 40, level = 3000) => Array.from({ length: n }, () => new Int16Array(240).fill(level));
 const settle = (ms = 30) => new Promise((r) => setTimeout(r, ms));
 const deferred = () => {
   let resolve;
@@ -177,17 +178,18 @@
 test('configuration falls back to the documented defaults', () => {
   const c = interpreter.readConfig({});
   assert.deepStrictEqual(
-    [c.model, c.fallbackModel, c.transcribeModel, c.noiseReduction, c.embedUrl, c.threshold, c.margin, c.chunkMs, c.gateTimeoutMs, c.hysteresis, c.speechRms, c.gain, c.presenceGraceMs],
-    ['gpt-realtime-translate', 'gpt-realtime-2025-08-28', 'gpt-4o-mini-transcribe', 'near_field', 'http://127.0.0.1:18082', 0.2, 0.05, 500, 300, 2, 400, 1.4, 60000],
+    [c.model, c.fallbackModel, c.transcribeModel, c.noiseReduction, c.embedUrl, c.threshold, c.margin, c.chunkMs, c.gateTimeoutMs, c.hysteresis, c.speechRms, c.gain, c.presenceGraceMs, c.noTranslationFatalMs],
+    ['gpt-realtime-translate', 'gpt-realtime-2025-08-28', 'gpt-4o-mini-transcribe', 'near_field', 'http://127.0.0.1:18082', 0.2, 0.05, 500, 300, 2, 400, 1.4, 60000, 60000],
   );
 });
 
 test('configuration reads the environment and keeps values in range', () => {
   const c = interpreter.readConfig({
     INTERPRETER_VOICE_THRESHOLD: '0.4', INTERPRETER_GAIN: '9', INTERPRETER_GATE_HYSTERESIS: '0', INTERPRETER_NOISE_REDUCTION: 'off',
-    INTERPRETER_GATE_CHUNK_MS: '0',
+    INTERPRETER_GATE_CHUNK_MS: '0', INTERPRETER_NO_TRANSLATION_FATAL_MS: '1000',
   });
   assert.strictEqual(c.chunkMs, 100);
+  assert.strictEqual(c.noTranslationFatalMs, 15_000);
   assert.strictEqual(c.threshold, 0.4);
   assert.strictEqual(c.gain, 4);
   assert.strictEqual(c.hysteresis, 1);
@@ -674,6 +676,103 @@
   } finally {
     Date.now = realNow;
     await interpreter.stopInterpreter('r-failopen');
+  }
+});
+
+// ── speech that never gets a translation ──
+
+/** Plays frames as `identity`'s microphone, on a track that ends after them. */
+async function playMic(room, identity, frames) {
+  room.emit('trackSubscribed', { kind: 1, frames }, { name: 'mic' }, { identity });
+  await settle();
+}
+const noTranslation = (lines) => lines.filter((l) => l.startsWith('FATAL interpreter: no translation'));
+
+test('speech that gets no translation is FATAL once, and the conversation goes on', async () => {
+  const { rtc, made, deps } = setup({ noTranslationFatalMs: 1000 });
+  await interpreter.startInterpreter({ sessionId: 's23', roomName: 'r-mute', participants: people() }, deps);
+  try {
+    const room = rtc.rooms[0];
+    const lines = await capture(async (seen) => {
+      await playMic(room, 'a#dev1', speechFrames(90));
+      assert.deepStrictEqual(noTranslation(seen), [], '0.9 s of speech is under the limit');
+      await playMic(room, 'a#dev1', speechFrames(30));
+      await playMic(room, 'a#dev1', speechFrames(200)); // on and on, still without a word back
+    });
+    assert.deepStrictEqual(noTranslation(lines), ['FATAL interpreter: no translation for 1 s of speech in r-mute ru→de']);
+    assert.strictEqual(interpreter.getInterpreterStatus('r-mute').running, true, "speech in the listener's language gets silence too: no end");
+    assert.ok(made.every((e) => !e.closed));
+    assert.strictEqual(made.find((e) => e.opts.targetLang === 'de').sent.length, 32, 'the direction is still fed');
+  } finally {
+    await interpreter.stopInterpreter('r-mute');
+  }
+});
+
+test('audio or text from the engine starts the count over; FATAL again only after a new run without either', async () => {
+  const { rtc, made, deps } = setup({ noTranslationFatalMs: 1000 });
+  await interpreter.startInterpreter({ sessionId: 's24', roomName: 'r-mute-reset', participants: people() }, deps);
+  try {
+    const room = rtc.rooms[0];
+    const toB = made.find((e) => e.opts.targetLang === 'de');
+    const lines = await capture(async (seen) => {
+      await playMic(room, 'a#dev1', speechFrames(90));
+      toB.opts.onAudio(new Int16Array(480).fill(5));
+      await playMic(room, 'a#dev1', speechFrames(90));
+      toB.opts.onTranslationText('Guten', false);
+      await playMic(room, 'a#dev1', speechFrames(90));
+      assert.deepStrictEqual(noTranslation(seen), [], 'each output started the count over');
+      await playMic(room, 'a#dev1', speechFrames(10)); // 1 s since the text
+      await playMic(room, 'a#dev1', speechFrames(90)); // still nothing back: no second line
+      assert.strictEqual(noTranslation(seen).length, 1);
+      toB.opts.onTranslationText('Tag', true);
+      await playMic(room, 'a#dev1', speechFrames(100)); // a new run without a word back
+    });
+    assert.strictEqual(noTranslation(lines).length, 2, lines.join('\n'));
+  } finally {
+    await interpreter.stopInterpreter('r-mute-reset');
+  }
+});
+
+test('what the gate silences is not counted: the partner on this phone, or quiet', async () => {
+  const { rtc, made, deps } = setup({ noTranslationFatalMs: 1000 });
+  await interpreter.startInterpreter({ sessionId: 's25', roomName: 'r-mute-zeros', participants: people() }, deps);
+  try {
+    const room = rtc.rooms[0];
+    const quiet = Array.from({ length: 150 }, () => new Int16Array(240));
+    const lines = await capture(async (seen) => {
+      await playMic(room, 'b#dev1', speechFrames(150)); // every window sounds like a: b's gate blocks it all
+      await playMic(room, 'a#dev1', quiet);
+      const toA = made.find((e) => e.opts.targetLang === 'ru');
+      assert.ok(toA.sent.length === 15 && toA.sent.every((c) => c.every((x) => x === 0)), 'b→a was handed only zeros');
+      assert.deepStrictEqual(noTranslation(seen), []);
+      await playMic(room, 'a#dev1', speechFrames(100)); // the same watch, on speech the gate let through
+    });
+    assert.deepStrictEqual(noTranslation(lines), ['FATAL interpreter: no translation for 1 s of speech in r-mute-zeros ru→de']);
+  } finally {
+    await interpreter.stopInterpreter('r-mute-zeros');
+  }
+});
+
+test('each direction keeps its own count', async () => {
+  const { rtc, made, deps } = setup({ noTranslationFatalMs: 1000 });
+  // a's microphone carries positive samples, b's negative: each gate hears its own owner.
+  deps.embed = { embedPcm: async (window) => print(window[0] > 0 ? 0 : 1) };
+  await interpreter.startInterpreter({ sessionId: 's26', roomName: 'r-mute-lanes', participants: people() }, deps);
+  try {
+    const room = rtc.rooms[0];
+    const toA = made.find((e) => e.opts.targetLang === 'ru');
+    const lines = await capture(async (seen) => {
+      await playMic(room, 'a#dev1', speechFrames(60));
+      await playMic(room, 'b#dev1', speechFrames(60, -3000));
+      assert.ok(toA.sent.length === 6 && toA.sent.every((c) => c[0] === -3000), "b's own speech went through");
+      assert.deepStrictEqual(noTranslation(seen), [], 'neither direction alone has had a second of speech');
+      toA.opts.onAudio(new Int16Array(480).fill(5)); // b→a speaks: only its own count starts over
+      await playMic(room, 'a#dev1', speechFrames(60));
+      await playMic(room, 'b#dev1', speechFrames(60, -3000));
+    });
+    assert.deepStrictEqual(noTranslation(lines), ['FATAL interpreter: no translation for 1 s of speech in r-mute-lanes ru→de']);
+  } finally {
+    await interpreter.stopInterpreter('r-mute-lanes');
   }
 });
 
```

Run: `cd /Users/dmitry/taler-id/.worktrees/interpreter/livekit-agent && npm test 2>&1 | grep -E "^ℹ (pass|fail)"`
Expected: `ℹ fail 6` — падают только новые и изменённые тесты этой задачи.

- [ ] **Step 2: Код**

Патч к `livekit-agent/interpreter.js`:

```diff
--- a/livekit-agent/interpreter.js
+++ b/livekit-agent/interpreter.js
@@ -106,6 +106,11 @@
     // Node runs a timer of 0, a negative value or more than 2^31-1 ms after
     // 1 ms: every conversation would end right after it started.
     presenceGraceMs: clamp(num(env.INTERPRETER_PRESENCE_GRACE_MS, 60_000), 10_000, 600_000),
+    // Speech that has gone this long without a translation is logged as FATAL.
+    // Below ~15 s one long phrase and the wait for its rendering would trip
+    // it; past ten minutes a mute direction would go unreported for most of a
+    // conversation the host is paying for.
+    noTranslationFatalMs: clamp(num(env.INTERPRETER_NO_TRANSLATION_FATAL_MS, 60_000), 15_000, 600_000),
     connectTimeoutMs: CONNECT_TIMEOUT_MS,
     disconnectTimeoutMs: DISCONNECT_TIMEOUT_MS,
     backendUrl: env.BACKEND_URL || null,
@@ -309,6 +314,7 @@
     listening: null,
     engine: null,
     gate: null,
+    untranslatedMs: 0, // speech let through since this direction last produced anything
   };
   try {
     await room.localParticipant.publishTrack(
@@ -332,6 +338,7 @@
         noiseReduction: cfg.noiseReduction,
         onAudio: (int16) => {
           if (session.stopping) return;
+          lane.untranslatedMs = 0;
           applyGain(int16, cfg.gain);
           for (let i = 0; i < int16.length; i += FRAME_SAMPLES) {
             // slice, not subarray: AudioFrame hands data.buffer to the native
@@ -341,7 +348,10 @@
             out.push(new rtc.AudioFrame(frame, SAMPLE_RATE, 1, frame.length));
           }
         },
-        onTranslationText: (text, final) => sendTo(session, d.listener, messages.caption('translation', d.speaker, text, final)),
+        onTranslationText: (text, final) => {
+          lane.untranslatedMs = 0;
+          sendTo(session, d.listener, messages.caption('translation', d.speaker, text, final));
+        },
         onSourceText: (text, final) => sendTo(session, d.speaker, messages.caption('source', d.speaker, text, final)),
         ...handlers,
       }),
@@ -362,7 +372,10 @@
         const vector = await session.embed.embedPcm(window, SAMPLE_RATE);
         return { own: cosine(vector, d.ownEmbedding), other: cosine(vector, d.otherEmbedding) };
       },
-      onOutput: (chunk) => lane.engine.sendAudio(chunk),
+      onOutput: (chunk) => {
+        noteUntranslated(session, lane, chunk);
+        lane.engine.sendAudio(chunk);
+      },
       onSpeaking: (on) => broadcast(session, messages.speaking(d.speaker, on)),
       onDecision: (record) => {
         noteFailOpen(session, record);
@@ -487,6 +500,31 @@
     console.error(
       `FATAL interpreter: voice-embed unavailable for ${Math.round((now - session.failOpenSince) / 1000)} s in ${session.roomName}`
       + ` (${session.failOpenCount} chunks let through unchecked)`,
+    );
+  }
+}
+
+/**
+ * FATAL once a direction has been handed noTranslationFatalMs of speech and
+ * has produced neither audio nor text. OpenAI failing after the session was
+ * confirmed (quota, model errors) leaves either engine connected and mute: no
+ * close, no reconnect, nothing for the listener, while the host keeps paying.
+ * A log line, not an end: speech already in the listener's language is
+ * rightly met with silence too. One line per mute run; the next is reported
+ * after the direction has spoken again and the count has built up anew.
+ */
+function noteUntranslated(session, lane, chunk) {
+  // The gate hands on the speaker's audio or the same length of zeros (the
+  // partner, the earpiece, quiet): only the former asks for a translation.
+  if (chunk.every((sample) => sample === 0)) return;
+  const limit = session.cfg.noTranslationFatalMs;
+  const before = lane.untranslatedMs;
+  lane.untranslatedMs += (chunk.length * 1000) / SAMPLE_RATE;
+  if (before < limit && lane.untranslatedMs >= limit) {
+    const { sourceLang, targetLang } = lane.direction;
+    console.error(
+      `FATAL interpreter: no translation for ${Math.round(lane.untranslatedMs / 1000)} s of speech in ${session.roomName}`
+      + ` ${sourceLang}→${targetLang}`,
     );
   }
 }
```

- [ ] **Step 3: Проверить на обоих Node**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter/livekit-agent
npm test 2>&1 | grep -E "^ℹ (pass|fail)"
~/.nvm/versions/node/v20.20.2/bin/node --test 2>&1 | grep -E "^# (pass|fail)"
```

Ожидается: `ℹ pass 301`, `ℹ fail 0`; `# pass 301`, `# fail 0`.

- [ ] **Step 4: Коммит**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter/livekit-agent
git add interpreter.js interpreter.test.js
git commit -m "feat(interpreter): сторож — речь без перевода пишет FATAL для мониторинга" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: Фикстуры голосов для сквозного набора

Два синтезированных голоса: образцы для записи (16 кГц, больше 15 с — столько требует `POST /voice-gate/enroll`) и
фразы разговора (24 кГц). Тексты фраз — не те, что в образцах. Файлы WAV генерируются скриптом и коммитятся.

**Files:**
- Create: `fixtures/interpreter/make.sh` и генерируемые им `voice-a-enroll.wav`, `voice-b-enroll.wav`, `a-1.wav`, `b-1.wav`, `b-2.wav` (репозиторий `taler_id_tests`)

- [ ] **Step 1: Скрипт**

`fixtures/interpreter/make.sh` целиком:

```bash
#!/usr/bin/env bash
# Voices for interpreter_test.ts, synthesized on a Mac (say + afconvert).
# The WAVs are committed; rerun only to change a text, then commit the WAVs.
#
#   voice-a-enroll.wav  ru, Milena  A's voice print for POST /voice-gate/enroll
#   voice-b-enroll.wav  de, Anna    B's voice print
#                       16 kHz mono PCM16 (what the enroll route expects),
#                       at least 16 s: the route refuses under 15 s
#   a-1.wav             ru, Milena  what A says
#   b-1.wav             de, Anna    what B says
#   b-2.wav             de, Anna    B's voice the test plays quietly into A's
#                       microphone, for the leak check
#                       24 kHz mono PCM16, the interpreter's own rate
#
# The conversation is a business talk and the voice prints are a different
# text, as in real use: the print is recorded once, the talk is about
# something else.
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

render() { # <voice> <sample rate> <file stem> <text>
  say -v "$1" -o "$tmp/$3.aiff" "$4"
  afconvert -f WAVE -d "LEI16@$2" -c 1 "$tmp/$3.aiff" "$3.wav"
}

seconds() {
  afinfo "$1" | awk '/estimated duration/ { print $3 }'
}

# The test's listening windows assume phrases of about four seconds.
check_length() { # <file> <min s> <max s>
  local d
  d=$(seconds "$1")
  if ! awk -v d="$d" -v lo="$2" -v hi="$3" 'BEGIN { exit !(d >= lo && d <= hi) }'; then
    echo "$1 is $d s, expected $2..$3 s: change its text" >&2
    exit 1
  fi
  printf '%-20s %6.2f s\n' "$1" "$d"
}

render Milena 16000 voice-a-enroll "Здравствуйте, меня зовут Милена. Я записываю этот образец голоса, чтобы приложение узнавало меня в разговоре. Говорю спокойно и разборчиво, обычным голосом, как каждый день. Утром я пью кофе и читаю новости, днём работаю с документами и встречаюсь с коллегами, а по выходным езжу за город к родителям. Летом мы всей семьёй отдыхаем у моря, а зимой катаемся на лыжах."
render Anna 16000 voice-b-enroll "Guten Tag, ich heiße Anna. Ich nehme diese Stimmprobe auf, damit die Anwendung mich im Gespräch erkennt. Ich spreche ruhig und deutlich, mit meiner ganz normalen Stimme. Morgens trinke ich Kaffee und lese die Nachrichten, tagsüber arbeite ich mit Dokumenten und treffe Kollegen, und am Wochenende fahre ich aufs Land zu meinen Eltern. Im Sommer machen wir als Familie Urlaub am Meer, und im Winter fahren wir Ski."
render Milena 24000 a-1 "Мы готовы подписать договор, если вы снизите цену на пять процентов."
render Anna 24000 b-1 "Die erste Lieferung kann schon nächste Woche in Ihrem Lager sein."
render Anna 24000 b-2 "Für größere Bestellungen gewähren wir gern einen zusätzlichen Rabatt."

check_length voice-a-enroll.wav 16 40
check_length voice-b-enroll.wav 16 40
check_length a-1.wav 3 6
check_length b-1.wav 3 6
check_length b-2.wav 3 6
```

- [ ] **Step 2: Сгенерировать и проверить длительности**

```bash
cd ~/Downloads/taler_id_tests && bash fixtures/interpreter/make.sh && ls -la fixtures/interpreter/
```

Ожидается: пять файлов WAV; скрипт сам сверяет длительности (образцы больше 15 с) и печатает их.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add fixtures/interpreter/
git commit -m "test: фикстуры голосов для test:interpreter" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 19: Сквозной набор `test:interpreter`

Два тестовых аккаунта и два бота на `@livekit/rtc-node`. Токены ботам выдаёт сам бэкенд (ответы создания и
входа), поэтому ключи LiveKit набору не нужны. Проверяет ручки и их ошибки, адресность дорожек и субтитров, перевод в
обе стороны, отсутствие утечки голоса собеседника, списание с хоста, секрет отчёта агента и уборку. Образцы голоса
записывает сам и удаляет только те, что записал. Реальные сессии OpenAI — центы за прогон.

**Files:**
- Create: `interpreter_test.ts`
- Modify: `package.json` (скрипты `test:interpreter*`)

- [ ] **Step 1: Набор и скрипты**

`interpreter_test.ts` целиком:

```ts
/**
 * Taler ID — conversation with translation (face-to-face interpreter), E2E.
 *
 * Two people at one table, each on their own phone. A shows a code, B enters
 * it, and from then on each hears only the translation of the other. The
 * agent `voice-interpreter` listens to both microphones, passes on only the
 * phone owner's voice (a voice-print gate), translates it, and publishes one
 * track per listener, `interp-for-<userId>`, plus captions on the data
 * channel (topic `interp`). Two LiveKit bots stand in for the phones:
 *
 *   A = integration_test     speaks Russian, voice Milena (the host, who pays)
 *   B = integration_test_2   speaks German,  voice Anna
 *
 *   GET  /interpreter/languages                       → {enabled, languages}
 *   POST /interpreter/sessions          {lang}        → {sessionId, code, expiresAt, roomName, token, livekitWsUrl}
 *   POST /interpreter/sessions/:id/code               → {code, expiresAt}
 *   POST /interpreter/sessions/join     {code, lang}  → {sessionId, roomName, token, livekitWsUrl, partner, directions}
 *   GET  /interpreter/sessions/:id                    → {status, endReason, partner, directions, startedAt}
 *   POST /interpreter/sessions/:id/end                → {status: 'ended'}
 *
 * The bots take their LiveKit token and URL from those responses, so the
 * suite needs no LiveKit secret, and they subscribe the way the app does:
 * only to the agent's track named after themselves. Keeping B off A's live
 * microphone is not checked here: @livekit/rtc-node cannot set permissions on
 * its own tracks, so that half of the isolation is left to the app's room
 * controller test and the manual check on phones.
 *
 * Voice prints. The gate compares every chunk of speech with both people's
 * prints, so each account needs a print of the voice its bot speaks with. An
 * account without one gets the fixture's (fixtures/interpreter/make.sh), and
 * the run deletes exactly the prints it enrolled. A print that was already
 * there is kept and assumed to be the fixture voice: a run killed before its
 * cleanup leaves one behind. If it is somebody else's voice, the gate drops
 * the bot's speech and checks 11/12 fail with silence: call
 * DELETE /voice-gate/owner for that account and rerun.
 *
 * Limits this suite is built around:
 *   - entering codes is capped at 10 attempts a minute per user, so the
 *     negative join checks are split between the accounts (A makes 4, B 3):
 *     two runs within one minute both get their real join through;
 *   - the service-wide throttle allows 10 requests a second per IP, which the
 *     bot server reaches easily (see room_chat_test.ts), so requests leave at
 *     least 150 ms apart;
 *   - the host is billed by the minute from the moment B joins, and the join
 *     needs the interpreter's 2-minute reserve on A's balance, so A is topped
 *     up with the stub purchase when it holds less than twice that reserve.
 *
 * Run:
 *   npm run test:interpreter         # DEV
 *   npm run test:interpreter:prod    # TEST (aeza id.taler.tirol)
 */

import axios, { AxiosResponse } from 'axios';
import FormData from 'form-data';
import {
  AudioFrame,
  AudioSource,
  AudioStream,
  DisconnectReason,
  LocalAudioTrack,
  RemoteParticipant,
  RemoteTrackPublication,
  Room,
  RoomEvent,
  TrackKind,
  TrackPublishOptions,
  TrackSource,
} from '@livekit/rtc-node';
import { createHash, randomUUID } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const PASSWORD = 'IntegrationTest123!';

const AGENT_IDENTITY = 'voice-interpreter';
const DATA_TOPIC = 'interp';
const FIXTURES = path.join(__dirname, 'fixtures', 'interpreter');

// Audio. The phrases are recorded at the interpreter's own rate.
const SAMPLE_RATE = 24_000;
const FRAME_MS = 20;
const FRAME_SAMPLES = (SAMPLE_RATE * FRAME_MS) / 1000;
/** A received frame this loud is sound: between phrases the agent's tracks carry near-silence. */
const SOUND_RMS = 300;
/** From the start of a phrase to the first translated sound (≈3 s on the DEV bench). */
const HEAR_WITHIN_MS = 12_000;
/**
 * A translation counts as finished after this long without sound on either
 * track. The simultaneous engine renders a phrase in parts (bench report
 * 2026-11-01: two caption parts of one phrase 4 s apart), so not much shorter...
 */
const QUIET_MS = 3_000;
/** ...but a phrase never holds the run for longer than this after it ends. */
const TAIL_CAP_MS = 20_000;
const CAPTION_WAIT_MS = 10_000;
/** Sound allowed on a speaker's own track while only they talk. */
const OWN_TRACK_TOLERANCE_MS = 300;
/** The partner's voice as the other phone's microphone hears it (bench/interpreter-bench.js). */
const LEAK_GAIN = 0.15;
const LEAK_TAIL_MS = 8_000;
const LEAK_TOLERANCE_MS = 500;

// Backend and LiveKit timing.
const MIN_GAP_MS = 150;
/** The join waits for the agent to start; the backend gives that call 35 s. */
const JOIN_TIMEOUT_MS = 45_000;
const END_TIMEOUT_MS = 30_000;
const CONNECT_TIMEOUT_MS = 15_000;
const AGENT_WAIT_MS = 15_000;
/** After the subscriptions, before the first phrase, as the bench does. */
const SETTLE_MS = 3_000;
const BILLING_WAIT_MS = 25_000;
const METERING_TICK_MS = 10_000;
const DISCONNECT_WAIT_MS = 10_000;
/** Our clock against the server's, for expiresAt. */
const CLOCK_SKEW_MS = 60_000;

const CODE_RE = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true, timeout: 20_000 });
let nextRequestAt = 0;
http.interceptors.request.use(async (config) => {
  const now = Date.now();
  const at = Math.max(now, nextRequestAt);
  nextRequestAt = at + MIN_GAP_MS;
  if (at > now) await sleep(at - now);
  return config;
});

function auth(token: string) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

function sleepUntil(t: number): Promise<void> {
  return sleep(t - Date.now());
}

let failed = 0;
let passed = 0;
function check(name: string, cond: boolean, details?: unknown) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`, details === undefined ? '' : redact(details)); failed++; }
}

function info(line: string) {
  console.log(`    ${line}`);
}

/** Thrown when there is nothing left to check without a missing value — one clear line instead of a cascade. */
class PrerequisiteError extends Error {}

function requireValue<T>(name: string, v: T | undefined | null): T {
  if (v === undefined || v === null || (v as any) === '') {
    throw new PrerequisiteError(`prerequisite failed: ${name}`);
  }
  return v as T;
}

/** Bodies printed on a failed check never carry a token: the interpreter hands out LiveKit tokens. */
function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, /token/i.test(k) ? '<redacted>' : redact(v)]),
    );
  }
  return value;
}

function ok2xx(res: AxiosResponse): boolean {
  return res.status === 200 || res.status === 201;
}

function seen(res: AxiosResponse) {
  return { status: res.status, body: res.data };
}

/** Error code in a Taler ID body: a string from our own exceptions, an array from ValidationPipe. */
function hasErrorCode(data: any, code: string): boolean {
  return data?.message === code || (Array.isArray(data?.message) && data.message.includes(code));
}

function parseJson(text: unknown): any {
  if (typeof text !== 'string') return null;
  try { return JSON.parse(text); } catch { return null; }
}

function jwtPayload(jwt: unknown): any {
  if (typeof jwt !== 'string') return null;
  const part = jwt.split('.')[1];
  return part ? parseJson(Buffer.from(part, 'base64url').toString('utf8')) : null;
}

/** Whatever is wrong with a LiveKit token the backend issued: right room and person, microphone only. */
function grantProblems(token: string, roomName: string, identity: string, lang: string): string[] {
  const claims = jwtPayload(token);
  const video = claims?.video ?? {};
  const problems: string[] = [];
  if (video.room !== roomName || video.roomJoin !== true) problems.push(`room ${video.room}, roomJoin ${video.roomJoin}`);
  if (claims?.sub !== identity) problems.push(`identity ${claims?.sub}, expected ${identity}`);
  if (video.canPublish !== true || JSON.stringify(video.canPublishSources) !== '["microphone"]') {
    problems.push(`canPublish ${video.canPublish}, sources ${JSON.stringify(video.canPublishSources)}`);
  }
  if (video.canSubscribe !== true) problems.push(`canSubscribe ${video.canSubscribe}`);
  if (video.canPublishData !== false) problems.push(`canPublishData ${video.canPublishData}`);
  if (parseJson(claims?.metadata)?.lang !== lang) problems.push(`metadata ${claims?.metadata}`);
  return problems;
}

/**
 * Waits until fn returns something other than undefined, at most timeoutMs.
 * A throw inside fn is "not yet", never a reason to bring the run down.
 */
async function waitFor<T>(fn: () => Promise<T | undefined> | T | undefined, timeoutMs: number, stepMs = 250): Promise<T | undefined> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let value: T | undefined;
    try { value = await fn(); } catch { value = undefined; }
    if (value !== undefined) return value;
    if (Date.now() >= deadline) return undefined;
    await sleep(stepMs);
  }
}

/** Settles after ms whatever happens: rtc-node's connect and disconnect can hang. */
function bounded(p: Promise<unknown>, ms: number): Promise<unknown> {
  return Promise.race([p.catch(() => undefined), sleep(ms)]);
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not finish within ${ms} ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

function short(text: string, max = 100): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

// ── fixtures ───────────────────────────────────────────────────────────────

/** PCM16 mono samples of a WAV. afconvert pads the header with an FLLR chunk, so the chunks are walked. */
function readWav(file: string, sampleRate: number): Int16Array {
  const name = path.basename(file);
  if (!fs.existsSync(file)) throw new PrerequisiteError(`${name} is missing: run fixtures/interpreter/make.sh on a Mac`);
  const buf = fs.readFileSync(file);
  if (buf.toString('ascii', 0, 4) !== 'RIFF' || buf.toString('ascii', 8, 12) !== 'WAVE') {
    throw new PrerequisiteError(`${name} is not a WAV file`);
  }
  let fmt: { format: number; channels: number; rate: number; bits: number } | null = null;
  let data: Buffer | null = null;
  for (let offset = 12; offset + 8 <= buf.length;) {
    const id = buf.toString('ascii', offset, offset + 4);
    const size = buf.readUInt32LE(offset + 4);
    const body = offset + 8;
    if (id === 'fmt ' && body + 16 <= buf.length) {
      fmt = {
        format: buf.readUInt16LE(body),
        channels: buf.readUInt16LE(body + 2),
        rate: buf.readUInt32LE(body + 4),
        bits: buf.readUInt16LE(body + 14),
      };
    } else if (id === 'data') {
      data = buf.subarray(body, Math.min(body + size, buf.length));
    }
    offset = body + size + (size % 2);
  }
  if (!fmt || !data || fmt.format !== 1 || fmt.channels !== 1 || fmt.bits !== 16 || fmt.rate !== sampleRate) {
    throw new PrerequisiteError(`${name} must be PCM16 mono at ${sampleRate} Hz: rerun fixtures/interpreter/make.sh`);
  }
  const samples = new Int16Array(Math.floor(data.length / 2));
  for (let i = 0; i < samples.length; i++) samples[i] = data.readInt16LE(i * 2);
  return samples;
}

function loadFixtures() {
  for (const stem of ['voice-a-enroll', 'voice-b-enroll']) {
    // The enroll route refuses less than 15 s of 16 kHz audio.
    const seconds = readWav(path.join(FIXTURES, `${stem}.wav`), 16_000).length / 16_000;
    if (seconds < 16) throw new PrerequisiteError(`${stem}.wav is ${seconds.toFixed(1)} s, needs at least 16 s`);
  }
  return {
    a1: readWav(path.join(FIXTURES, 'a-1.wav'), SAMPLE_RATE),
    b1: readWav(path.join(FIXTURES, 'b-1.wav'), SAMPLE_RATE),
    b2: readWav(path.join(FIXTURES, 'b-2.wav'), SAMPLE_RATE),
  };
}

// ── accounts ───────────────────────────────────────────────────────────────

interface Account {
  label: 'A' | 'B';
  lang: string;
  enrollWav: string;
  token: string;
  userId: string;
  /** The LiveKit identity the backend must give this login: makeParticipantIdentity(userId, session_id). */
  identity: string;
  printBefore: { enrolled: boolean; enrolledAt?: string } | null;
  enrolledByRun: boolean;
}

async function signIn(label: 'A' | 'B', email: string, lang: string, enrollWav: string): Promise<Account> {
  const res = await http.post('/auth/login', { email, password: PASSWORD });
  if (res.status !== 200 || typeof res.data?.accessToken !== 'string') {
    throw new PrerequisiteError(`login ${label} (${email}) → ${res.status}: ${JSON.stringify(redact(res.data))}`);
  }
  const token: string = res.data.accessToken;
  const claims = jwtPayload(token);
  if (!claims?.sub) throw new PrerequisiteError(`login ${label}: no user id in the access token`);
  // The backend's makeParticipantIdentity: the person plus a short hash of the login session.
  const identity = claims.session_id
    ? `${claims.sub}#${createHash('sha256').update(String(claims.session_id)).digest('hex').slice(0, 8)}`
    : claims.sub;
  return { label, lang, enrollWav, token, userId: claims.sub, identity, printBefore: null, enrolledByRun: false };
}

/** Enrolls the fixture voice unless the account already has a print; remembers what it found. */
async function ensureVoicePrint(acct: Account): Promise<void> {
  const status = await http.get('/voice-gate/owner-status', auth(acct.token));
  if (status.status !== 200 || typeof status.data?.enrolled !== 'boolean') {
    throw new PrerequisiteError(`${acct.label}: GET /voice-gate/owner-status → ${status.status} ${JSON.stringify(status.data)}`);
  }
  acct.printBefore = { enrolled: status.data.enrolled, enrolledAt: status.data.enrolledAt };
  if (status.data.enrolled) {
    console.log(`  ${acct.label}: already has a voice print (${status.data.enrolledAt}), kept and assumed to be ${acct.enrollWav}`);
    return;
  }
  const form = new FormData();
  form.append('audio', fs.createReadStream(path.join(FIXTURES, acct.enrollWav)), {
    filename: acct.enrollWav,
    contentType: 'audio/wav',
  });
  const res = await http.post('/voice-gate/enroll', form, {
    headers: { ...form.getHeaders(), Authorization: `Bearer ${acct.token}` },
    timeout: 60_000,
  });
  if (!ok2xx(res) || res.data?.ok !== true) {
    throw new PrerequisiteError(`${acct.label}: POST /voice-gate/enroll → ${res.status} ${JSON.stringify(res.data)}`);
  }
  acct.enrolledByRun = true;
  console.log(`  ${acct.label}: enrolled ${acct.enrollWav} as its voice print (${res.data.embeddingDim} numbers, ${res.data.audioSec} s)`);
}

/** Said next to a failed hearing check: the likeliest cause is a print of another voice. */
function printHint(acct: Account): string | undefined {
  if (acct.enrolledByRun) return undefined;
  return `${acct.label} had a voice print before this run (${acct.printBefore?.enrolledAt}); if it is not ${acct.enrollWav}, `
    + `the gate drops ${acct.label}'s speech: DELETE /voice-gate/owner for ${acct.label} and rerun`;
}

interface Tx {
  id: string;
  type: string;
  amountPlanck: string;
  featureKey: string | null;
  sessionId: string | null;
  metadata: any;
}

/** The account's interpreter transactions among its latest 100; null when the call fails. */
async function interpreterTx(acct: Account): Promise<Tx[] | null> {
  const res = await http.get('/billing/transactions', auth(acct.token));
  if (res.status !== 200 || !Array.isArray(res.data)) return null;
  return (res.data as Tx[]).filter((t) => t.featureKey === 'interpreter');
}

async function balanceOf(acct: Account): Promise<bigint> {
  const res = await http.get('/billing/balance', auth(acct.token));
  if (res.status !== 200 || typeof res.data?.balancePlanck !== 'string') {
    throw new PrerequisiteError(`${acct.label}: GET /billing/balance → ${res.status} ${JSON.stringify(res.data)}`);
  }
  return BigInt(res.data.balancePlanck);
}

/** Tops A up when needed and returns the interpreter transactions each account had before the run. */
async function prepareBilling(a: Account, b: Account): Promise<{ a: Set<string>; b: Set<string> }> {
  const pricebook = await http.get('/billing/pricebook', auth(a.token));
  const row = Array.isArray(pricebook.data) ? pricebook.data.find((r: any) => r.featureKey === 'interpreter') : undefined;
  if (!row) {
    throw new PrerequisiteError(`GET /billing/pricebook has no "interpreter" row on ${BASE_URL}: migration 20261101120000_interpreter not applied?`);
  }
  // The join needs the reserve; the run then spends about a minute on top of it.
  const need = 2n * BigInt(row.minReservePlanck);
  let balance = await balanceOf(a);
  if (balance < need) {
    const buy = await http.post('/billing/purchase/starter', {}, auth(a.token));
    if (!ok2xx(buy)) throw new PrerequisiteError(`A holds ${balance} planck, needs ${need}, and the stub top-up failed: ${buy.status} ${JSON.stringify(buy.data)}`);
    balance = await balanceOf(a);
    if (balance < need) throw new PrerequisiteError(`after the top-up A holds ${balance} planck, needs ${need}: buy another package`);
    console.log(`  A: topped up with the starter package, balance ${balance} planck`);
  } else {
    console.log(`  A: balance ${balance} planck covers twice the interpreter reserve`);
  }
  const before = { a: await interpreterTx(a), b: await interpreterTx(b) };
  if (!before.a || !before.b) throw new PrerequisiteError('GET /billing/transactions failed');
  return { a: new Set(before.a.map((t) => t.id)), b: new Set(before.b.map((t) => t.id)) };
}

// ── bots ───────────────────────────────────────────────────────────────────

interface HeardFrame { t: number; rms: number; ms: number }
interface DataMessage { t: number; from: string; msg: any }
interface Played { startedAt: number; endsAt: number }
interface Clip { at: number; samples: Int16Array; gain: number }

interface Bot {
  label: string;
  /** Every frame of this bot's own interpretation track, interp-for-<me>. */
  heard: HeardFrame[];
  /** Every message on topic `interp`. */
  data: DataMessage[];
  /** Remote tracks now in the room, by sid. */
  publications: Map<string, { identity: string; name: string }>;
  /** Every track this bot subscribed to. */
  subscriptions: { identity: string; name: string }[];
  agentSeenAt: number | null;
  disconnected: { at: number; reason: string } | null;
  /** Plays a clip into the microphone from the next frame on. */
  play(samples: Int16Array, gain?: number): Played;
  close(): Promise<void>;
}

function trackNameFor(userId: string): string {
  return `interp-for-${userId}`;
}

function rms(samples: Int16Array): number {
  if (samples.length === 0) return 0;
  let sum = 0;
  for (let i = 0; i < samples.length; i++) sum += samples[i] * samples[i];
  return Math.sqrt(sum / samples.length);
}

/** Feeds a microphone in real time: the scheduled clips where they fall, digital silence elsewhere. */
function runPump(source: AudioSource, clips: Clip[], running: () => boolean): Promise<void> {
  const pump = (async () => {
    const t0 = Date.now();
    for (let n = 0; running(); n++) {
      const frameAt = t0 + n * FRAME_MS;
      const frame = new Int16Array(FRAME_SAMPLES);
      for (const c of clips) {
        const offset = Math.round(((frameAt - c.at) * SAMPLE_RATE) / 1000);
        if (offset + FRAME_SAMPLES <= 0 || offset >= c.samples.length) continue;
        for (let i = 0; i < FRAME_SAMPLES; i++) {
          const j = offset + i;
          if (j < 0 || j >= c.samples.length) continue;
          const v = frame[i] + c.samples[j] * c.gain;
          frame[i] = v > 32767 ? 32767 : v < -32768 ? -32768 : v;
        }
      }
      await source.captureFrame(new AudioFrame(frame, SAMPLE_RATE, 1, FRAME_SAMPLES));
      await sleep(t0 + (n + 1) * FRAME_MS - Date.now());
    }
  })();
  // Handled at once: a failed capture must not kill the run as an unhandled rejection before its cleanup.
  pump.catch(() => undefined);
  return pump;
}

/**
 * Joins the room as one phone: publishes a microphone and listens only to the
 * interpreter's track named after its owner, as the app does.
 */
async function connectBot(acct: Account, url: string, token: string): Promise<Bot> {
  const room = new Room();
  const mine = trackNameFor(acct.userId);
  const clips: Clip[] = [];
  // An AudioStream from rtc-node 0.13 does not end when its track goes away: cancel it explicitly.
  const cancels: (() => void)[] = [];
  let running = true;
  let pump: Promise<void> = Promise.resolve();

  const bot: Bot = {
    label: acct.label,
    heard: [],
    data: [],
    publications: new Map(),
    subscriptions: [],
    agentSeenAt: null,
    disconnected: null,
    play(samples, gain = 1) {
      const startedAt = Date.now() + FRAME_MS;
      clips.push({ at: startedAt, samples, gain });
      return { startedAt, endsAt: startedAt + (samples.length / SAMPLE_RATE) * 1000 };
    },
    async close() {
      running = false;
      for (const cancel of cancels) cancel();
      await bounded(pump, 2000);
      await bounded(room.disconnect(), 3000);
    },
  };

  const noteAgent = (identity: string) => {
    if (identity === AGENT_IDENTITY && bot.agentSeenAt === null) bot.agentSeenAt = Date.now();
  };
  const consider = (pub: RemoteTrackPublication, participant: RemoteParticipant) => {
    noteAgent(participant.identity);
    if (pub.sid) bot.publications.set(pub.sid, { identity: participant.identity, name: pub.name ?? '' });
    if (participant.identity === AGENT_IDENTITY && pub.name === mine && !pub.subscribed) pub.setSubscribed(true);
  };

  room.on(RoomEvent.ParticipantConnected, (p) => noteAgent(p.identity));
  room.on(RoomEvent.TrackPublished, consider);
  room.on(RoomEvent.TrackUnpublished, (pub) => {
    if (pub.sid) bot.publications.delete(pub.sid);
  });
  room.on(RoomEvent.TrackSubscribed, (track, pub, participant) => {
    bot.subscriptions.push({ identity: participant.identity, name: pub.name ?? '' });
    if (participant.identity !== AGENT_IDENTITY || pub.name !== mine || track.kind !== TrackKind.KIND_AUDIO) return;
    const reader = new AudioStream(track, SAMPLE_RATE, 1).getReader();
    cancels.push(() => { reader.cancel().catch(() => undefined); });
    (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        bot.heard.push({ t: Date.now(), rms: rms(value.data), ms: (value.samplesPerChannel / value.sampleRate) * 1000 });
      }
    })().catch(() => undefined);
  });
  room.on(RoomEvent.DataReceived, (payload, participant, _kind, topic) => {
    if (topic !== DATA_TOPIC) return;
    const msg = parseJson(Buffer.from(payload).toString('utf8'));
    if (msg) bot.data.push({ t: Date.now(), from: participant?.identity ?? '', msg });
  });
  room.on(RoomEvent.Disconnected, (reason) => {
    if (!bot.disconnected) bot.disconnected = { at: Date.now(), reason: DisconnectReason[reason] ?? String(reason) };
  });

  try {
    await withTimeout(room.connect(url, token, { autoSubscribe: false, dynacast: false }), CONNECT_TIMEOUT_MS, 'LiveKit connect');
    // Whoever was in the room before us: events only report what comes after.
    for (const p of room.remoteParticipants.values()) {
      noteAgent(p.identity);
      for (const pub of p.trackPublications.values()) consider(pub, p);
    }
    const source = new AudioSource(SAMPLE_RATE, 1);
    const options = new TrackPublishOptions();
    options.source = TrackSource.SOURCE_MICROPHONE;
    await room.localParticipant!.publishTrack(LocalAudioTrack.createAudioTrack(`mic-${acct.label}`, source), options);
    pump = runPump(source, clips, () => running);
  } catch (e) {
    // Joined but not publishing: leave rather than stay in somebody's room.
    running = false;
    await bounded(room.disconnect(), 3000);
    throw new PrerequisiteError(`${acct.label}'s bot could not join ${url}: ${(e as Error).message}`);
  }
  return bot;
}

function firstSoundAt(bot: Bot, from: number): number | undefined {
  return bot.heard.find((f) => f.t >= from && f.rms >= SOUND_RMS)?.t;
}

function soundMs(bot: Bot, from: number, to: number): number {
  let ms = 0;
  for (const f of bot.heard) if (f.t >= from && f.t < to && f.rms >= SOUND_RMS) ms += f.ms;
  return ms;
}

function lastSoundAt(bot: Bot): number {
  for (let i = bot.heard.length - 1; i >= 0; i--) if (bot.heard[i].rms >= SOUND_RMS) return bot.heard[i].t;
  return 0;
}

/** Waits until neither bot has heard anything for QUIET_MS, counting from `since` at the earliest. */
async function settle(bots: Bot[], since: number): Promise<void> {
  const deadline = Date.now() + TAIL_CAP_MS;
  while (Date.now() < deadline) {
    if (Date.now() - Math.max(since, ...bots.map(lastSoundAt)) >= QUIET_MS) return;
    await sleep(200);
  }
}

function agentTrackNames(bot: Bot): string[] {
  return [...bot.publications.values()].filter((p) => p.identity === AGENT_IDENTITY).map((p) => p.name).sort();
}

function onlyOwnTrack(bot: Bot, userId: string): boolean {
  return bot.subscriptions.length > 0
    && bot.subscriptions.every((s) => s.identity === AGENT_IDENTITY && s.name === trackNameFor(userId));
}

/** One role's captions about one speaker since `from`, deltas joined in order. */
function captionText(bot: Bot, role: 'translation' | 'source', speaker: string, from: number): string {
  return bot.data
    .filter((d) => d.t >= from && d.msg.type === 'caption' && d.msg.role === role && d.msg.speaker === speaker)
    .map((d) => String(d.msg.text ?? ''))
    .join('');
}

type Script = 'cyrillic' | 'latin' | 'mixed' | 'too short';

function scriptOf(text: string): Script {
  const cyrillic = (text.match(/\p{Script=Cyrillic}/gu) ?? []).length;
  const latin = (text.match(/\p{Script=Latin}/gu) ?? []).length;
  const letters = cyrillic + latin;
  if (letters < 8) return 'too short';
  if (cyrillic >= 0.9 * letters) return 'cyrillic';
  if (latin >= 0.9 * letters) return 'latin';
  return 'mixed';
}

/** Waits for a caption to grow into enough letters of the expected script. */
async function waitForCaption(bot: Bot, role: 'translation' | 'source', speaker: string, from: number, script: Script) {
  const ok = await waitFor(() => (scriptOf(captionText(bot, role, speaker, from)) === script ? true : undefined), CAPTION_WAIT_MS, 200);
  return { ok: ok === true, text: captionText(bot, role, speaker, from) };
}

function gotSpeaking(bot: Bot, speaker: string, from: number): boolean {
  return bot.data.some((d) => d.t >= from && d.msg.type === 'speaking' && d.msg.speaker === speaker && d.msg.on === true);
}

/** Captions this bot got that were not meant for it: only the partner's translation and its own source text are. */
function misaddressed(bot: Bot, self: Account, partner: Account): DataMessage[] {
  return bot.data.filter((d) => d.msg.type === 'caption' && (
    d.from !== AGENT_IDENTITY
    || !((d.msg.role === 'translation' && d.msg.speaker === partner.userId) || (d.msg.role === 'source' && d.msg.speaker === self.userId))
  ));
}

// ── the test ───────────────────────────────────────────────────────────────

async function main() {
  console.log(`\nInterpreter E2E → ${BASE_URL}\n`);
  const clips = loadFixtures();
  const A = await signIn('A', 'integration_test@taler-test.com', 'ru', 'voice-a-enroll.wav');
  const B = await signIn('B', 'integration_test_2@taler-test.com', 'de', 'voice-b-enroll.wav');
  console.log('Logged in as A (integration_test, Russian) and B (integration_test_2, German)');

  const accounts = [A, B];
  const bots: Bot[] = [];
  // Every conversation a create answered with, so the cleanup can end what the run left open.
  const openSessions = new Set<string>();
  const noteSession = (res: AxiosResponse) => {
    if (ok2xx(res) && typeof res.data?.sessionId === 'string') openSessions.add(res.data.sessionId);
  };
  const join = (acct: Account, code: string, lang: string) =>
    http.post('/interpreter/sessions/join', { code, lang }, { ...auth(acct.token), timeout: JOIN_TIMEOUT_MS });
  const view = (acct: Account, id: string) => http.get(`/interpreter/sessions/${id}`, auth(acct.token));
  const simultaneousBothWays = (data: any) =>
    data?.directions?.toMe === 'simultaneous' && data?.directions?.fromMe === 'simultaneous';

  try {
    // ── Setup: voice prints, money, the transactions to compare with ─────
    await ensureVoicePrint(A);
    await ensureVoicePrint(B);
    const txBefore = await prepareBilling(A, B);

    // ── 1. Languages ─────────────────────────────────────────────────────
    const langs = await http.get('/interpreter/languages', auth(A.token));
    check('1. GET /interpreter/languages → 200', langs.status === 200, seen(langs));
    if (langs.status === 404) throw new PrerequisiteError(`no /interpreter on ${BASE_URL}: this backend build predates the interpreter`);
    check('1b. enabled === true', langs.data?.enabled === true, langs.data?.enabled);
    if (langs.data?.enabled !== true) {
      throw new PrerequisiteError(`the interpreter is switched off on ${BASE_URL}: INTERPRETER_ENABLED is not "true" in the backend .env`);
    }
    const list: any[] = Array.isArray(langs.data?.languages) ? langs.data.languages : [];
    const odd = list.filter((l) => !/^[a-z]{2,3}$/.test(l?.code ?? '') || typeof l?.name !== 'string' || !l.name);
    check('1c. 81 languages, each a bare ISO code (no region) with a name, no repeats',
      list.length === 81 && odd.length === 0 && new Set(list.map((l) => l.code)).size === 81,
      { count: list.length, odd: odd.slice(0, 5) });
    check('1d. Russian and German are among them',
      list.some((l) => l.code === 'ru' && l.name === 'Russian') && list.some((l) => l.code === 'de' && l.name === 'German'),
      list.filter((l) => l.code === 'ru' || l.code === 'de'));

    // ── 2. A language the agent does not speak ───────────────────────────
    const unknownLang = await http.post('/interpreter/sessions', { lang: 'xx' }, auth(A.token));
    noteSession(unknownLang);
    check('2. create with "xx" → 400 unsupported_language',
      unknownLang.status === 400 && hasErrorCode(unknownLang.data, 'unsupported_language'), seen(unknownLang));
    const regional = await http.post('/interpreter/sessions', { lang: 'pt-BR' }, auth(A.token));
    noteSession(regional);
    check('2b. create with a regional code "pt-BR" → 400 unsupported_language',
      regional.status === 400 && hasErrorCode(regional.data, 'unsupported_language'), seen(regional));

    // ── 3. A starts and waits in the room ────────────────────────────────
    const created = await http.post('/interpreter/sessions', { lang: A.lang }, auth(A.token));
    noteSession(created);
    check('3. A starts a conversation in Russian → 200/201', ok2xx(created), seen(created));
    if (!ok2xx(created)) {
      const leftOpen = created.data?.message === 'already_in_session'
        ? ' (an earlier run left a conversation open; it ends by itself within about a minute, partner_left, then rerun)'
        : '';
      throw new PrerequisiteError(`A could not start a conversation (see 3), nothing left to test${leftOpen}`);
    }
    const sessionId: string = requireValue('sessionId (POST /interpreter/sessions)', created.data?.sessionId);
    const firstCode: string = requireValue('code (POST /interpreter/sessions)', created.data?.code);
    const roomName: string = requireValue('roomName (POST /interpreter/sessions)', created.data?.roomName);
    const hostToken: string = requireValue('token (POST /interpreter/sessions)', created.data?.token);
    const hostUrl: string = requireValue('livekitWsUrl (POST /interpreter/sessions)', created.data?.livekitWsUrl);
    const validFor = Date.parse(created.data?.expiresAt) - Date.now();
    check('3b. shape: sessionId uuid, 8-character code without look-alike letters, expiresAt ~5 min ahead, roomName interp-<uuid>, ws(s) URL',
      UUID_RE.test(sessionId) && CODE_RE.test(firstCode)
        && validFor > 5 * 60_000 - CLOCK_SKEW_MS && validFor < 5 * 60_000 + CLOCK_SKEW_MS
        && /^interp-[0-9a-f-]{36}$/.test(roomName) && /^wss?:\/\//.test(hostUrl),
      { sessionId, code: firstCode, expiresAt: created.data?.expiresAt, roomName, livekitWsUrl: hostUrl });
    const hostGrant = grantProblems(hostToken, roomName, A.identity, A.lang);
    check('3c. A\'s LiveKit token: this room, identity <A>#<device>, metadata {lang:"ru"}, microphone only, may subscribe, no data',
      hostGrant.length === 0, hostGrant);
    // From here on A sits in the room and waits for B, as the app does.
    const botA = await connectBot(A, hostUrl, hostToken);
    bots.push(botA);
    console.log('  A\'s bot is in the room, waiting for B');

    // ── 4-6. Codes that must not let anybody in ──────────────────────────
    const own = await join(A, firstCode, B.lang);
    check('4. A enters its own code → 409 own_code', own.status === 409 && hasErrorCode(own.data, 'own_code'), seen(own));
    const sameLang = await join(B, firstCode, A.lang);
    check('5. B enters it with A\'s language → 400 same_language',
      sameLang.status === 400 && hasErrorCode(sameLang.data, 'same_language'), seen(sameLang));
    const unknownCode = await join(A, 'ZZZZ2222', B.lang);
    check('6. a well-formed code nobody holds → 404 code_not_found',
      unknownCode.status === 404 && hasErrorCode(unknownCode.data, 'code_not_found'), seen(unknownCode));
    const malformed = await join(A, 'not a code!', B.lang);
    check('6b. a malformed code → 404 code_not_found',
      malformed.status === 404 && hasErrorCode(malformed.data, 'code_not_found'), seen(malformed));

    // ── 7. A new code replaces the old one ───────────────────────────────
    const renewed = await http.post(`/interpreter/sessions/${sessionId}/code`, {}, auth(A.token));
    const newCode = renewed.data?.code;
    const newValidFor = Date.parse(renewed.data?.expiresAt) - Date.now();
    check('7. A asks for a new code → 200/201, a different code, valid ~5 min',
      ok2xx(renewed) && typeof newCode === 'string' && CODE_RE.test(newCode) && newCode !== firstCode
        && newValidFor > 5 * 60_000 - CLOCK_SKEW_MS && newValidFor < 5 * 60_000 + CLOCK_SKEW_MS,
      seen(renewed));
    const notHost = await http.post(`/interpreter/sessions/${sessionId}/code`, {}, auth(B.token));
    check('7b. B, not the host, asks for a new code → 404 session_not_found',
      notHost.status === 404 && hasErrorCode(notHost.data, 'session_not_found'), seen(notHost));
    // Entered by A on purpose: while the old code still worked, A would get own_code, not a seat.
    const oldCode = await join(A, firstCode, B.lang);
    check('7c. the old code is dead: entering it → 404 code_not_found (own_code would mean it still works)',
      oldCode.status === 404 && hasErrorCode(oldCode.data, 'code_not_found'), seen(oldCode));
    const code: string = ok2xx(renewed) && typeof newCode === 'string' ? newCode : firstCode;

    // ── 8. B joins ───────────────────────────────────────────────────────
    const joinSentAt = Date.now();
    const joined = await join(B, code, B.lang);
    check('8. B enters the code in German → 200/201', ok2xx(joined), seen(joined));
    if (!ok2xx(joined)) {
      const agentDown = joined.data?.message === 'interpreter_unavailable'
        ? ' (the agent did not start: livekit-ai-agent unreachable via AI_AGENT_URL, INTERPRETER_SHARED_SECRET differs, or no OPENAI_API_KEY on the agent)'
        : '';
      throw new PrerequisiteError(`B could not join (see 8), nothing left to test${agentDown}`);
    }
    const guestToken: string = requireValue('token (POST /interpreter/sessions/join)', joined.data?.token);
    const guestUrl: string = requireValue('livekitWsUrl (POST /interpreter/sessions/join)', joined.data?.livekitWsUrl);
    check('8b. the same conversation and room as A\'s',
      joined.data?.sessionId === sessionId && joined.data?.roomName === roomName,
      { sessionId: joined.data?.sessionId, roomName: joined.data?.roomName });
    const guestGrant = grantProblems(guestToken, roomName, B.identity, B.lang);
    check('8c. B\'s LiveKit token: this room, identity <B>#<device>, metadata {lang:"de"}, microphone only, may subscribe, no data',
      guestGrant.length === 0, guestGrant);
    const hostAsPartner = joined.data?.partner;
    const nullableString = (o: any, key: string) => !!o && key in o && (o[key] === null || typeof o[key] === 'string');
    check('8d. partner is A: speaks ru, firstName and avatarUrl present (string or null)',
      hostAsPartner?.lang === A.lang && nullableString(hostAsPartner, 'firstName') && nullableString(hostAsPartner, 'avatarUrl'),
      hostAsPartner);
    check('8e. directions: ru↔de is simultaneous both ways', simultaneousBothWays(joined.data), joined.data?.directions);
    check('8f. the interpreter stayed out of the room while A was waiting',
      botA.agentSeenAt === null || botA.agentSeenAt >= joinSentAt, { agentSeenAt: botA.agentSeenAt, joinSentAt });

    // ── 9. Both see the conversation; what must not work while it runs ──
    const hostView = await view(A, sessionId);
    check('9. GET as A → active, partner speaks de, simultaneous both ways, startedAt set, no endReason',
      hostView.status === 200 && hostView.data?.status === 'active' && !hostView.data?.endReason
        && hostView.data?.partner?.lang === B.lang && simultaneousBothWays(hostView.data)
        && !Number.isNaN(Date.parse(hostView.data?.startedAt)),
      seen(hostView));
    const guestView = await view(B, sessionId);
    check('9b. GET as B → active, partner speaks ru',
      guestView.status === 200 && guestView.data?.status === 'active' && guestView.data?.partner?.lang === A.lang,
      seen(guestView));
    const stranger = await view(A, randomUUID());
    check('9c. GET of a conversation A is not in → 404 session_not_found',
      stranger.status === 404 && hasErrorCode(stranger.data, 'session_not_found'), seen(stranger));
    const reused = await join(B, code, B.lang);
    check('9d. the code is single-use: entering it again → 404 code_not_found',
      reused.status === 404 && hasErrorCode(reused.data, 'code_not_found'), seen(reused));
    const another = await http.post('/interpreter/sessions', { lang: A.lang }, auth(A.token));
    noteSession(another);
    check('9e. A starts another conversation meanwhile → 409 already_in_session',
      another.status === 409 && hasErrorCode(another.data, 'already_in_session'), seen(another));
    const lateCode = await http.post(`/interpreter/sessions/${sessionId}/code`, {}, auth(A.token));
    check('9f. a new code for a conversation under way → 409 not_waiting',
      lateCode.status === 409 && hasErrorCode(lateCode.data, 'not_waiting'), seen(lateCode));

    // ── 10. B's phone joins; each listens only to its own interpretation ─
    const botB = await connectBot(B, guestUrl, guestToken);
    bots.push(botB);
    const expectedTracks = [trackNameFor(A.userId), trackNameFor(B.userId)].sort();
    const agentReady = await waitFor(
      () => (JSON.stringify(agentTrackNames(botA)) === JSON.stringify(expectedTracks)
        && onlyOwnTrack(botA, A.userId) && onlyOwnTrack(botB, B.userId) ? true : undefined),
      AGENT_WAIT_MS,
    );
    check('10. voice-interpreter is in the room publishing exactly interp-for-<A> and interp-for-<B>',
      JSON.stringify(agentTrackNames(botA)) === JSON.stringify(expectedTracks), { seenByA: agentTrackNames(botA), expectedTracks });
    check('10b. A\'s bot receives interp-for-<A> from voice-interpreter, and nothing else', onlyOwnTrack(botA, A.userId), botA.subscriptions);
    check('10c. B\'s bot receives interp-for-<B> from voice-interpreter, and nothing else', onlyOwnTrack(botB, B.userId), botB.subscriptions);
    if (!agentReady) throw new PrerequisiteError('the bots never got their interpretation tracks: nothing to listen to (see 10-10c)');
    await sleep(SETTLE_MS);

    // ── 11. A speaks Russian: B hears German ─────────────────────────────
    const a1 = botA.play(clips.a1);
    const heardByB = await waitFor(() => firstSoundAt(botB, a1.startedAt), a1.startedAt + HEAR_WITHIN_MS - Date.now(), 100);
    check('11. A says a Russian phrase → B hears the translation within 12 s', heardByB !== undefined,
      printHint(A) ?? 'no sound on interp-for-<B>');
    if (heardByB !== undefined) info(`B heard it ${heardByB - a1.startedAt} ms after A began`);
    await sleepUntil(a1.endsAt);
    await settle([botA, botB], a1.endsAt);
    const toB = await waitForCaption(botB, 'translation', A.userId, a1.startedAt, 'latin');
    check('11b. B gets A\'s words as a translation caption in Latin script', toB.ok, toB.text);
    info(`B reads: «${short(toB.text)}»`);
    const ownA = await waitForCaption(botA, 'source', A.userId, a1.startedAt, 'cyrillic');
    check('11c. A gets its own words back as a source caption in Cyrillic', ownA.ok, ownA.text);
    info(`A reads its own words: «${short(ownA.text)}»`);
    const echoA = soundMs(botA, a1.startedAt, Date.now());
    check('11d. A\'s own track stays silent while only A talks', echoA <= OWN_TRACK_TOLERANCE_MS, { soundMs: echoA });
    check('11e. both phones get the "A is speaking" signal',
      gotSpeaking(botA, A.userId, a1.startedAt) && gotSpeaking(botB, A.userId, a1.startedAt),
      { toA: gotSpeaking(botA, A.userId, a1.startedAt), toB: gotSpeaking(botB, A.userId, a1.startedAt) });

    // ── 12. B speaks German: A hears Russian ─────────────────────────────
    const b1 = botB.play(clips.b1);
    const heardByA = await waitFor(() => firstSoundAt(botA, b1.startedAt), b1.startedAt + HEAR_WITHIN_MS - Date.now(), 100);
    check('12. B says a German phrase → A hears the translation within 12 s', heardByA !== undefined,
      printHint(B) ?? 'no sound on interp-for-<A>');
    if (heardByA !== undefined) info(`A heard it ${heardByA - b1.startedAt} ms after B began`);
    await sleepUntil(b1.endsAt);
    await settle([botA, botB], b1.endsAt);
    const toA = await waitForCaption(botA, 'translation', B.userId, b1.startedAt, 'cyrillic');
    check('12b. A gets B\'s words as a translation caption in Cyrillic', toA.ok, toA.text);
    info(`A reads: «${short(toA.text)}»`);
    const ownB = await waitForCaption(botB, 'source', B.userId, b1.startedAt, 'latin');
    check('12c. B gets its own words back as a source caption in Latin script', ownB.ok, ownB.text);
    const echoB = soundMs(botB, b1.startedAt, Date.now());
    check('12d. B\'s own track stays silent while only B talks', echoB <= OWN_TRACK_TOLERANCE_MS, { soundMs: echoB });
    const strayA = misaddressed(botA, A, B);
    const strayB = misaddressed(botB, B, A);
    check('12e. captions are addressed: each phone got only the partner\'s translation and its own source text, from voice-interpreter',
      strayA.length === 0 && strayB.length === 0, { toA: strayA.slice(0, 3), toB: strayB.slice(0, 3) });

    // ── 13. B's voice reaches A's microphone; nobody hears it back ──────
    await settle([botA, botB], 0);
    const leak = botA.play(clips.b2, LEAK_GAIN);
    await sleepUntil(leak.endsAt + LEAK_TAIL_MS);
    const leakedMs = soundMs(botB, leak.startedAt, Date.now());
    check(`13. B's German played into A's microphone at ×${LEAK_GAIN} while B is silent → B hears (almost) nothing`,
      leakedMs <= LEAK_TOLERANCE_MS, { soundMs: leakedMs, toleranceMs: LEAK_TOLERANCE_MS });
    const leakedText = captionText(botB, 'translation', A.userId, leak.startedAt);
    check('13b. ...and no translation caption for it', leakedText === '', leakedText);
    // Not a check: with the gate open the model's silence on German into
    // German still keeps B's earpiece quiet, and the gate fails open by design
    // when the embed service is slow. Worth seeing, though.
    info(gotSpeaking(botB, A.userId, leak.startedAt)
      ? 'the voice gate on A\'s microphone opened for the leak (fail-open, or the margin let it pass)'
      : 'the voice gate on A\'s microphone stayed closed for the leak');

    // ── 14. The host pays ────────────────────────────────────────────────
    const charged = await waitFor(async () => {
      const fresh = (await interpreterTx(A))?.filter((t) => !txBefore.a.has(t.id)) ?? [];
      return fresh.length > 0 ? fresh : undefined;
    }, BILLING_WAIT_MS, 2500);
    check('14. A is charged: SPEND transactions with featureKey "interpreter" since the join, each above zero',
      !!charged && charged.every((t) => t.type === 'SPEND' && /^\d+$/.test(t.amountPlanck) && BigInt(t.amountPlanck) > 0n),
      charged ?? 'no interpreter transaction since the join');
    const billingIds = [...new Set((charged ?? []).map((t) => t.sessionId))];
    const billingSessionId = billingIds.length === 1 && billingIds[0] ? billingIds[0] : null;
    check('14b. ...all on one billing session', !!billingSessionId, billingIds);
    if (charged) {
      const planck = charged.reduce((sum, t) => sum + BigInt(t.amountPlanck), 0n);
      const minutes = charged.reduce((sum, t) => sum + Number(t.metadata?.unitsUsed ?? 0), 0);
      info(`A paid ${planck} planck for ${minutes.toFixed(2)} min so far, in ${charged.length} metering ticks`);
    }
    const guestTx = await interpreterTx(B);
    const guestCharged = guestTx?.filter((t) => !txBefore.b.has(t.id));
    check('14c. B, the guest, is not charged', !!guestCharged && guestCharged.length === 0,
      guestCharged ?? 'GET /billing/transactions failed for B');

    // ── 15. The agent's callback is closed to everybody else ─────────────
    // Run while the conversation is active: a callback that got through
    // would end it as partner_left, which 15c and 16b would both show.
    const callback = `/interpreter/internal/sessions/${sessionId}/agent-ended`;
    const withLogin = await http.post(callback, { reason: 'partner_left' }, auth(A.token));
    check('15. agent-ended with a user\'s login token but no x-interpreter-secret → 401', withLogin.status === 401, seen(withLogin));
    const wrongSecret = await http.post(callback, { reason: 'partner_left' }, { headers: { 'x-interpreter-secret': 'e2e-not-the-secret' } });
    check('15b. agent-ended with a wrong secret → 401', wrongSecret.status === 401, seen(wrongSecret));
    const stillOn = await view(A, sessionId);
    check('15c. the conversation is still active after both', stillOn.data?.status === 'active', seen(stillOn));

    // ── 16. A hangs up ───────────────────────────────────────────────────
    const ended = await http.post(`/interpreter/sessions/${sessionId}/end`, {}, { ...auth(A.token), timeout: END_TIMEOUT_MS });
    const endedAt = Date.now();
    check('16. A ends it → 200/201 {status:"ended"}', ok2xx(ended) && ended.data?.status === 'ended', seen(ended));
    if (ok2xx(ended)) openSessions.delete(sessionId);
    const hostAfter = await view(A, sessionId);
    check('16b. GET as A → ended, endReason hangup',
      hostAfter.data?.status === 'ended' && hostAfter.data?.endReason === 'hangup', seen(hostAfter));
    const guestAfter = await view(B, sessionId);
    check('16c. GET as B → ended, endReason hangup',
      guestAfter.data?.status === 'ended' && guestAfter.data?.endReason === 'hangup', seen(guestAfter));
    const dropped = await waitFor(() => (botA.disconnected && botB.disconnected ? true : undefined), DISCONNECT_WAIT_MS, 200);
    check('16d. both bots are dropped within 10 s: the room is deleted', dropped === true,
      { A: botA.disconnected, B: botB.disconnected });
    for (const bot of [botA, botB]) {
      if (bot.disconnected) info(`${bot.label}'s bot dropped ${bot.disconnected.at - endedAt} ms after the end (${bot.disconnected.reason})`);
    }
    const again = await http.post(`/interpreter/sessions/${sessionId}/end`, {}, { ...auth(A.token), timeout: END_TIMEOUT_MS });
    const afterAgain = await view(A, sessionId);
    check('16e. ending it again → still {status:"ended"}, and the reason stays hangup',
      ok2xx(again) && again.data?.status === 'ended' && afterAgain.data?.endReason === 'hangup',
      { again: seen(again), endReason: afterAgain.data?.endReason });
    const endStranger = await http.post(`/interpreter/sessions/${randomUUID()}/end`, {}, auth(A.token));
    check('16f. ending a conversation A is not in → 404 session_not_found',
      endStranger.status === 404 && hasErrorCode(endStranger.data, 'session_not_found'), seen(endStranger));

    // ── 17. The meter stops with the conversation ────────────────────────
    if (!billingSessionId) {
      check('17. no debits on the billing session after the end', false, 'no billing session to watch (see 14b)');
    } else {
      // Let a metering tick that was already under way at the end land first.
      await sleepUntil(endedAt + 3000);
      const atEnd = await interpreterTx(A);
      const counted = new Set((atEnd ?? []).filter((t) => t.sessionId === billingSessionId).map((t) => t.id));
      await sleep(METERING_TICK_MS + 2000);
      const later = await interpreterTx(A);
      const extra = later?.filter((t) => t.sessionId === billingSessionId && !counted.has(t.id));
      check('17. no debits on the billing session in the 12 s after the end (a metering tick is 10 s)',
        !!atEnd && !!extra && extra.length === 0,
        atEnd && extra ? extra : 'GET /billing/transactions failed');
    }
  } catch (e) {
    if (e instanceof PrerequisiteError) {
      console.log(`  ✗ ${e.message}`);
      failed++;
    } else {
      throw e;
    }
  } finally {
    // Each step on its own: one failure must not skip the rest. The end
    // comes first: it closes the host's billing and deletes the room.
    for (const id of openSessions) {
      try {
        const r = await http.post(`/interpreter/sessions/${id}/end`, {}, { ...auth(A.token), timeout: END_TIMEOUT_MS });
        console.log(`  cleanup: end conversation ${id} → ${r.status}`);
      } catch (e) {
        console.log(`  cleanup: end conversation ${id} → error: ${(e as Error).message}`);
      }
    }
    for (const bot of bots) {
      try {
        await bot.close();
      } catch (e) {
        console.log(`  cleanup: ${bot.label}'s bot → error: ${(e as Error).message}`);
      }
    }
    for (const acct of accounts) {
      if (!acct.enrolledByRun) continue;
      try {
        const del = await http.delete('/voice-gate/owner', auth(acct.token));
        const status = await http.get('/voice-gate/owner-status', auth(acct.token));
        check(`cleanup. ${acct.label}: the voice print this run enrolled is deleted again`,
          del.status === 204 && status.data?.enrolled === false, { delete: del.status, ownerStatus: status.data });
      } catch (e) {
        check(`cleanup. ${acct.label}: the voice print this run enrolled is deleted again`, false, (e as Error).message);
      }
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  // rtc-node keeps native handles open: leave on our own terms.
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  if (e instanceof PrerequisiteError) console.log(`  ✗ ${e.message}`);
  // An axios error carries its request, Authorization header included: print only what failed.
  else if (axios.isAxiosError(e)) {
    console.error(`\n✗ ${e.config?.method?.toUpperCase()} ${e.config?.url} → ${e.response?.status ?? e.code}: ${JSON.stringify(redact(e.response?.data) ?? e.message)}`);
  } else console.error(e);
  console.log(`\n${passed} passed, ${failed + 1} failed`);
  process.exit(1);
});
```

Патч к `package.json`:

```diff
--- a/package.json
+++ b/package.json
@@ -90,7 +90,12 @@
     "test:speakers:talerid": "dotenv -e .env.talerid -- npx ts-node speaker_labels_test.ts",
     "test:partner": "dotenv -e .env.dev -- npx ts-node partner_messenger_test.ts",
     "test:partner:prod": "dotenv -e .env.prod -- npx ts-node partner_messenger_test.ts",
-    "test:partner:talerid": "PARTNER_E2E_SMOKE=1 dotenv -e .env.talerid -- npx ts-node partner_messenger_test.ts"
+    "test:partner:talerid": "PARTNER_E2E_SMOKE=1 dotenv -e .env.talerid -- npx ts-node partner_messenger_test.ts",
+    "test:interpreter": "BASE_URL=https://staging.id.taler.tirol npx ts-node interpreter_test.ts",
+    "test:interpreter:prod": "BASE_URL=https://id.taler.tirol npx ts-node interpreter_test.ts",
+    "test:interpreter-selftest": "BASE_URL=https://staging.id.taler.tirol npx ts-node interpreter_selftest.ts",
+    "test:interpreter-selftest:prod": "BASE_URL=https://id.taler.tirol npx ts-node interpreter_selftest.ts",
+    "test:interpreter-selftest:talerid": "BASE_URL=https://api.talerid.io npx ts-node interpreter_selftest.ts"
   },
   "devDependencies": {
     "@types/node": "^20.0.0",
```

- [ ] **Step 2: Типы**

```bash
cd ~/Downloads/taler_id_tests && npx tsc --noEmit -p tsconfig.json 2>&1 | grep -c "interpreter_test" ; true
```

Ожидается: `0`. У проекта 40 давних строк ошибок в шести скриптах без импортов — к этой работе они не относятся.
Прогон против бэкенда — в задаче 22, после выкатки на DEV.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add interpreter_test.ts package.json
git commit -m "test: test:interpreter — разговор с переводом от QR до уборки" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 20: Смоук самопроверки и `test:billing`

`test:interpreter-selftest` — пост-деплойный смоук: вход тестовым аккаунтом и `GET /interpreter/selftest` (оба движка
OpenAI). Работает и при выключенном выключателе. `test:billing` ждал ровно 6 тумблеров — с `interpreter` их 7.

**Files:**
- Create: `interpreter_selftest.ts`
- Modify: `billing_test.ts`

- [ ] **Step 1: Смоук и правка `test:billing`**

`interpreter_selftest.ts` целиком:

```ts
/**
 * Post-deploy smoke for the face-to-face interpreter's two engines.
 * Run after every backend or livekit-ai-agent deploy, next to test:translator.
 *
 * GET /interpreter/selftest → the backend calls livekit-ai-agent with the
 * shared secret → the agent opens, side by side, a gpt-realtime-translate
 * session (the simultaneous engine) and a session of the phrase engine's
 * model, sends each the session.update the interpreter really sends, and waits
 * up to 10 s for the confirmation → {ok, reason, simultaneous, phrase, latencyMs}.
 *
 * Catches what the unit tests cannot: OpenAI renaming or retiring either model
 * (the phrase engine runs a dated snapshot, so it will be retired one day),
 * OpenAI refusing a field of the session shape, the agent without its OpenAI
 * key or the shared secret, the backend unable to reach the agent. No LiveKit,
 * no audio, no voice prints.
 *
 * Unlike /voice/translator/selftest the route needs a login: an anonymous call
 * must not be able to open OpenAI sessions.
 *
 * Usage:
 *   npm run test:interpreter-selftest            # DEV
 *   npm run test:interpreter-selftest:prod       # TEST
 *   npm run test:interpreter-selftest:talerid    # PROD
 */

import axios from 'axios';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const USER = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };

// The agent gives each engine 10 s, the backend gives the agent 25 s.
const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true, timeout: 35_000 });

function fail(msg: string, details?: unknown): never {
  console.error(`\n❌ ${msg}`);
  if (details !== undefined) console.error(details);
  process.exit(1);
}

function engineLine(name: string, result: any): string {
  return `${name}: ${result?.ok === true ? 'ok' : 'FAILED'}, ${result?.reason ?? 'no reason given'}`;
}

async function main() {
  console.log(`\n── interpreter selftest — ${BASE_URL} ──`);

  const login = await http.post('/auth/login', USER);
  if (login.status !== 200 || typeof login.data?.accessToken !== 'string') fail(`login ${login.status}`, login.data);
  console.log('  ✓ login');

  const t0 = Date.now();
  const res = await http.get('/interpreter/selftest', {
    headers: { Authorization: `Bearer ${login.data.accessToken}` },
  });
  const body = res.data;
  if (res.status !== 200) {
    const hint = res.status === 404
      ? ': this backend build predates the interpreter'
      : body?.message === 'interpreter_disabled'
        ? ': INTERPRETER_ENABLED is not "true" in the backend .env'
        : '';
    fail(`GET /interpreter/selftest → ${res.status}${hint}`, body);
  }
  if (body?.ok !== true || body?.simultaneous?.ok !== true || body?.phrase?.ok !== true) {
    fail(
      `interpreter selftest failed: ${body?.reason ?? 'no reason given'}\n`
        + `   ${engineLine('simultaneous', body?.simultaneous)}\n`
        + `   ${engineLine('phrase', body?.phrase)}`,
    );
  }
  console.log(`  ✓ interpreter selftest in ${Date.now() - t0} ms (agent latency ${body.latencyMs} ms)`);
  console.log(`    ${engineLine('simultaneous', body.simultaneous)}`);
  console.log(`    ${engineLine('phrase', body.phrase)}`);

  console.log('\n✅ interpreter selftest passed\n');
}

main().catch((e) => {
  // An axios error carries its request, Authorization header included: print only what failed.
  if (axios.isAxiosError(e)) {
    fail(`${e.config?.method?.toUpperCase()} ${e.config?.url} → ${e.response?.status ?? e.code}: ${e.message}`);
  }
  fail(String((e as Error)?.stack || e));
});
```

Патч к `billing_test.ts`:

```diff
--- a/billing_test.ts
+++ b/billing_test.ts
@@ -83,7 +83,7 @@
   const pbRes = await http.get('/billing/pricebook', auth(token));
   check('6. GET /billing/pricebook → 200', pbRes.status === 200, pbRes.data);
   const keys: string[] = Array.isArray(pbRes.data) ? pbRes.data.map((p: any) => p.featureKey) : [];
-  const required = ['voice_assistant', 'web_search', 'ai_twin', 'outbound_call', 'whisper_transcribe', 'meeting_summary'];
+  const required = ['voice_assistant', 'web_search', 'ai_twin', 'outbound_call', 'whisper_transcribe', 'meeting_summary', 'interpreter'];
   for (const k of required) {
     check(`6b. pricebook has "${k}"`, keys.includes(k));
   }
@@ -91,7 +91,7 @@
   // 7. Toggles GET + PATCH
   const togRes = await http.get('/billing/settings/toggles', auth(token));
   check('7. GET /billing/settings/toggles → 200', togRes.status === 200, togRes.data);
-  check('7b. 6 toggles returned', Array.isArray(togRes.data) && togRes.data.length === 6, togRes.data);
+  check('7b. 7 toggles returned', Array.isArray(togRes.data) && togRes.data.length === 7, togRes.data);
 
   const offRes = await http.patch('/billing/settings/toggles/web_search', { enabled: false }, auth(token));
   check('7c. PATCH web_search off → 200', offRes.status === 200, offRes.data);
```

- [ ] **Step 2: Типы**

```bash
cd ~/Downloads/taler_id_tests && npx tsc --noEmit -p tsconfig.json 2>&1 | grep -cE "interpreter_selftest|billing_test" ; true
```

Ожидается: `0`.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add interpreter_selftest.ts billing_test.ts
git commit -m "test: test:interpreter-selftest; test:billing ждёт 7 тумблеров" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Исправления по ревью (задачи с буквой)

Выполняются после задачи 20, в этом порядке, до задачи 21. Ревью кода по группам задач нашло то, что ниже; числа в «Ожидается» — от состояния после задачи 20 и предыдущих задач этого раздела. Сквозной набор и стенд с этими правками прогоняются в задаче 22.

### Task 6b: Код QR принимает то, что телефон ставит вместо дефиса

По ревью задач 4–6:
- **Код, набранный руками, отклонялся как несуществующий.** Нормализация убирала только ASCII-дефис и пробелы. Умная пунктуация iOS превращает `-` в длинное или короткое тире, вставка из мессенджера приносит пробел нулевой ширины, клавиатура CJK — полноширинные цифры. Человек видит на экране правильный код и получает `404 code_not_found`. Теперь такие разделители убираются, а полноширинные знаки приводятся к ASCII (NFKC). Подчёркивание и прочая пунктуация по-прежнему не разделитель.

**Files:**
- Modify: `src/interpreter/interpreter-code.spec.ts`, `src/interpreter/interpreter-code.ts`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/interpreter/interpreter-code.spec.ts`:

```diff
--- a/src/interpreter/interpreter-code.spec.ts
+++ b/src/interpreter/interpreter-code.spec.ts
@@ -26,6 +26,25 @@
     expect(normalizeCode(' AB CD EF 23 ')).toBe('ABCDEF23');
   });
 
+  it('takes what a phone puts in place of a dash or a space', () => {
+    for (const sep of [
+      '\u2010', // hyphen
+      '\u2011', // non-breaking hyphen
+      '\u2013', // en dash: iOS smart punctuation
+      '\u2014', // em dash: iOS smart punctuation, '--'
+      '\u2212', // minus sign
+      '\u00A0', // no-break space
+      '\u200B', // zero-width space from a paste
+    ]) {
+      expect(normalizeCode(`ABCD${sep}EFGH`)).toBe('ABCDEFGH');
+    }
+    expect(normalizeCode('\uFEFFABCDEFGH')).toBe('ABCDEFGH'); // BOM
+  });
+
+  it('folds full-width letters and digits from a CJK keyboard', () => {
+    expect(normalizeCode('\uFF41\uFF42\uFF43\uFF44EFG\uFF12')).toBe('ABCDEFG2');
+  });
+
   it('refuses anything that cannot be a code', () => {
     for (const raw of [
       'ABCDEFG', // too short
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter-code.spec.ts` — падают 2 из 7. Всего наборов 18, тестов 187, падающих 2.

- [ ] **Step 2: Код**

Патч к `src/interpreter/interpreter-code.ts`:

```diff
--- a/src/interpreter/interpreter-code.ts
+++ b/src/interpreter/interpreter-code.ts
@@ -20,10 +20,16 @@
   return code;
 }
 
+// What a phone may put between the groups instead of a plain space or '-':
+// smart punctuation turns '-' into a dash look-alike (U+2010–2015, minus sign),
+// a paste from a messenger brings zero-width characters and a BOM.
+const SEPARATORS = /[\s\-\u2010-\u2015\u2212\u200B-\u200D\uFEFF]/g;
+
 /** The code as generated, or null if the input cannot be one. */
 export function normalizeCode(raw: unknown): string | null {
   if (typeof raw !== 'string') return null;
-  const code = raw.toUpperCase().replace(/[\s-]/g, '');
+  // NFKC folds full-width letters and digits (a CJK keyboard) to ASCII.
+  const code = raw.normalize('NFKC').toUpperCase().replace(SEPARATORS, '');
   return CODE_SHAPE.test(code) ? code : null;
 }
 
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 187 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter-code.spec.ts src/interpreter/interpreter-code.ts
git commit -m "fix(interpreter): код из QR принимает тире-двойники, невидимые символы и полноширинные знаки" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9b: Тело не того типа отвечает только кодом поля; самопроверка называет статус прокси

По ревью задач 7–9:
- **В `message` рядом с нашим кодом попадала английская фраза class-validator.** `{"lang": 42}` давал `["unsupported_language", "lang must be a string"]`: `IsString` не останавливает `Matches` и `MaxLength`, оба отчитываются. Теперь каждое правило поля называет один код, как в `src/partner-api/dto/verify-link-code.dto.ts`. Для кода — `code_not_found`: приложение его уже понимает, нового кода в таблице не появляется.
- **Самопроверка теряла статус прокси.** Если перед агентом nginx отвечает HTML-страницей 502, `res.json()` падал, и в ответе оставалась только ошибка разбора `Unexpected token '<'`. Теперь причина — `agent answered 502, not JSON`, статус по-прежнему 503.

**Files:**
- Modify: `src/interpreter/dto/interpreter-dtos.spec.ts`, `src/interpreter/interpreter-agent.client.spec.ts`, `src/interpreter/dto/create-interpreter-session.dto.ts`, `src/interpreter/dto/join-interpreter-session.dto.ts`, `src/interpreter/interpreter-agent.client.ts`, `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/interpreter/dto/interpreter-dtos.spec.ts`:

```diff
--- a/src/interpreter/dto/interpreter-dtos.spec.ts
+++ b/src/interpreter/dto/interpreter-dtos.spec.ts
@@ -42,10 +42,28 @@
         code: 'A'.repeat(33),
         lang: 'de',
       }),
-    ).toHaveLength(1);
-    expect(
-      await messages(JoinInterpreterSessionDto, { code: 42, lang: 'de' }),
-    ).not.toEqual([]);
+    ).toEqual(['code_not_found']);
+  });
+
+  it('answer a field of the wrong type with the field code alone', async () => {
+    // A failed IsString does not stop Matches or MaxLength: both report.
+    for (const bad of [42, null, ['ru'], { a: 1 }]) {
+      for (const msg of [
+        ...(await messages(CreateInterpreterSessionDto, { lang: bad })),
+        ...(await messages(JoinInterpreterSessionDto, {
+          code: 'X',
+          lang: bad,
+        })),
+      ]) {
+        expect(msg).toBe('unsupported_language');
+      }
+      const code = await messages(JoinInterpreterSessionDto, {
+        code: bad,
+        lang: 'de',
+      });
+      expect(code.length).toBeGreaterThan(0);
+      for (const msg of code) expect(msg).toBe('code_not_found');
+    }
   });
 
   it('take only the endings the agent reports', async () => {
```

Патч к `src/interpreter/interpreter-agent.client.spec.ts`:

```diff
--- a/src/interpreter/interpreter-agent.client.spec.ts
+++ b/src/interpreter/interpreter-agent.client.spec.ts
@@ -178,6 +178,17 @@
       expect(timeout).toHaveBeenCalledWith(25_000);
     });
 
+    it('answers 503 with the status of an answer that is not JSON', async () => {
+      fetchFn.mockResolvedValue(
+        new Response('<html>502 Bad Gateway</html>', { status: 502 }),
+      );
+
+      await expect(client.selftest()).resolves.toEqual({
+        status: 503,
+        body: { ok: false, reason: 'agent answered 502, not JSON' },
+      });
+    });
+
     it('answers 503 when the agent cannot be reached', async () => {
       fetchFn.mockRejectedValue(
         new DOMException('The operation timed out.', 'TimeoutError'),
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/dto/interpreter-dtos.spec.ts` — падают 2 из 4; `src/interpreter/interpreter-agent.client.spec.ts` — падают 1 из 11. Всего наборов 18, тестов 189, падающих 3.

- [ ] **Step 2: Код**

Патч к `src/interpreter/dto/create-interpreter-session.dto.ts`:

```diff
--- a/src/interpreter/dto/create-interpreter-session.dto.ts
+++ b/src/interpreter/dto/create-interpreter-session.dto.ts
@@ -2,7 +2,7 @@
 
 export class CreateInterpreterSessionDto {
   /** The host's language; whether the agent speaks it is the service's check. */
-  @IsString()
+  @IsString({ message: 'unsupported_language' })
   @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
   lang!: string;
 }
```

Патч к `src/interpreter/dto/join-interpreter-session.dto.ts`:

```diff
--- a/src/interpreter/dto/join-interpreter-session.dto.ts
+++ b/src/interpreter/dto/join-interpreter-session.dto.ts
@@ -1,13 +1,17 @@
 import { IsString, Matches, MaxLength } from 'class-validator';
 
 export class JoinInterpreterSessionDto {
-  /** As scanned or typed: the service normalizes case, spaces and dashes. */
-  @IsString()
-  @MaxLength(32)
+  /**
+   * As scanned or typed: the service normalizes case, spaces and dashes.
+   * Every check names the same code, or class-validator's English sentence
+   * ("code must be a string") would ride along in `message`.
+   */
+  @IsString({ message: 'code_not_found' })
+  @MaxLength(32, { message: 'code_not_found' })
   code!: string;
 
   /** The guest's language; whether the agent speaks it is the service's check. */
-  @IsString()
+  @IsString({ message: 'unsupported_language' })
   @Matches(/^[a-z]{2,3}$/, { message: 'unsupported_language' })
   lang!: string;
 }
```

Патч к `src/interpreter/interpreter-agent.client.ts`:

```diff
--- a/src/interpreter/interpreter-agent.client.ts
+++ b/src/interpreter/interpreter-agent.client.ts
@@ -86,15 +86,22 @@
 
   /** The agent's own answer and status; 503 when there was none. */
   async selftest(): Promise<{ status: number; body: unknown }> {
+    let status = 0;
     try {
       const res = await this.call(
         'GET',
         '/interpreter/selftest',
         SELFTEST_TIMEOUT_MS,
       );
-      return { status: res.status, body: await res.json() };
+      status = res.status;
+      return { status, body: await res.json() };
     } catch (e) {
-      return { status: 503, body: { ok: false, reason: errorText(e) } };
+      // An answer that is not JSON came from a proxy in front of the agent
+      // (nginx's 502 page): its status says more than the parser's error.
+      const reason = status
+        ? `agent answered ${status}, not JSON`
+        : errorText(e);
+      return { status: 503, body: { ok: false, reason } };
     }
   }
 
```

Патч к `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`:

```diff
--- a/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
+++ b/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
@@ -146,6 +146,8 @@
 | `503 interpreter_unavailable` | агент не стартовал |
 | `404 session_not_found` / `409 not_waiting` | чужая или несуществующая сессия / новый код не в `waiting` |
 
+Поле тела не того типа (язык не строка, код не строка или длиннее 32 символов) — `400` с кодом своего поля: `unsupported_language` или `code_not_found`. Каждое правило проверки называет один и тот же код, иначе рядом с ним в `message` попала бы английская фраза class-validator.
+
 - `GET /interpreter/languages` → `{enabled, languages: [{code, name}]}`. Список — 81 язык агента, ровно коды `SUPPORTED_LANGS` из `livekit-agent/lang-names.js`, без регионов (`pt`, не `pt-BR`). Импортировать агентский файл в бэкенд нельзя: сборка не кладёт `livekit-agent/` в `dist/`. Поэтому в бэкенде своя копия списка и Jest-тест, который сверяет её с `lang-names.js`. Код, который бэкенд примет, а агент нет, закончится `503` уже после открытия биллинга. Синхронность зависит от пары и сообщается при входе Б.
 - `POST /interpreter/sessions` с телом `{lang}`. Проверки:
   - режим включён;
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 189 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/dto/interpreter-dtos.spec.ts src/interpreter/interpreter-agent.client.spec.ts src/interpreter/dto/create-interpreter-session.dto.ts src/interpreter/dto/join-interpreter-session.dto.ts src/interpreter/interpreter-agent.client.ts docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
git commit -m "fix(interpreter): тело не того типа — только код поля; самопроверка называет статус прокси" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11b: Сверка закрывает биллинг, который не держит ни одна сессия

По ревью задачи 10:
- **Хост мог платить до двух часов за разговор, которого нет (критично).** Вход Б открывает биллинг (`startSession`) и только потом записывает его id в сессию. Все пути закрытия — `close()` и оба прохода сверки — идут от строки сессии. Если процесс умер между этими шагами, если не прошла уборка после проигранного захвата кода или шаг биллинга в `close()`, открытый `AiSession` не находит никто, кроме потолка метеринга в 2 часа. Теперь третий проход сверки берёт `interpreter`-биллинг в `active` старше минуты и закрывает как `failed` тот, что не держит ни одна `ACTIVE`-сессия. Минута — запас на вход, который как раз открыл биллинг и вот-вот его привяжет: между этими шагами нет ничего, кроме одного запроса к базе.
- Две ноды PROD могут закрыть один и тот же биллинг почти одновременно — так же, как сегодня метеринг и `close()`: `endBillingIfActive` перечитывает статус и закрывает только `active`.
- Заодно по тому же ревью — в таблицу ошибок спеки: `409 same_voice_print` (есть в коде с задачи 10, в таблице не было) и `503 interpreter_unavailable` при создании, когда LiveKit не создал комнату.

**Files:**
- Modify: `src/interpreter/interpreter.reconciler.spec.ts`, `src/interpreter/interpreter.service.spec.ts`, `src/interpreter/interpreter.reconciler.ts`, `src/interpreter/interpreter.service.ts`, `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/interpreter/interpreter.reconciler.spec.ts`:

```diff
--- a/src/interpreter/interpreter.reconciler.spec.ts
+++ b/src/interpreter/interpreter.reconciler.spec.ts
@@ -13,20 +13,37 @@
   ...over,
 });
 
-function setup(rows: { active?: unknown[]; waiting?: unknown[] } = {}) {
+function setup(
+  rows: {
+    active?: unknown[];
+    waiting?: unknown[];
+    openBilling?: { id: string }[];
+  } = {},
+) {
   const prisma = {
     interpreterSession: {
-      findMany: jest.fn(async ({ where }: any) =>
-        where.status === 'ACTIVE' ? (rows.active ?? []) : (rows.waiting ?? []),
-      ),
+      findMany: jest.fn(async ({ where }: any) => {
+        if (where.billingSessionId) {
+          return ((rows.active ?? []) as any[]).filter((s) =>
+            where.billingSessionId.in.includes(s.billingSessionId),
+          );
+        }
+        return where.status === 'ACTIVE'
+          ? (rows.active ?? [])
+          : (rows.waiting ?? []);
+      }),
       updateMany: jest.fn().mockResolvedValue({ count: 1 }),
     },
     aiSession: {
       findUnique: jest.fn().mockResolvedValue({ status: 'active' }),
+      findMany: jest.fn(async () => rows.openBilling ?? []),
     },
   };
   const livekit = { agentPresent: jest.fn().mockResolvedValue(true) };
-  const interpreter = { close: jest.fn().mockResolvedValue(undefined) };
+  const interpreter = {
+    close: jest.fn().mockResolvedValue(undefined),
+    closeUnheldBilling: jest.fn().mockResolvedValue(undefined),
+  };
   const reconciler = new InterpreterReconciler(
     prisma as any,
     livekit as any,
@@ -144,6 +161,71 @@
   });
 });
 
+describe('InterpreterReconciler: billing no session holds', () => {
+  it('closes open interpreter billing that no ACTIVE session holds', async () => {
+    // bill-1 belongs to a live conversation; bill-2 was opened by a join that
+    // died before claiming the code, or left open by a failed cleanup.
+    const { reconciler, prisma, interpreter } = setup({
+      active: [active()],
+      openBilling: [{ id: 'bill-1' }, { id: 'bill-2' }],
+    });
+
+    await reconciler.runOnce(NOW);
+
+    expect(prisma.aiSession.findMany).toHaveBeenCalledWith({
+      where: {
+        featureKey: 'interpreter',
+        status: 'active',
+        // A join that is still running gets a minute to link it.
+        startedAt: { lt: new Date(NOW.getTime() - 60_000) },
+      },
+      select: { id: true },
+    });
+    expect(prisma.interpreterSession.findMany).toHaveBeenCalledWith({
+      where: {
+        status: 'ACTIVE',
+        billingSessionId: { in: ['bill-1', 'bill-2'] },
+      },
+      select: { billingSessionId: true },
+    });
+    expect(interpreter.closeUnheldBilling).toHaveBeenCalledTimes(1);
+    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-2');
+  });
+
+  it('does not look for sessions when no interpreter billing is open', async () => {
+    const { reconciler, prisma, interpreter } = setup();
+
+    await reconciler.runOnce(NOW);
+
+    // The active and the waiting pass; no third lookup.
+    expect(prisma.interpreterSession.findMany).toHaveBeenCalledTimes(2);
+    expect(interpreter.closeUnheldBilling).not.toHaveBeenCalled();
+  });
+
+  it('goes on with the other billing sessions when one fails to close', async () => {
+    const { reconciler, interpreter } = setup({
+      openBilling: [{ id: 'bill-2' }, { id: 'bill-3' }],
+    });
+    interpreter.closeUnheldBilling.mockRejectedValueOnce(new Error('db down'));
+
+    await expect(reconciler.runOnce(NOW)).resolves.toBeUndefined();
+    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-3');
+  });
+
+  it('runs even when the session passes could not load', async () => {
+    const { reconciler, prisma, interpreter } = setup({
+      openBilling: [{ id: 'bill-2' }],
+    });
+    prisma.interpreterSession.findMany
+      .mockRejectedValueOnce(new Error('db down'))
+      .mockRejectedValueOnce(new Error('db down'));
+
+    await reconciler.runOnce(NOW);
+
+    expect(interpreter.closeUnheldBilling).toHaveBeenCalledWith('bill-2');
+  });
+});
+
 describe('InterpreterReconciler: robustness', () => {
   it('goes on with the other sessions when one fails', async () => {
     const { reconciler, livekit, interpreter } = setup({
```

Патч к `src/interpreter/interpreter.service.spec.ts`:

```diff
--- a/src/interpreter/interpreter.service.spec.ts
+++ b/src/interpreter/interpreter.service.spec.ts
@@ -893,6 +893,29 @@
   });
 });
 
+describe('closeUnheldBilling', () => {
+  it('ends billing the reconciler found with no session holding it', async () => {
+    const { service, gating, prisma } = setup();
+
+    await service.closeUnheldBilling('bill-9');
+
+    expect(prisma.aiSession.findUnique).toHaveBeenCalledWith({
+      where: { id: 'bill-9' },
+      select: { status: true },
+    });
+    expect(gating.endSession).toHaveBeenCalledWith('bill-9', 'failed');
+  });
+
+  it('leaves it alone when metering or another node ended it first', async () => {
+    const { service, gating, prisma } = setup();
+    prisma.aiSession.findUnique.mockResolvedValue({ status: 'failed' });
+
+    await service.closeUnheldBilling('bill-9');
+
+    expect(gating.endSession).not.toHaveBeenCalled();
+  });
+});
+
 describe('selftest', () => {
   it("passes the agent's answer through", async () => {
     const { service, agent } = setup();
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter.reconciler.spec.ts` — падают 3 из 15; `src/interpreter/interpreter.service.spec.ts` — падают 2 из 47. Всего наборов 18, тестов 195, падающих 5.

- [ ] **Step 2: Код**

Патч к `src/interpreter/interpreter.reconciler.ts`:

```diff
--- a/src/interpreter/interpreter.reconciler.ts
+++ b/src/interpreter/interpreter.reconciler.ts
@@ -1,6 +1,7 @@
 import { Injectable, Logger } from '@nestjs/common';
 import { Interval } from '@nestjs/schedule';
 import type { InterpreterEndReason } from '@prisma/client';
+import { FEATURE_KEYS } from '../billing/constants/feature-keys';
 import { PrismaService } from '../prisma/prisma.service';
 import { InterpreterLivekitService } from './interpreter-livekit.service';
 import { InterpreterService } from './interpreter.service';
@@ -10,6 +11,8 @@
 const AGENT_LOST_AFTER_MS = 60_000;
 // After a code expires the host can still ask for a new one this long.
 const WAITING_GRACE_MS = 5 * 60_000;
+// A join links the billing it opened to the session a moment later.
+const UNLINKED_BILLING_GRACE_MS = 60_000;
 
 const SESSION_FIELDS = {
   id: true,
@@ -32,6 +35,7 @@
  * funds, the 2-hour cap), an agent gone without reporting (restart, deploy),
  * a QR nobody scanned. Every end goes through InterpreterService.close, the
  * same path as a hang-up. Runs on every app node; close() makes that safe.
+ * Last, it closes interpreter billing that no ACTIVE session holds.
  */
 @Injectable()
 export class InterpreterReconciler {
@@ -79,6 +83,49 @@
         }),
       (s) => this.interpreter.close(s, 'EXPIRED', { stopAgent: false }),
     );
+    await this.reconcileBilling(now);
+  }
+
+  /**
+   * The passes above start from a session row, so they never see billing that
+   * no ACTIVE session holds: a join that died between opening billing and
+   * claiming the code, a cleanup step that failed after a lost claim or in
+   * close(). Metering would charge the host for it up to its 2-hour cap.
+   */
+  private async reconcileBilling(now: Date): Promise<void> {
+    let unheld: string[];
+    try {
+      const open = await this.prisma.aiSession.findMany({
+        where: {
+          featureKey: FEATURE_KEYS.INTERPRETER,
+          status: 'active',
+          startedAt: {
+            lt: new Date(now.getTime() - UNLINKED_BILLING_GRACE_MS),
+          },
+        },
+        select: { id: true },
+      });
+      if (open.length === 0) return;
+      const held = await this.prisma.interpreterSession.findMany({
+        where: {
+          status: 'ACTIVE',
+          billingSessionId: { in: open.map((b) => b.id) },
+        },
+        select: { billingSessionId: true },
+      });
+      const heldIds = new Set(held.map((s) => s.billingSessionId));
+      unheld = open.map((b) => b.id).filter((id) => !heldIds.has(id));
+    } catch (e) {
+      this.log.warn(`loading open billing failed: ${String(e)}`);
+      return;
+    }
+    for (const id of unheld) {
+      try {
+        await this.interpreter.closeUnheldBilling(id);
+      } catch (e) {
+        this.log.warn(`billing ${id}: closing failed: ${String(e)}`);
+      }
+    }
   }
 
   private async reconcileActive(
```

Патч к `src/interpreter/interpreter.service.ts`:

```diff
--- a/src/interpreter/interpreter.service.ts
+++ b/src/interpreter/interpreter.service.ts
@@ -521,6 +521,18 @@
     }
   }
 
+  /**
+   * Billing the reconciler found open with no ACTIVE session holding it.
+   * Nothing else would ever close it: every other path starts from the
+   * session row, and the row does not lead here.
+   */
+  async closeUnheldBilling(billingSessionId: string): Promise<void> {
+    this.log.warn(
+      `billing ${billingSessionId}: open with no active session, closing`,
+    );
+    await this.endBillingIfActive(billingSessionId, 'failed');
+  }
+
   /** Metering may have closed it already; endSession would overwrite that status. */
   private async endBillingIfActive(
     billingSessionId: string,
```

Патч к `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`:

```diff
--- a/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
+++ b/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
@@ -139,11 +139,12 @@
 | `400 unsupported_language` / `400 same_language` | язык не из списка / совпадает с языком хоста |
 | `409 voice_print_required` / `409 host_voice_print_required` | нет пригодного образца у вызывающего / у хоста |
 | `409 already_in_session` | у пользователя уже идёт разговор |
+| `409 same_voice_print` | при входе Б: образцы хоста и гостя почти одинаковы (косинус от 0,99), до открытия биллинга |
 | `402 insufficient_funds` / `403 feature_disabled` | при создании: у самого хоста нет резерва / выключен тумблер |
 | `402 host_insufficient_funds` / `403 host_feature_disabled` | при входе Б: то же у хоста |
 | `404 code_not_found` / `410 code_expired` / `409 own_code` / `409 code_used` | код |
 | `429 too_many_attempts` | больше 10 попыток входа в минуту |
-| `503 interpreter_unavailable` | агент не стартовал |
+| `503 interpreter_unavailable` | агент не стартовал (вход Б) / комнату LiveKit не создать (создание) |
 | `404 session_not_found` / `409 not_waiting` | чужая или несуществующая сессия / новый код не в `waiting` |
 
 Поле тела не того типа (язык не строка, код не строка или длиннее 32 символов) — `400` с кодом своего поля: `unsupported_language` или `code_not_found`. Каждое правило проверки называет один и тот же код, иначе рядом с ним в `message` попала бы английская фраза class-validator.
@@ -186,6 +187,7 @@
 - Активная сессия, чья биллинг-сессия уже не `active` (`terminated_no_funds` или `terminated_stale`), закрывается с причиной `no_funds` или `max_duration`.
 - Активная сессия, в комнате которой участника `voice-interpreter` нет дольше 60 с (`listParticipants`), закрывается с причиной `agent_lost`. Так ловятся рестарт и деплой агента: в этих случаях он сам `agent-ended` не пришлёт. Отсчёт идёт от `agentSeenAt` (а до первой сверки — от `startedAt`). Если `listParticipants` упал, сверка в этот раз ничего не делает: сбой API — не пустая комната.
 - Сессия в `waiting`, у которой код истёк больше 5 минут назад и новый не запрошен, закрывается с причиной `expired`.
+- Биллинг `interpreter` в `active`, открытый больше минуты назад, который не держит ни одна активная сессия, закрывается как `failed`. Остальные проходы идут от строки сессии и такой биллинг не видят: вход Б умер между открытием биллинга и захватом кода, или не прошла уборка после проигранного захвата либо в `close()`. Иначе метеринг списывал бы с хоста до потолка в 2 часа. Минута — запас на вход, который как раз открыл биллинг и вот-вот его привяжет.
 
 Каждое закрытие по сверке идёт тем же путём, что и `end`: стоп агента, закрытие биллинга, удаление комнаты. Закрытие условное (`status ≠ ended` → `ended`), поэтому из двух app-нод PROD побочные действия выполняет одна. Биллинг закрывается, только если `AiSession` ещё `active` (`endSession` не идемпотентен): `translation_failed` и `agent_lost` — как `failed`, `no_funds` и `max_duration` — уже закрыт метерингом, остальное — `completed`.
 
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 195 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter.reconciler.spec.ts src/interpreter/interpreter.service.spec.ts src/interpreter/interpreter.reconciler.ts src/interpreter/interpreter.service.ts docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
git commit -m "fix(interpreter): сверка закрывает биллинг, который не держит ни одна сессия" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11c: `agentSeenAt` пишется только вперёд

По ревью задач 11–13:
- **Запоздавшая запись с другой ноды откатывала отметку назад.** Сверка пишет в `agentSeenAt` время начала своего прохода, а проход с медленным LiveKit идёт секунды. Нода А начала проход в T0, нода Б в T5 увидела агента и записала T5 раньше, чем дошла запись А — и отметка вернулась к T0. 60 с до `agent_lost` начинают считаться слишком рано, и короткое переподключение агента может закончить живой разговор. Теперь запись условная: только если отметки нет или она раньше.

**Files:**
- Modify: `src/interpreter/interpreter.reconciler.spec.ts`, `src/interpreter/interpreter.reconciler.ts`, `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`

- [ ] **Step 1: Тесты (падают)**

Патч к `src/interpreter/interpreter.reconciler.spec.ts`:

```diff
--- a/src/interpreter/interpreter.reconciler.spec.ts
+++ b/src/interpreter/interpreter.reconciler.spec.ts
@@ -93,8 +93,13 @@
     await reconciler.runOnce(NOW);
 
     expect(livekit.agentPresent).toHaveBeenCalledWith('interp-room-1');
+    // Only forward: another node may have written a later sighting already.
     expect(prisma.interpreterSession.updateMany).toHaveBeenCalledWith({
-      where: { id: 'sess-1', status: 'ACTIVE' },
+      where: {
+        id: 'sess-1',
+        status: 'ACTIVE',
+        OR: [{ agentSeenAt: null }, { agentSeenAt: { lt: NOW } }],
+      },
       data: { agentSeenAt: NOW },
     });
     expect(interpreter.close).not.toHaveBeenCalled();
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/interpreter/interpreter.reconciler.spec.ts` — падают 1 из 15. Всего наборов 18, тестов 195, падающих 1.

- [ ] **Step 2: Код**

Патч к `src/interpreter/interpreter.reconciler.ts`:

```diff
--- a/src/interpreter/interpreter.reconciler.ts
+++ b/src/interpreter/interpreter.reconciler.ts
@@ -150,7 +150,14 @@
     if (present === null) return;
     if (present) {
       await this.prisma.interpreterSession.updateMany({
-        where: { id: s.id, status: 'ACTIVE' },
+        // Only forward: a slow tick on one node must not overwrite a fresher
+        // sighting another node wrote meanwhile, or the 60 s would count
+        // from too early and could end a conversation the agent never left.
+        where: {
+          id: s.id,
+          status: 'ACTIVE',
+          OR: [{ agentSeenAt: null }, { agentSeenAt: { lt: now } }],
+        },
         data: { agentSeenAt: now },
       });
       return;
```

Патч к `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`:

```diff
--- a/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
+++ b/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
@@ -122,7 +122,7 @@
 | `codeExpiresAt` | дата-время? | |
 | `status` | enum `waiting`, `active`, `ended` | |
 | `billingSessionId` | uuid? | `AiSession.id` |
-| `agentSeenAt` | дата-время? | когда сверка последний раз видела агента в комнате; по нему считается `agent_lost` |
+| `agentSeenAt` | дата-время? | когда сверка последний раз видела агента в комнате; по нему считается `agent_lost`. Пишется только вперёд: запоздавшая запись медленной сверки с другой ноды не откатывает отметку назад |
 | `startedAt` / `endedAt` | дата-время? | `startedAt` — момент входа Б |
 | `endReason` | enum? | `hangup`, `partner_left`, `no_funds`, `max_duration`, `translation_failed`, `agent_lost`, `expired` |
 | `createdAt` / `updatedAt` | дата-время | |
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 18 наборов, 195 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/interpreter/interpreter.reconciler.spec.ts src/interpreter/interpreter.reconciler.ts docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
git commit -m "fix(interpreter): agentSeenAt пишется только вперёд" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14b: Ручки переводчика звонка, E2EE и музыки ожидания закрыты для комнат разговора

По ревью задач 14–15:
- **Задача 14 закрыла `RoomAccessGuard`, но не ручки, которым хватает токена Taler ID.** `translator/start|stop`, `set-lang`, `disable-e2ee`, `hold-music/start|stop` стоят только под `JwtAuthGuard` и не проверяют, кто в комнате. Имя комнаты `interp-…` знают оба участника: любой из них мог бы запустить в разговоре переводчик звонка поверх агента или музыку ожидания в оба телефона. Теперь на этих шести ручках `NotInterpreterRoomGuard` → `403 interpreter_room`. `RoomAccessGuard` берёт ту же проверку `isInterpreterRoom`.
- Остальные комнаты ведут себя как раньше: их права здесь не меняются (что эти ручки пускают любого с токеном в любую комнату по имени — давняя особенность, она вне этой работы).

**Files:**
- Create: `src/voice/guards/not-interpreter-room.guard.spec.ts`, `src/voice/guards/not-interpreter-room.guard.ts`
- Modify: `src/voice/voice.controller.ts`, `src/voice/guards/room-access.guard.ts`, `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`

- [ ] **Step 1: Тесты (падают)**

`src/voice/guards/not-interpreter-room.guard.spec.ts` целиком:

```ts
import { ForbiddenException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { VoiceController } from '../voice.controller';
import {
  isInterpreterRoom,
  NotInterpreterRoomGuard,
} from './not-interpreter-room.guard';

const ctxFor = (roomName?: string) =>
  ({
    switchToHttp: () => ({ getRequest: () => ({ params: { roomName } }) }),
  }) as any;

describe('NotInterpreterRoomGuard', () => {
  const guard = new NotInterpreterRoomGuard();

  it('refuses an interpreter room with 403 interpreter_room', () => {
    let err: unknown;
    try {
      guard.canActivate(ctxFor('interp-0f8fad5b-d9cb-469f-a165-70867728950e'));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ForbiddenException);
    expect((err as ForbiddenException).message).toBe('interpreter_room');
  });

  it('lets every other room through', () => {
    for (const room of ['call-1', 'group-1', 'personal-ab12cd34-1', 'tmp-1']) {
      expect(guard.canActivate(ctxFor(room))).toBe(true);
    }
    expect(isInterpreterRoom(undefined)).toBe(false);
  });

  it('stands behind the token on every room route that has no room check', () => {
    // These routes take any Taler ID token: without the guard a participant,
    // who knows the room's name, could start them in an interpreter room.
    for (const route of [
      'disableE2EE',
      'startTranslator',
      'stopTranslator',
      'setTranslatorLang',
      'startHoldMusic',
      'stopHoldMusic',
    ] as const) {
      expect(
        Reflect.getMetadata(GUARDS_METADATA, VoiceController.prototype[route]),
      ).toEqual([JwtAuthGuard, NotInterpreterRoomGuard]);
    }
  });
});
```

Run: `npx jest src/interpreter src/billing src/voice/guards`
Expected: `src/voice/guards/not-interpreter-room.guard.spec.ts` — не запускается: Cannot find module. Всего наборов 19, тестов 195, падающих 0, не запустившихся наборов 1.

- [ ] **Step 2: Код**

`src/voice/guards/not-interpreter-room.guard.ts` целиком:

```ts
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

/** Rooms of a conversation with translation, named by src/interpreter. */
export function isInterpreterRoom(roomName: unknown): boolean {
  return typeof roomName === 'string' && roomName.startsWith('interp-');
}

/**
 * For the room routes that trust a Taler ID token alone: the call translator,
 * the E2EE switch, hold music. Both people in an interpreter room know its
 * name, and none of these belongs there: the call translator would talk over
 * the agent, hold music would play into both phones.
 */
@Injectable()
export class NotInterpreterRoomGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    if (isInterpreterRoom(ctx.switchToHttp().getRequest().params?.roomName)) {
      throw new ForbiddenException('interpreter_room');
    }
    return true;
  }
}
```

Патч к `src/voice/voice.controller.ts`:

```diff
--- a/src/voice/voice.controller.ts
+++ b/src/voice/voice.controller.ts
@@ -25,6 +25,7 @@
 import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
 import { RecorderSecretGuard } from './guards/recorder-secret.guard';
 import { RoomAccessGuard } from './guards/room-access.guard';
+import { NotInterpreterRoomGuard } from './guards/not-interpreter-room.guard';
 import { LK_API_KEY, LK_API_SECRET } from '../common/livekit-credentials';
 import { CurrentUser } from '../common/decorators/current-user.decorator';
 import { RoomActor } from '../common/decorators/room-actor.decorator';
@@ -440,7 +441,7 @@
   // ─── E2EE ───
 
   @Post('rooms/:roomName/disable-e2ee')
-  @UseGuards(JwtAuthGuard)
+  @UseGuards(JwtAuthGuard, NotInterpreterRoomGuard)
   disableE2EE(@Param('roomName') roomName: string) {
     return this.service.disableE2EE(roomName);
   }
@@ -453,19 +454,19 @@
   }
 
   @Post('rooms/:roomName/translator/start')
-  @UseGuards(JwtAuthGuard)
+  @UseGuards(JwtAuthGuard, NotInterpreterRoomGuard)
   startTranslator(@Param('roomName') roomName: string) {
     return this.service.startTranslator(roomName);
   }
 
   @Post('rooms/:roomName/translator/stop')
-  @UseGuards(JwtAuthGuard)
+  @UseGuards(JwtAuthGuard, NotInterpreterRoomGuard)
   stopTranslator(@Param('roomName') roomName: string) {
     return this.service.stopTranslator(roomName);
   }
 
   @Post('rooms/:roomName/set-lang')
-  @UseGuards(JwtAuthGuard)
+  @UseGuards(JwtAuthGuard, NotInterpreterRoomGuard)
   setTranslatorLang(
     @Param('roomName') roomName: string,
     @Body('lang') lang: string,
@@ -607,13 +608,13 @@
   // ─── Hold Music ───
 
   @Post('rooms/:roomName/hold-music/start')
-  @UseGuards(JwtAuthGuard)
+  @UseGuards(JwtAuthGuard, NotInterpreterRoomGuard)
   startHoldMusic(@Param('roomName') roomName: string) {
     return this.service.startHoldMusic(roomName);
   }
 
   @Post('rooms/:roomName/hold-music/stop')
-  @UseGuards(JwtAuthGuard)
+  @UseGuards(JwtAuthGuard, NotInterpreterRoomGuard)
   stopHoldMusic(@Param('roomName') roomName: string) {
     return this.service.stopHoldMusic(roomName);
   }
```

Патч к `src/voice/guards/room-access.guard.ts`:

```diff
--- a/src/voice/guards/room-access.guard.ts
+++ b/src/voice/guards/room-access.guard.ts
@@ -11,6 +11,7 @@
 import { PrismaService } from '../../prisma/prisma.service';
 import { isApiAccessToken } from '../../common/utils/access-token.util';
 import { LK_API_SECRET } from '../../common/livekit-credentials';
+import { isInterpreterRoom } from './not-interpreter-room.guard';
 
 /**
  * Proves the caller is entitled to act on `:roomName` — and, on success,
@@ -58,7 +59,7 @@
     // guard. None of the routes behind it (recorder, public translator, room
     // chat) belongs in such a room: a recorder there would capture the very
     // speech the agent keeps off the other phone.
-    if (roomName.startsWith('interp-')) {
+    if (isInterpreterRoom(roomName)) {
       throw new ForbiddenException('interpreter_room');
     }
 
```

Патч к `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`:

```diff
--- a/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
+++ b/docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
@@ -195,6 +195,7 @@
 - Векторы образцов никакая ручка не отдаёт и в логи не пишет. Агенту они уходят только по внутренней сети: localhost на DEV и TEST, VPC `10.130.0.0/20` на PROD.
 - Перебор кодов: около 40 бит, TTL 5 минут, код одноразовый. На ручку входа — 10 попыток в минуту на пользователя, счётчиком в Redis. `@Throttle` для этого не годится: глобальный `ThrottlerGuard` считает по IP и срабатывает раньше проверки токена.
 - `RoomAccessGuard` пускает любой токен LiveKit своей комнаты на ручки записи встречи, публичного переводчика и чата. Для комнат `interp-*` он отвечает `403 interpreter_room`: иначе участник разговора с переводом мог бы своим токеном включить в нём запись встречи.
+- Комнатные ручки, которым хватает одного токена Taler ID (переводчик звонка — `translator/start|stop`, `set-lang`; `disable-e2ee`; музыка ожидания), для `interp-*` отвечают тем же `403 interpreter_room` (`NotInterpreterRoomGuard`). Имя комнаты знают оба участника, и иначе любой из них мог бы запустить в разговоре переводчик звонка поверх агента или музыку в оба телефона.
 
 **Выключатель** `INTERPRETER_ENABLED` (по умолчанию выключен). В выключенном состоянии `languages` отвечает `enabled=false`, остальные ручки — `403 interpreter_disabled`. Приложение показывает кнопку только при `enabled=true`.
 
```

- [ ] **Step 3: Проверить**

```bash
npx jest src/interpreter src/billing src/voice/guards 2>&1 | tail -6
npx tsc --noEmit -p tsconfig.build.json; echo tsc-exit=$?
```

Ожидается: 19 наборов, 198 тестов, все зелёные; `tsc-exit=0`.

- [ ] **Step 4: Коммит**

```bash
git add src/voice/guards/not-interpreter-room.guard.spec.ts src/voice/guards/not-interpreter-room.guard.ts src/voice/voice.controller.ts src/voice/guards/room-access.guard.ts docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
git commit -m "fix(voice): переводчик звонка, E2EE и музыка ожидания закрыты для комнат разговора" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 20b: Сквозные наборы — уборка по Ctrl-C, токены не в выводе

По ревью задач 18–20:
- **Ctrl-C посреди `test:interpreter` оставлял разговор платным.** Уборка стояла в `finally`, а SIGINT по умолчанию убивает процесс без него. Это первый набор, который держит открытым поминутный биллинг: разговор с хоста списывал до 60–120 с, пока его не закроют агент и сверка, а записанные прогоном образцы голоса оставались. Теперь уборка — одна функция `cleanup()` для `finally` и для SIGINT/SIGTERM, выполняется один раз; после сигнала выход с кодом 130, второй Ctrl-C выходит сразу.
- **Смоук самопроверки печатал ответ входа как есть.** При неожиданной форме ответа `/auth/login` в CI-лог ушло бы поле с токеном. Теперь вывод проходит `redact()`, как в основном наборе.
- Подсказка `interpreter_disabled` в смоуке не срабатывала никогда: самопроверка не зависит от выключателя. Убрана, на её месте комментарий.
- В шапке набора — какие коды ошибок оставлены Jest-тестам бэкенда и почему.

**Files:**
- Modify: `interpreter_test.ts`, `interpreter_selftest.ts` (репозиторий `taler_id_tests`)

- [ ] **Step 1: Правки**

Патч к `interpreter_test.ts`:

```diff
--- a/interpreter_test.ts
+++ b/interpreter_test.ts
@@ -34,6 +34,14 @@
  * the bot's speech and checks 11/12 fail with silence: call
  * DELETE /voice-gate/owner for that account and rerun.
  *
+ * Ctrl-C (or a CI timeout's SIGTERM) runs the same cleanup before leaving:
+ * from B's join on, the host pays by the minute. A second Ctrl-C leaves at once.
+ *
+ * Left to the backend's Jest suite: 410 code_expired (needs a 5-minute wait),
+ * 409 same_voice_print, 402/403 host_insufficient_funds/host_feature_disabled
+ * (would need the host's wallet or toggles changed), 429 too_many_attempts
+ * (would spend the minute's join attempts both accounts need).
+ *
  * Limits this suite is built around:
  *   - entering codes is capped at 10 attempts a minute per user, so the
  *     negative join checks are split between the accounts (A makes 4, B 3):
@@ -630,6 +638,59 @@
 
 // ── the test ───────────────────────────────────────────────────────────────
 
+/** What the cleanup undoes; module-level, so a signal handler reaches it too. */
+type Run = { host: Account; accounts: Account[]; bots: Bot[]; openSessions: Set<string> };
+let run: Run | undefined;
+let cleaning: Promise<void> | undefined;
+
+/**
+ * Each step on its own: one failure must not skip the rest. The end comes
+ * first: it closes the host's billing and deletes the room. Runs once, from
+ * the main flow's finally or from a signal, whichever comes first.
+ */
+function cleanup(): Promise<void> {
+  cleaning ??= (async () => {
+    if (!run) return;
+    const { host, accounts, bots, openSessions } = run;
+    for (const id of openSessions) {
+      try {
+        const r = await http.post(`/interpreter/sessions/${id}/end`, {}, { ...auth(host.token), timeout: END_TIMEOUT_MS });
+        console.log(`  cleanup: end conversation ${id} → ${r.status}`);
+      } catch (e) {
+        console.log(`  cleanup: end conversation ${id} → error: ${(e as Error).message}`);
+      }
+    }
+    for (const bot of bots) {
+      try {
+        await bot.close();
+      } catch (e) {
+        console.log(`  cleanup: ${bot.label}'s bot → error: ${(e as Error).message}`);
+      }
+    }
+    for (const acct of accounts) {
+      if (!acct.enrolledByRun) continue;
+      try {
+        const del = await http.delete('/voice-gate/owner', auth(acct.token));
+        const status = await http.get('/voice-gate/owner-status', auth(acct.token));
+        check(`cleanup. ${acct.label}: the voice print this run enrolled is deleted again`,
+          del.status === 204 && status.data?.enrolled === false, { delete: del.status, ownerStatus: status.data });
+      } catch (e) {
+        check(`cleanup. ${acct.label}: the voice print this run enrolled is deleted again`, false, (e as Error).message);
+      }
+    }
+  })();
+  return cleaning;
+}
+
+// The default handler would kill the process with the conversation still
+// billed. `once`: a second signal finds no handler and leaves at once.
+for (const signal of ['SIGINT', 'SIGTERM'] as const) {
+  process.once(signal, () => {
+    console.log(`\n  ${signal}: cleaning up before leaving (again to leave at once)`);
+    void cleanup().finally(() => process.exit(130));
+  });
+}
+
 async function main() {
   console.log(`\nInterpreter E2E → ${BASE_URL}\n`);
   const clips = loadFixtures();
@@ -641,6 +702,7 @@
   const bots: Bot[] = [];
   // Every conversation a create answered with, so the cleanup can end what the run left open.
   const openSessions = new Set<string>();
+  run = { host: A, accounts, bots, openSessions };
   const noteSession = (res: AxiosResponse) => {
     if (ok2xx(res) && typeof res.data?.sessionId === 'string') openSessions.add(res.data.sessionId);
   };
@@ -947,34 +1009,7 @@
       throw e;
     }
   } finally {
-    // Each step on its own: one failure must not skip the rest. The end
-    // comes first: it closes the host's billing and deletes the room.
-    for (const id of openSessions) {
-      try {
-        const r = await http.post(`/interpreter/sessions/${id}/end`, {}, { ...auth(A.token), timeout: END_TIMEOUT_MS });
-        console.log(`  cleanup: end conversation ${id} → ${r.status}`);
-      } catch (e) {
-        console.log(`  cleanup: end conversation ${id} → error: ${(e as Error).message}`);
-      }
-    }
-    for (const bot of bots) {
-      try {
-        await bot.close();
-      } catch (e) {
-        console.log(`  cleanup: ${bot.label}'s bot → error: ${(e as Error).message}`);
-      }
-    }
-    for (const acct of accounts) {
-      if (!acct.enrolledByRun) continue;
-      try {
-        const del = await http.delete('/voice-gate/owner', auth(acct.token));
-        const status = await http.get('/voice-gate/owner-status', auth(acct.token));
-        check(`cleanup. ${acct.label}: the voice print this run enrolled is deleted again`,
-          del.status === 204 && status.data?.enrolled === false, { delete: del.status, ownerStatus: status.data });
-      } catch (e) {
-        check(`cleanup. ${acct.label}: the voice print this run enrolled is deleted again`, false, (e as Error).message);
-      }
-    }
+    await cleanup();
   }
 
   console.log(`\n${passed} passed, ${failed} failed`);
```

Патч к `interpreter_selftest.ts`:

```diff
--- a/interpreter_selftest.ts
+++ b/interpreter_selftest.ts
@@ -33,8 +33,19 @@
 
 function fail(msg: string, details?: unknown): never {
   console.error(`\n❌ ${msg}`);
-  if (details !== undefined) console.error(details);
+  if (details !== undefined) console.error(redact(details));
   process.exit(1);
+}
+
+/** Output lands in CI logs and chats: no token, whatever field it hides in. */
+function redact(value: unknown): unknown {
+  if (Array.isArray(value)) return value.map(redact);
+  if (value && typeof value === 'object') {
+    return Object.fromEntries(
+      Object.entries(value).map(([k, v]) => [k, /token/i.test(k) ? '<redacted>' : redact(v)]),
+    );
+  }
+  return value;
 }
 
 function engineLine(name: string, result: any): string {
@@ -54,11 +65,8 @@
   });
   const body = res.data;
   if (res.status !== 200) {
-    const hint = res.status === 404
-      ? ': this backend build predates the interpreter'
-      : body?.message === 'interpreter_disabled'
-        ? ': INTERPRETER_ENABLED is not "true" in the backend .env'
-        : '';
+    // Not behind INTERPRETER_ENABLED: the smoke runs on TEST and PROD while it is off.
+    const hint = res.status === 404 ? ': this backend build predates the interpreter' : '';
     fail(`GET /interpreter/selftest → ${res.status}${hint}`, body);
   }
   if (body?.ok !== true || body?.simultaneous?.ok !== true || body?.phrase?.ok !== true) {
```

- [ ] **Step 2: Типы и сигнал**

```bash
cd ~/Downloads/taler_id_tests
npx tsc --noEmit -p tsconfig.json 2>&1 | grep -cE "interpreter_test|interpreter_selftest" ; true
# Ctrl-C до входа: сервер, который не отвечает, держит набор на логине
node -e "require('http').createServer(() => {}).listen(18999)" & SRV=$!
BASE_URL=http://127.0.0.1:18999 ./node_modules/.bin/ts-node interpreter_test.ts & RUN=$!
sleep 6; kill -INT $RUN; wait $RUN; echo exit=$?; kill $SRV
```

Ожидается: `0`; строка `SIGINT: cleaning up before leaving (again to leave at once)`; `exit=130`.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add interpreter_test.ts interpreter_selftest.ts
git commit -m "test: test:interpreter — уборка по Ctrl-C; смоук не печатает токены" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 21: CLAUDE.md — новые наборы в обязательном списке

**Files:**
- Modify: `/Users/dmitry/talerid/CLAUDE.md` (не в git; правка — обычным редактированием файла)

- [ ] **Step 1: Две записи перед разделом про TEST**

Перед строкой

```
### После деплоя на TEST (aeza `138.124.61.221`) — прогнать те же тесты на TEST:
```

вставить:

````md
### 21. Разговор с переводом (DEV)
E2E: два тестовых аккаунта записывают образцы голоса фикстурами → A создаёт разговор (QR-код), B входит по коду → два бота на `@livekit/rtc-node` с токенами от бэкенда → перевод в обе стороны, адресность дорожек `interp-for-<я>` и субтитров, голос собеседника в чужом микрофоне не переводится → списание с хоста → завершение, комната удалена, повтор идемпотентен → уборка.
```bash
cd ~/Downloads/taler_id_tests && npm run test:interpreter
```
- Около 60 проверок, пара минут, настоящие сессии OpenAI (центы).
- Образцы голоса записывает сам и удаляет только те, что записал. Если у тестового аккаунта уже был образец живого человека — проверки перевода упадут тишиной с подсказкой «`DELETE /voice-gate/owner` и перезапустить».
- Ctrl-C проходит ту же уборку: завершает разговор (с хоста идёт поминутное списание), отключает ботов, удаляет записанные образцы. Второй Ctrl-C выходит сразу.
- На TEST — `test:interpreter:prod`, на PROD набора нет. Оба — только после выкатки фичи на эти окружения (план 3).

### 22. Самопроверка переводчика разговора (post-deploy, ~10 с)
Вход тестовым аккаунтом → `GET /interpreter/selftest` → агент открывает обе сессии OpenAI, как в разговоре: `gpt-realtime-translate` и фразовую модель (`INTERPRETER_FALLBACK_MODEL`, датированный снимок — его OpenAI может убрать). Работает и при выключенном `INTERPRETER_ENABLED`.
```bash
cd ~/Downloads/taler_id_tests && npm run test:interpreter-selftest          # DEV
```
- `:prod` (TEST) и `:talerid` (PROD) — после выкатки агента с разговором на эти окружения.
- Строка `FATAL interpreter: no translation for N s of speech in <комната> <src>→<dst>` в мониторинге: фильтр пропустил речь, а движок не вернул ни звука, ни текста. Не всегда авария — так же выглядит человек, который долго говорит на языке собеседника. Повторяется в разных комнатах — прогнать этот смоук и смотреть ключ и модели OpenAI.

````

Строки батарей TEST и PROD не трогать: там наборы появятся вместе с выкаткой фичи на эти окружения.

- [ ] **Step 2: Проверить**

```bash
grep -n "### 21. Разговор с переводом\|### 22. Самопроверка переводчика разговора" /Users/dmitry/talerid/CLAUDE.md
```

Ожидается: две строки, обе выше раздела «После деплоя на TEST».

---

### Task 22: Выкатка на DEV и проверки на живом стенде

**Выполняет контроллер сам, не исполнитель-подагент: шаги затрагивают общий сервер и требуют решений по ходу.**

- [ ] **Step 1: Спросить пользователя**

Нужно явное «да» сразу на всё:
- пуш ветки `feat/interpreter`;
- слияние её в `dev` и пуш `dev`;
- пуш `main` репозитория `taler_id_tests` (задачи 18–20);
- деплой бэкенда и агента на DEV, правка `.env` бэкенда и агента на DEV.

Без «да» — стоп. TEST и PROD в этот план не входят.

- [ ] **Step 2: Ветки**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter && git push -u origin feat/interpreter
cd /Users/dmitry/taler-id && git fetch origin
git worktree add /tmp/talerid-dev-merge -b tmp-dev-merge origin/dev
cd /tmp/talerid-dev-merge && git merge --no-ff feat/interpreter -m "Merge feat/interpreter into dev" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
git push origin HEAD:dev
cd /Users/dmitry/taler-id && git worktree remove /tmp/talerid-dev-merge && git branch -D tmp-dev-merge
cd ~/Downloads/taler_id_tests && git push origin main
```

Конфликт при слиянии — разобрать вручную, не теряя чужих правок `dev`; при сомнениях — спросить пользователя. Основной чекаут `~/taler-id` не трогать: в нём могут работать другие сессии.

- [ ] **Step 3: Состояние DEV перед деплоем**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/taler-id && git fetch -q && git status -sb | head -1 && npx prisma migrate status 2>&1 | tail -4"'
```

Ожидается: чистое дерево на `dev`, не применена только `20261101120000_interpreter`.

- [ ] **Step 4: `.env` бэкенда и агента на DEV**

Скриптом через stdin, чтобы секрет не появился ни в командной строке, ни на экране. Сначала — резервные копии.

```bash
cat > /tmp/interp-dev-env.sh <<'EOF'
set -e
cd ~/taler-id
STAMP=$(date +%Y%m%d-%H%M%S)
cp .env .env.bak-interpreter-$STAMP
cp livekit-agent/.env livekit-agent/.env.bak-interpreter-$STAMP
if ! grep -q '^INTERPRETER_SHARED_SECRET=.' .env; then
  SECRET=$(openssl rand -hex 32)
  printf '\nINTERPRETER_ENABLED=true\nINTERPRETER_SHARED_SECRET=%s\n' "$SECRET" >> .env
  printf '\nINTERPRETER_SHARED_SECRET=%s\n' "$SECRET" >> livekit-agent/.env
fi
grep -c '^INTERPRETER_SHARED_SECRET=.' .env livekit-agent/.env
grep '^INTERPRETER_ENABLED=' .env
echo "backend AI_AGENT_URL: $(grep '^AI_AGENT_URL=' .env | cut -d= -f2- || true)"
echo "agent BACKEND_URL host: $(grep '^BACKEND_URL=' livekit-agent/.env | cut -d= -f2- | sed -E 's#^(https?://[^/]+).*#\1#' || true)"
EOF
ssh dvolkov@77.73.131.137 'ssh dev-backend bash -s' < /tmp/interp-dev-env.sh; rm /tmp/interp-dev-env.sh
```

Ожидается: оба файла содержат секрет (по `1`), `INTERPRETER_ENABLED=true`. `BACKEND_URL` агента должен вести на бэкенд DEV (`https://staging.id.taler.tirol` или локальный адрес DEV). Если он ведёт на `id.taler.tirol` (это TEST) — стоп и вопрос пользователю: туда же сейчас уходят отчёты записи встреч.

- [ ] **Step 5: Деплой бэкенда на DEV**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/taler-id && git pull -q && npm ci --loglevel=error && npx prisma migrate deploy && npx prisma generate >/dev/null && npm run build >/dev/null && pm2 restart taler-id-dev --update-env && sleep 8 && pm2 logs taler-id-dev --lines 120 --nostream 2>&1 | grep -iE \"InterpreterController|Nest application successfully started|error\" | tail -15"'
```

Ожидается: `Mapped {/interpreter/...}` для всех ручек, `Nest application successfully started`, без ошибок внедрения зависимостей. Модуль впервые собирается целиком именно здесь — Jest его собирал с подменённым `BillingModule`.

- [ ] **Step 6: Агент на DEV**

Агент на DEV работает из того же чекаута, `~/taler-id/livekit-agent`.

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/taler-id/livekit-agent && npm ci --loglevel=error && node -e \"require(\x27dotenv\x27).config(); const s=require(\x27fs\x27).readFileSync(\x27index.js\x27,\x27utf8\x27); for (const [,m] of s.matchAll(/require\\(\x27(\\.\\/[^\x27]+)\x27\\)/g)) require(m); console.log(\x27modules-ok\x27)\" && pm2 restart livekit-ai-agent --update-env && sleep 5 && pm2 logs livekit-ai-agent --lines 40 --nostream 2>&1 | tail -8"'
```

Ожидается: `modules-ok`, агент перезапустился без ошибок.

- [ ] **Step 7: Сквозные наборы на DEV**

С мака DEV по HTTPS сейчас недоступен — наборы гоняются с бот-сервера из временного клона.

```bash
ssh dvolkov@77.73.131.137 'export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh >/dev/null; D=$(mktemp -d ~/tid-interp-run.XXXX) && git clone -q --depth 1 git@github.com:dvvolkovv/taler_id_tests.git $D && cd $D && npm ci --loglevel=error && npm run test:interpreter-selftest; npm run test:interpreter; R=$?; cd ~ && rm -rf $D; exit $R'
```

Ожидается: самопроверка `ok: true` у обоих движков; `test:interpreter` — все проверки зелёные. Падение — разобрать по тексту проверки, починить отдельной задачей с ревью (как b-задачи плана 1) и повторить.

- [ ] **Step 8: Обязательная батарея DEV**

Наборы 4–20 из CLAUDE.md против DEV — тем же временным клоном на бот-сервере, по одному, с паузами 20 с (лимит входов в nginx). `test:billing` теперь ждёт 7 тумблеров. Известное: `test:room-chat` с бот-сервера упирается в общий троттлер — перепроверять с мака, когда DEV станет доступен оттуда.

- [ ] **Step 9: Стенд — замер ускорения фразового движка**

Тот же конвейер, что в задаче 20 плана 1, только пара ru-sk:

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter
COPYFILE_DISABLE=1 tar --no-mac-metadata -czf - --exclude node_modules --exclude bench/reports -C livekit-agent . \
  | ssh dvolkov@77.73.131.137 'ssh dev-backend "rm -rf ~/interp-bench && mkdir -p ~/interp-bench && tar xzf - -C ~/interp-bench && cd ~/interp-bench && npm ci --loglevel=error >/dev/null && node bench/interpreter-bench.js --env ~/taler-id/livekit-agent/.env --pair ru-sk --out bench/reports 2>&1 | grep -A12 \"Задержка\""'
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/interp-bench/bench/reports && tar czf - ."' | tar xzf - -C livekit-agent/bench/reports
ssh dvolkov@77.73.131.137 'ssh dev-backend "rm -rf ~/interp-bench && echo cleaned"'
cd livekit-agent && git add bench/reports && git commit -m "test(interpreter): стенд ru-sk после времени по звуку во фразовом движке" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

Ожидается: задержка фразового направления (ru→sk) меньше прежних 7,0–7,5 с. Сравнить с отчётом `2026-11-01-04-09-ru-sk.md`.

- [ ] **Step 10: Мониторинг видит `FATAL interpreter:`**

Задача из спеки (раздел «Выкатка», п. 5). Только чтение:

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "sudo -n cat /etc/taler-monitor/push.env 2>/dev/null | grep -E \"^(SYSTEMD_UNITS|DOCKER_CONTAINERS|PM2|LOG|SIGNAL)\" ; grep -n \"FATAL\" /opt/taler-monitor/push.sh 2>/dev/null | head -5"'
```

Выяснить, попадают ли строки pm2-журнала `livekit-ai-agent` с `FATAL` в мониторинг (как `FATAL replication-watchdog`). Не попадают — рассказать пользователю и предложить подключение отдельной задачей в репозитории `taler_monitor`; конфиг мониторинга без его «да» не менять.

- [ ] **Step 11: Отчёт пользователю**

Коротко: что выкачено на DEV, итоги наборов, задержка фразового направления до и после, состояние мониторинга, что не проверено.

---

### Task 23: Контрольная точка перед планом 3

Дать пользователю сводку по-русски:
- бэкенд разговора на DEV: ручки, оплата хостом, сверка, `RoomAccessGuard`;
- итоги `test:interpreter` и самопроверки, обязательной батареи DEV;
- ускорение фразового движка в цифрах стенда;
- мониторинг `FATAL interpreter:` — подключён или нет;
- что осталось на план 3: мобилка (экраны, QR, сканер, комната, субтитры, ассистент `open_interpreter`, таймаут входа ≥ 40 с), dev-сборки, ручная проверка двумя разными людьми, выкатка на TEST и PROD.

Затем спросить: пишем план 3 (мобилка) или что-то меняем. План 3 не начинать без ответа.
