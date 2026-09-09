# Пароль на встречу — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Пароль на встречу становится доступен человеку: его можно задать при создании комнаты и ввести при входе через браузер.

**Architecture:** Механизм на бэкенде уже готов — пароль хешируется bcrypt при создании и сверяется при входе по коду, а `GET /voice/rooms/public/:code` отдаёт `requiresPassword`. Работа сводится к трём точкам: поле ввода в веб-комнате, необязательное поле при создании в двух местах мобильного приложения, и одна проверка на бэкенде, освобождающая создателя от собственного пароля. Модель доступа не меняется.

**Tech Stack:** NestJS + bcrypt (бэкенд), ванильный JS (`public/room.html`), Flutter (`taler_id_mobile`), Jest, ts-node-набор в `taler_id_tests`.

**Спека:** `docs/superpowers/specs/2026-09-09-room-password-design.md`

---

## Структура файлов

**Бэкенд (`taler_id`):**
- Изменить `src/voice/voice.service.ts` — `joinPublicRoomAuth`: создатель не вводит собственный пароль.
- Создать `src/voice/voice.service.password.spec.ts` — правила пароля отдельным файлом: в модуле уже принята схема «один spec на тему» (`voice.service.chat.spec.ts`, `voice.service.join.spec.ts`), и мешать пароль в существующие не нужно.
- Изменить `public/room.html` — поле пароля на экране входа и разделение причин отказа.

**Мобилка (`taler_id_mobile`):**
- Изменить `lib/features/call_history/presentation/screens/call_history_screen.dart` — поле пароля при создании быстрой комнаты и показ пароля рядом со ссылкой.
- Изменить `lib/features/calendar/presentation/screens/calendar_screen.dart` — то же для встречи из календаря.

**Тесты (`taler_id_tests`):**
- Изменить `room_chat_test.ts` — защищённая комната в существующем наборе.

---

## Task 1: Создатель не вводит собственный пароль

**Files:**
- Modify: `src/voice/voice.service.ts` (`joinPublicRoomAuth`, проверка `room.passwordHash`)
- Test: `src/voice/voice.service.password.spec.ts`

- [ ] **Step 1: Написать падающие тесты**

Создать `src/voice/voice.service.password.spec.ts`:

```ts
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { VoiceService } from './voice.service';

describe('VoiceService — пароль комнаты', () => {
  let service: VoiceService;
  let prisma: any;
  let hash: string;

  const room = (over: Record<string, unknown> = {}) => ({
    code: 'abc123',
    roomName: 'tmp-1',
    type: 'temporary',
    isActive: true,
    expiresAt: null,
    creatorId: 'creator-1',
    passwordHash: hash,
    ...over,
  });

  beforeAll(async () => {
    hash = await bcrypt.hash('верный', 10);
  });

  beforeEach(() => {
    prisma = {
      publicRoom: { findUnique: jest.fn(), update: jest.fn() },
      user: { findUnique: jest.fn().mockResolvedValue(null) },
    };
    service = new VoiceService(
      prisma,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
    // Комнату в LiveKit создавать незачем — проверяем только правила пароля.
    (service as any).rooms = { createRoom: jest.fn().mockResolvedValue(undefined) };
    (service as any).ruRooms = { createRoom: jest.fn().mockResolvedValue(undefined) };
  });

  it('создатель входит в свою комнату, не вводя собственный пароль', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'creator-1', undefined, 'sess-1'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('чужой залогиненный без пароля не входит', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'somebody-else', undefined, 'sess-1'),
    ).rejects.toThrow(ForbiddenException);
  });

  it('чужой залогиненный с неверным паролем не входит', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'somebody-else', 'неверный', 'sess-1'),
    ).rejects.toThrow(ForbiddenException);
  });

  it('чужой залогиненный с верным паролем входит', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoomAuth('abc123', 'somebody-else', 'верный', 'sess-1'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('гость с верным паролем входит, с неверным — нет', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'верный'),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });

    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', 'неверный'),
    ).rejects.toThrow(ForbiddenException);
  });

  it('гостю освобождение создателя не достаётся: у гостя нет учётной записи', async () => {
    // Защита от «упростим»: если проверку пароля пропускать по совпадению
    // creatorId с чем угодно, гость без пароля начнёт входить в чужую комнату.
    prisma.publicRoom.findUnique.mockResolvedValue(room());
    await expect(
      service.joinPublicRoom('abc123', 'Гость', undefined),
    ).rejects.toThrow(ForbiddenException);
  });

  it('в комнате без пароля пароль никому не нужен', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(room({ passwordHash: null }));
    await expect(
      service.joinPublicRoom('abc123', 'Гость', undefined),
    ).resolves.toMatchObject({ roomName: 'tmp-1' });
  });

  it('несуществующая комната — 404, а не отказ по паролю', async () => {
    prisma.publicRoom.findUnique.mockResolvedValue(null);
    await expect(
      service.joinPublicRoomAuth('нет-такой', 'creator-1', undefined, 'sess-1'),
    ).rejects.toThrow(NotFoundException);
  });
});
```

- [ ] **Step 2: Запустить и убедиться, что падает**

Run: `cd ~/Downloads/taler_id && npx jest src/voice/voice.service.password.spec.ts`
Expected: FAIL — первый тест («создатель входит…») падает с `ForbiddenException`, остальные проходят: правила для чужих уже работают.

- [ ] **Step 3: Реализовать**

В `src/voice/voice.service.ts`, в `joinPublicRoomAuth`, заменить блок проверки пароля:

```ts
    // Создатель не вводит собственный пароль: он его и придумал, а входит
    // по своей же ссылке той же веткой, что и посторонний с кодом.
    // Приглашённые участники звонка сюда не попадают вовсе — они входят
    // через joinRoom, где пароля нет: пароль защищает вход ПО КОДУ комнаты,
    // а не участие в звонке, на который позвали поимённо.
    const isCreator = !!room.creatorId && room.creatorId === userId;
    if (room.passwordHash && !isCreator) {
      if (!password || !(await bcrypt.compare(password, room.passwordHash))) {
        throw new ForbiddenException('Invalid room password');
      }
    }
```

⚠️ Проверка `!!room.creatorId` не косметика: у комнаты `creatorId` может быть пустым, и без этой половины условия `undefined === undefined` пропустило бы в комнату кого угодно.

- [ ] **Step 4: Запустить и убедиться, что проходит**

Run: `cd ~/Downloads/taler_id && npx jest src/voice`
Expected: PASS — новый файл целиком и все прежние тесты модуля.

- [ ] **Step 5: Мутировать собственные утверждения**

Проверить, что тесты падают при сломанном коде, а не украшают отчёт:
- убрать `&& !isCreator` → падает тест про создателя;
- заменить условие на `room.creatorId === userId` без `!!room.creatorId` и подставить комнату с `creatorId: null` — этого случая в наборе нет, добавить его отдельным тестом, если мутация выживает;
- убрать всю проверку пароля → падают тесты про чужого и про гостя.

- [ ] **Step 6: Коммит**

```bash
cd ~/Downloads/taler_id
git add src/voice/voice.service.ts src/voice/voice.service.password.spec.ts
git commit -m "feat(voice): создатель не вводит собственный пароль комнаты"
```

---

## Task 2: Ввод пароля в веб-комнате

**Files:**
- Modify: `public/room.html` — разметка экрана входа (~строки 651-668), загрузка описания комнаты, функция `joinRoom`

- [ ] **Step 1: Добавить поле в разметку**

В блок `<div id="step-join" class="step">`, сразу после `<div class="input-wrap">` с полем имени, добавить:

```html
      <div class="input-wrap" id="password-wrap" style="display:none">
        <input type="password" id="room-password" placeholder="Пароль встречи" maxlength="64" autocomplete="off">
      </div>
```

- [ ] **Step 2: Показывать поле, когда комната под паролем**

В функции загрузки описания комнаты, рядом со строкой
`document.getElementById('room-title-text').textContent = roomTitle;`
добавить:

```js
        // Сервер сам сообщает, нужен ли пароль, — гадать по отказу не нужно.
        if (data.requiresPassword) {
          document.getElementById('password-wrap').style.display = '';
        }
```

- [ ] **Step 3: Отправлять пароль и различать причины отказа**

Заменить тело `joinRoom` от проверки имени до блока `catch` на:

```js
      const pwdWrap = document.getElementById('password-wrap');
      const needsPassword = pwdWrap.style.display !== 'none';
      const password = document.getElementById('room-password').value.trim();
      if (needsPassword && !password) {
        document.getElementById('join-error').textContent = 'Введите пароль встречи';
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/voice/rooms/public/${roomCode}/join`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(needsPassword ? { name, password } : { name }),
        });
        // 403 — это неверный пароль, и только он. Показывать здесь «проверьте
        // соединение» нельзя: человек будет жать кнопку бесконечно, потому что
        // сообщение говорит о связи, а исправить надо пароль.
        if (res.status === 403) {
          btn.disabled = false;
          btn.textContent = 'Войти в комнату';
          document.getElementById('join-error').textContent = 'Неверный пароль';
          return;
        }
        if (!res.ok) throw new Error('join failed');
        const data = await res.json();
        await connectToRoom(data.token);
      } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Войти в комнату';
        document.getElementById('join-error').textContent = 'Не удалось подключиться. Попробуйте ещё раз.';
      }
```

- [ ] **Step 4: Проверить руками на DEV**

Создать две комнаты — с паролем и без:

```bash
B=https://staging.id.taler.tirol
TOK=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')
curl -s -X POST $B/voice/rooms/temporary -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"title":"с паролем","password":"секрет"}'
curl -s -X POST $B/voice/rooms/temporary -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"title":"без пароля"}'
```

⚠️ На `/auth/login` в nginx стоит лимит 10 запросов в минуту — логиниться один раз и переиспользовать токен.

Свой `room.html` выложить на DEV и вернуть обратно после проверки:
```bash
scp public/room.html dvolkov@89.169.55.217:~/taler-id/public/room.html
# после проверки:
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git checkout public/room.html'
```

Что увидеть (наблюдения, не ожидания):
- в комнате без пароля поля нет вовсе, вход работает как раньше;
- в комнате с паролем поле есть, пустое поле даёт «Введите пароль встречи» и запрос не уходит;
- неверный пароль даёт «Неверный пароль», а не сообщение про соединение;
- верный пароль пускает в комнату.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id
git add public/room.html
git commit -m "feat(room): ввод пароля встречи в веб-комнате"
```

---

## Task 3: Пароль при создании быстрой комнаты

**Files:**
- Modify: `lib/features/call_history/presentation/screens/call_history_screen.dart` (`_createTemporaryRoom` ~строка 237, `_showTempRoomSheet` ~строка 260)

- [ ] **Step 1: Спросить пароль перед созданием**

Заменить начало `_createTemporaryRoom` так, чтобы перед запросом показывался диалог с необязательным полем. Поле пустое по умолчанию — привычный сценарий не меняется:

```dart
  Future<void> _createTemporaryRoom() async {
    if (_creatingTemp) return;
    final l10n = AppLocalizations.of(context)!;
    final passwordCtrl = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.roomCreateTitle),
        content: TextField(
          controller: passwordCtrl,
          autofocus: false,
          decoration: InputDecoration(
            labelText: l10n.roomPasswordOptional,
            helperText: l10n.roomPasswordHelper,
          ),
          maxLength: 64,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(l10n.cancel)),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: Text(l10n.create)),
        ],
      ),
    );
    if (confirmed != true) {
      passwordCtrl.dispose();
      return;
    }
    final password = passwordCtrl.text.trim();
    passwordCtrl.dispose();

    setState(() => _creatingTemp = true);
    try {
      final data = await sl<DioClient>().post<Map<String, dynamic>>(
        '/voice/rooms/temporary',
        data: password.isEmpty ? null : {'password': password},
        fromJson: (d) => Map<String, dynamic>.from(d as Map),
      );
      final code = data['code'] as String;
      final link = data['link'] as String;
      if (mounted) _showTempRoomSheet(code, link, password);
```

Дальше `catch` и `finally` остаются как были.

- [ ] **Step 2: Показать пароль рядом со ссылкой**

`_showTempRoomSheet` получает третий параметр и показывает пароль **отдельной строкой с отдельной кнопкой копирования**:

```dart
  void _showTempRoomSheet(String code, String link, [String password = '']) {
```

и внутри, после блока со ссылкой, добавить:

```dart
            if (password.isNotEmpty) ...[
              const SizedBox(height: 12),
              // Пароль копируется отдельно от ссылки намеренно: если положить
              // его в ту же строку, человек отправит всё одним сообщением и
              // защита перестанет что-либо значить. А если не показать вовсе —
              // отправит ссылку, а пароль оставит себе, и встреча не состоится.
              Row(
                children: [
                  Expanded(child: Text('${l10n.roomPasswordLabel}: $password')),
                  IconButton(
                    icon: const Icon(Icons.copy),
                    tooltip: l10n.copy,
                    onPressed: () {
                      Clipboard.setData(ClipboardData(text: password));
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(l10n.roomPasswordCopied)),
                      );
                    },
                  ),
                ],
              ),
            ],
```

- [ ] **Step 3: Добавить строки локализации**

В `lib/l10n/app_ru.arb`:
```json
  "roomCreateTitle": "Новая комната",
  "roomPasswordOptional": "Пароль (необязательно)",
  "roomPasswordHelper": "Гости введут его при входе по ссылке",
  "roomPasswordLabel": "Пароль",
  "roomPasswordCopied": "Пароль скопирован",
```
В `lib/l10n/app_en.arb`:
```json
  "roomCreateTitle": "New room",
  "roomPasswordOptional": "Password (optional)",
  "roomPasswordHelper": "Guests will enter it when joining by link",
  "roomPasswordLabel": "Password",
  "roomPasswordCopied": "Password copied",
```
Затем `flutter gen-l10n`.

⚠️ Ключи `cancel`, `create`, `copy` в файлах уже есть — проверить перед добавлением, чтобы не завести дубликаты.

- [ ] **Step 4: Проверить сборку и тесты**

Run: `cd ~/Downloads/taler_id_mobile && flutter analyze lib/features/call_history/ && flutter test`
Expected: новых замечаний анализатора на тронутом файле нет; тесты зелёные.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/features/call_history/ lib/l10n/
git commit -m "feat(voice): пароль при создании быстрой комнаты"
```

---

## Task 4: Пароль при создании встречи из календаря

**Files:**
- Modify: `lib/features/calendar/presentation/screens/calendar_screen.dart` (`_generateMeetingLink` ~строка 1322, и вызов `/voice/rooms/public` ~строка 559)

- [ ] **Step 1: Спросить пароль и передать его**

В `_generateMeetingLink` перед запросом добавить тот же диалог, что в Task 3 (строки локализации уже добавлены там же, заново не заводить), и передать пароль:

```dart
      final room = await sl<DioClient>().post<Map<String, dynamic>>(
        '/voice/rooms/public',
        data: {
          'title': _titleCtrl.text.trim().isNotEmpty
              ? _titleCtrl.text.trim()
              : AppLocalizations.of(context)!.calendarMeeting,
          if (password.isNotEmpty) 'password': password,
        },
        fromJson: (d) => Map<String, dynamic>.from(d as Map),
      );
```

- [ ] **Step 2: Положить пароль в описание встречи рядом со ссылкой**

Там, где ссылка подставляется в описание события, дописать пароль отдельной строкой — иначе приглашённые получат ссылку и не получат пароль:

```dart
      if (password.isNotEmpty) {
        // Отдельной строкой, а не внутри ссылки: ссылка уходит в приглашение
        // календаря, и пароль в ней сделал бы защиту бессмысленной.
        link = '$link\n${AppLocalizations.of(context)!.roomPasswordLabel}: $password';
      }
```

- [ ] **Step 3: Второй вызов создания оставить без пароля**

Вызов на строке ~559 (`'/voice/rooms/public', data: {'title': …}`) создаёт комнату для встречи, поднятой из ассистента, и диалога там нет. Оставить как есть — комната создаётся без пароля. Дописать однострочный комментарий, что это осознанно, а не пропущено.

- [ ] **Step 4: Проверить**

Run: `cd ~/Downloads/taler_id_mobile && flutter analyze lib/features/calendar/ && flutter test`
Expected: новых замечаний нет, тесты зелёные.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/features/calendar/
git commit -m "feat(calendar): пароль при создании встречи"
```

---

## Task 5: Защищённая комната в e2e-наборе

**Files:**
- Modify: `~/Downloads/taler_id_tests/room_chat_test.ts`

⚠️ В этом репозитории лежат чужие незакоммиченные правки — `git add -A` не делать, добавлять только свой файл.

- [ ] **Step 1: Дописать проверки**

Перед блоком `finally` добавить:

```ts
    // Пароль на комнату: вход по коду.
    const protectedRoom = await http.post('/voice/rooms/temporary',
      { title: 'с паролем', password: 'секрет-е2е' }, auth(userToken));
    check('17. комната с паролем создана',
      protectedRoom.status === 200 || protectedRoom.status === 201, protectedRoom.data);
    const pCode = protectedRoom.data?.code as string;

    const info = await http.get(`/voice/rooms/public/${pCode}`);
    check('17b. описание комнаты сообщает о пароле', info.data?.requiresPassword === true, info.data);

    const noPwd = await http.post(`/voice/rooms/public/${pCode}/join`, { name: 'Гость' });
    check('18. гость без пароля → 403', noPwd.status === 403, noPwd.status);

    const wrongPwd = await http.post(`/voice/rooms/public/${pCode}/join`, { name: 'Гость', password: 'не тот' });
    check('18b. гость с неверным паролем → 403', wrongPwd.status === 403, wrongPwd.status);

    const rightPwd = await http.post(`/voice/rooms/public/${pCode}/join`, { name: 'Гость', password: 'секрет-е2е' });
    check('18c. гость с верным паролем входит', typeof rightPwd.data?.token === 'string', rightPwd.status);

    const creator = await http.post(`/voice/rooms/public/${pCode}/join-auth`, {}, auth(userToken));
    check('19. создатель входит без пароля', typeof creator.data?.token === 'string', creator.status);

    await http.delete(`/voice/rooms/temporary/${pCode}`, auth(userToken));
```

- [ ] **Step 2: Прогнать против DEV**

Run: `cd ~/Downloads/taler_id_tests && npm run test:room-chat`
Expected: все прежние проверки плюс шесть новых, `0 failed`.

- [ ] **Step 3: Убедиться, что за собой убрано**

Run: `curl -s -o /dev/null -w '%{http_code}\n' https://staging.id.taler.tirol/voice/rooms/public/<код из вывода>`
Expected: `404` — обе временные комнаты удалены.

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add room_chat_test.ts
git commit -m "test: пароль комнаты — вход гостя и создателя"
```

---

## Task 6: Раскатка

- [ ] **Step 1: DEV**

```bash
cd ~/Downloads/taler_id && git push origin dev
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
cd ~/Downloads/taler_id_tests && npm run test:room-chat
```

- [ ] **Step 2: TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && npx prisma migrate status && git pull && npm run build && pm2 restart taler-id'
cd ~/Downloads/taler_id_tests && npm run test:room-chat:prod
```
Миграций эта работа не добавляет — `migrate status` должен подтвердить, что схема актуальна.

- [ ] **Step 3: PROD — только по явной команде пользователя**

```bash
ssh dvolkov@77.73.131.137 'ssh do-app-1 "cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id && sleep 8 && curl -s -o /dev/null -w \"health:%{http_code}\n\" http://localhost:3000/health"'
# дождаться health:200, затем то же на do-app-2
cd ~/Downloads/taler_id_tests && npm run test:room-chat:talerid
```
⚠️ После перезапуска ноде нужно больше шести секунд: первая проверка может дать `000`, это не отказ. Подождать и проверить повторно.

- [ ] **Step 4: Мобильный релиз**

Отдельным шагом и только когда версия понадобится пользователям: слить `dev` в `main`, поднять `pubspec`, собрать артефакты, и **только после того как они лягут на место** — объявить версию в `app.controller.ts` и `APP_RELEASES`.
