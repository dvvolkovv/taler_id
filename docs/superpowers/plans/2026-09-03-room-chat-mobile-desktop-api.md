# Чат в комнате: мобилка, десктоп и серверная ручка — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Дать участникам звонка переписываться в комнате с любого клиента — браузер, телефон, десктоп — плюс серверную ручку, через которую в чат может писать ассистент.

**Architecture:** Протокол не меняется: пакет `{type:'chat_message', text, name, ts, msgId}` в data-канале LiveKit, `reliable`. Веб уже умеет отправку и приём. Добавляются три отправителя/получателя: Flutter-приложение (один экран звонка на мобилку и десктоп), серверный `RoomServiceClient.sendData`, и tool голосового ассистента поверх новой ручки. Чат эфемерный — истории нет.

**Tech Stack:** NestJS + livekit-server-sdk 2.15 (бэкенд), Flutter + livekit_client (приложение), ванильный JS (`public/room.html`), Jest (бэкенд), flutter_test (приложение), node-скрипты в `taler_id_tests` (E2E).

**Спека:** `docs/superpowers/specs/2026-09-03-room-chat-mobile-desktop-api-design.md`

---

## Структура файлов

**Бэкенд (`taler_id`):**
- Изменяется: `src/voice/voice.service.ts` — метод `sendRoomChatMessage`
- Изменяется: `src/voice/voice.controller.ts` — маршрут `POST rooms/:roomName/chat`
- Создаётся: `src/voice/voice.service.chat.spec.ts` — юнит-тесты метода
- Изменяется: `public/room.html` — отправка чата через `broadcastData`

**Приложение (`taler_id_mobile`):**
- Создаётся: `lib/features/voice/presentation/controllers/room_chat_controller.dart` — состояние чата
- Создаётся: `lib/features/voice/presentation/widgets/room_chat_panel.dart` — панель
- Изменяется: `lib/features/voice/presentation/screens/voice_call_screen.dart` — приём, отправка, кнопка, подключение панели
- Изменяется: `lib/l10n/app_ru.arb`, `lib/l10n/app_en.arb` — строки
- Изменяется: `lib/features/assistant/tools/assistant_tools_schema.dart` — объявление tool
- Изменяется: `lib/features/assistant/tools/assistant_tools_executor.dart` — исполнение tool
- Создаётся: `test/voice/room_chat_controller_test.dart`
- Создаётся: `test/voice/room_chat_panel_test.dart`

**E2E (`taler_id_tests`):**
- Создаётся: `room_chat_test.ts` + записи `test:room-chat` и `test:room-chat:prod` в `package.json`

---

## Task 1: Метод сервиса `sendRoomChatMessage`

**Files:**
- Modify: `src/voice/voice.service.ts`
- Test: `src/voice/voice.service.chat.spec.ts` (создать)

Метод должен слать пакет тем же клиентом, который выбирает `sfuFor(roomName)` — иначе для CIS-комнат (`call-ru-…`) сообщение уйдёт не на тот SFU.

- [ ] **Шаг 1: Написать падающий тест**

Создать `src/voice/voice.service.chat.spec.ts`. Конструирование сервиса напрямую — как в существующем `voice.service.join.spec.ts`; приватные клиенты подменяются после создания.

```ts
import { BadRequestException } from '@nestjs/common';
import { VoiceService } from './voice.service';

describe('VoiceService.sendRoomChatMessage', () => {
  let service: VoiceService;
  let euSendData: jest.Mock;
  let ruSendData: jest.Mock;

  const decode = (mock: jest.Mock) =>
    JSON.parse(Buffer.from(mock.mock.calls[0][1]).toString('utf8'));

  beforeEach(() => {
    service = new VoiceService(
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );
    euSendData = jest.fn().mockResolvedValue(undefined);
    ruSendData = jest.fn().mockResolvedValue(undefined);
    (service as any).rooms = { sendData: euSendData };
    (service as any).ruRooms = { sendData: ruSendData };
  });

  it('публикует пакет chat_message в комнату', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');

    expect(euSendData).toHaveBeenCalledTimes(1);
    expect(euSendData.mock.calls[0][0]).toBe('call-42');

    const packet = decode(euSendData);
    expect(packet.type).toBe('chat_message');
    expect(packet.text).toBe('Привет');
    expect(packet.name).toBe('Ассистент');
    expect(typeof packet.ts).toBe('number');
    expect(typeof packet.msgId).toBe('string');
  });

  it('шлёт надёжным каналом, а не lossy', async () => {
    await service.sendRoomChatMessage('call-42', 'Привет', 'Ассистент');
    // DataPacket_Kind.RELIABLE === 0 в livekit-server-sdk
    expect(euSendData.mock.calls[0][2]).toBe(0);
  });

  it('CIS-комнату обслуживает российский SFU', async () => {
    await service.sendRoomChatMessage('call-ru-7', 'Привет', 'Ассистент');
    expect(ruSendData).toHaveBeenCalledTimes(1);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('обрезает пробелы по краям', async () => {
    await service.sendRoomChatMessage('call-42', '  Привет  ', 'Ассистент');
    expect(decode(euSendData).text).toBe('Привет');
  });

  it('отказывает на пустом тексте и ничего не шлёт', async () => {
    await expect(
      service.sendRoomChatMessage('call-42', '   ', 'Ассистент'),
    ).rejects.toThrow(BadRequestException);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('отказывает на тексте длиннее 500 символов', async () => {
    await expect(
      service.sendRoomChatMessage('call-42', 'x'.repeat(501), 'Ассистент'),
    ).rejects.toThrow(BadRequestException);
    expect(euSendData).not.toHaveBeenCalled();
  });

  it('каждый пакет получает свой msgId', async () => {
    await service.sendRoomChatMessage('call-42', 'раз', 'Ассистент');
    await service.sendRoomChatMessage('call-42', 'два', 'Ассистент');
    const first = JSON.parse(
      Buffer.from(euSendData.mock.calls[0][1]).toString('utf8'),
    ).msgId;
    const second = JSON.parse(
      Buffer.from(euSendData.mock.calls[1][1]).toString('utf8'),
    ).msgId;
    expect(first).not.toBe(second);
  });
});
```

- [ ] **Шаг 2: Убедиться, что тест падает**

Run: `cd ~/Downloads/taler_id && npx jest src/voice/voice.service.chat.spec.ts`
Expected: FAIL — `service.sendRoomChatMessage is not a function`

- [ ] **Шаг 3: Добавить импорты в сервис**

В `src/voice/voice.service.ts` расширить существующие импорты:

```ts
import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import {
  AccessToken,
  RoomServiceClient,
  DataPacket_Kind,
} from 'livekit-server-sdk';
```

- [ ] **Шаг 4: Реализовать метод**

Вставить в класс `VoiceService` рядом с `removeParticipant` (около строки 185):

```ts
  /**
   * Публикует сообщение в чат комнаты тем же протоколом, которым обмениваются
   * клиенты: пакет `chat_message` в data-канале LiveKit. Позволяет писать в
   * комнату серверной стороне — например, голосовому ассистенту.
   *
   * Клиент SFU берётся через sfuFor: CIS-комнаты (`call-ru-…`) живут на
   * отдельном сервере, и отправка в `this.rooms` до них не дойдёт.
   */
  async sendRoomChatMessage(
    roomName: string,
    text: string,
    name: string,
  ): Promise<{ ok: true; ts: number }> {
    const trimmed = (text ?? '').trim();
    if (!trimmed) throw new BadRequestException('text is empty');
    if (trimmed.length > 500) {
      throw new BadRequestException('text is longer than 500 characters');
    }

    const ts = Date.now();
    const packet = {
      type: 'chat_message',
      text: trimmed,
      name,
      ts,
      msgId: `server_${uuidv4()}`,
    };

    await this.sfuFor(roomName).client.sendData(
      roomName,
      new TextEncoder().encode(JSON.stringify(packet)),
      DataPacket_Kind.RELIABLE,
      {},
    );

    return { ok: true, ts };
  }
```

- [ ] **Шаг 5: Убедиться, что тесты проходят**

Run: `cd ~/Downloads/taler_id && npx jest src/voice/voice.service.chat.spec.ts`
Expected: PASS, 7 тестов

- [ ] **Шаг 6: Коммит**

```bash
cd ~/Downloads/taler_id
git add src/voice/voice.service.ts src/voice/voice.service.chat.spec.ts
git commit -m "feat(voice): отправка сообщения в чат комнаты со стороны сервера"
```

---

## Task 2: Маршрут `POST /voice/rooms/:roomName/chat`

**Files:**
- Modify: `src/voice/voice.controller.ts` (рядом с блоком Meeting Recorder, около строки 355)

`RoomAccessGuard` уже принимает либо LiveKit-токен, выданный на эту комнату, либо токен Taler ID участника/владельца, и требует параметр `:roomName`. Форма маршрута совпадает — новых правил доступа не появляется.

- [ ] **Шаг 1: Добавить маршрут**

После `getRecorderStatus` вставить:

```ts
  // ─── Чат комнаты ───
  // Тот же протокол, что у клиентов: пакет chat_message в data-канале.
  // Доступ — как у управления записью: RoomAccessGuard.

  @Post('rooms/:roomName/chat')
  @UseGuards(RoomAccessGuard)
  sendRoomChat(
    @Param('roomName') roomName: string,
    @Body() body: { text?: string; name?: string },
  ) {
    return this.service.sendRoomChatMessage(
      roomName,
      body?.text ?? '',
      body?.name?.trim() || 'Ассистент',
    );
  }
```

- [ ] **Шаг 2: Проверить сборку**

Run: `cd ~/Downloads/taler_id && npm run build`
Expected: сборка без ошибок

- [ ] **Шаг 3: Прогнать тесты войса целиком**

Run: `cd ~/Downloads/taler_id && npx jest src/voice`
Expected: PASS, падений нет

Отдельного юнит-теста на маршрут не пишем осознанно: guard не меняется, его поведение уже покрыто `src/voice/guards/room-access.guard.spec.ts`, а то, что маршрут действительно закрыт этим guard'ом и пускает по LiveKit-токену комнаты, проверяется сквозным тестом в Task 9.

- [ ] **Шаг 4: Коммит**

```bash
cd ~/Downloads/taler_id
git add src/voice/voice.controller.ts
git commit -m "feat(voice): ручка POST /voice/rooms/:roomName/chat"
```

---

## Task 3: Веб — отправка чата через `broadcastData`

**Files:**
- Modify: `public/room.html` (функция `sendChatMessage`, около строки 3357)

Две правки, обе про появление новых отправителей.

**Отправка.** Чат публикуется напрямую через `publishData`, минуя `broadcastData()`, — а `msgId` для дедупликации проставляет именно `broadcastData`. Пока отправитель один, это сходит с рук; с появлением приложения и сервера повторы станут заметны.

**Приём.** Ветка приёма гейтится наличием участника-отправителя:

```js
if (msg.type === 'chat_message' && participant) {
```

`RoomServiceClient.sendData` публикует пакет от имени сервера, без publishing participant, поэтому в браузере второй аргумент `RoomEvent.DataReceived` будет `undefined` и серверное сообщение молча отбросится — ручка ответит 200, а в комнате ничего не появится. Имя отправителя сервер всегда кладёт в `msg.name`, так что участник для отображения не нужен. Найдено при реализации Task 1.

- [ ] **Шаг 0: Снять гейт на участника в приёме**

Найти около строки 1242:

```js
            if (msg.type === 'chat_message' && participant) {
              appendChatMessage(msg.name || getDisplayName(participant), msg.text, msg.ts || Date.now(), false);
            }
```

Заменить на:

```js
            if (msg.type === 'chat_message') {
              // Участника может не быть: сервер публикует через
              // RoomServiceClient.sendData от своего имени, без отправителя.
              // Имя в таком пакете всегда лежит в msg.name.
              const who = participant ? getDisplayName(participant) : '';
              appendChatMessage(msg.name || who || 'Taler ID', msg.text, msg.ts || Date.now(), false);
            }
```

- [ ] **Шаг 1: Заменить тело отправки**

Найти в `sendChatMessage` блок:

```js
      try {
        room.localParticipant.publishData(encoder.encode(JSON.stringify(msg)), { reliable: true });
      } catch (e) {
        console.warn('[CHAT] Failed to send:', e);
        return;
      }

      appendChatMessage(msg.name, text, msg.ts, true);
```

Заменить на:

```js
      // broadcastData проставляет msgId — без него приёмная дедупликация
      // не работает, а отправителей теперь трое: веб, приложение и сервер.
      broadcastData(msg);

      appendChatMessage(msg.name, text, msg.ts, true);
```

- [ ] **Шаг 2: Проверить руками в браузере**

Поднять статику и открыть страницу:

```bash
cd ~/Downloads/taler_id/public && python3 -m http.server 8899 --bind 127.0.0.1 &
```

Открыть `http://127.0.0.1:8899/room.html`, в консоли выполнить:

```js
window.room = { localParticipant: { publishData: (d) => console.log('SENT', JSON.parse(new TextDecoder().decode(d))), identity: 'web-1' } };
document.getElementById('chat-input').value = 'проверка';
sendChatMessage();
```

Expected: в консоли `SENT {type: 'chat_message', text: 'проверка', name: …, ts: …, msgId: 'web-1_0'}` — ключевое, что `msgId` присутствует.

Остановить сервер: `pkill -f "http.server 8899"`

- [ ] **Шаг 3: Коммит**

```bash
cd ~/Downloads/taler_id
git add public/room.html
git commit -m "fix(room): чат уходит через broadcastData, чтобы получить msgId"
```

---

## Task 4: Строки локализации

**Files:**
- Modify: `lib/l10n/app_ru.arb` (шаблон — `template-arb-locale: ru`)
- Modify: `lib/l10n/app_en.arb`

Остальные 22 локали заполнять не нужно: в них и сейчас пробелы (в `app_de.arb` не хватает 172 ключей), генератор это допускает.

- [ ] **Шаг 1: Добавить ключи в `app_ru.arb`**

Рядом с `"voiceYou"` (строка 638) добавить:

```json
  "voiceChat": "Чат",
  "voiceChatHint": "Сообщение...",
  "voiceChatEmpty": "Пока никто ничего не написал",
  "voiceChatSend": "Отправить",
```

- [ ] **Шаг 2: Добавить те же ключи в `app_en.arb`**

```json
  "voiceChat": "Chat",
  "voiceChatHint": "Message...",
  "voiceChatEmpty": "Nothing has been written yet",
  "voiceChatSend": "Send",
```

- [ ] **Шаг 3: Перегенерировать локализации**

Run: `cd ~/Downloads/taler_id_mobile && flutter gen-l10n`
Expected: завершается без ошибок, в `lib/l10n/app_localizations.dart` появляется `voiceChat`

- [ ] **Шаг 4: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/l10n/
git commit -m "i18n(voice): строки чата комнаты"
```

---

## Task 5: Контроллер состояния чата

**Files:**
- Create: `lib/features/voice/presentation/controllers/room_chat_controller.dart`
- Test: `test/voice/room_chat_controller_test.dart`

Дедупликацию по `msgId` контроллер не делает — она уже сделана в начале `_handleDataReceived`, до разбора типа пакета.

- [ ] **Шаг 1: Написать падающий тест**

Создать `test/voice/room_chat_controller_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/voice/presentation/controllers/room_chat_controller.dart';

void main() {
  late RoomChatController c;

  setUp(() => c = RoomChatController());

  test('принимает пакет chat_message и кладёт его в ленту', () {
    final handled = c.handlePacket(
      {'type': 'chat_message', 'text': 'Привет', 'name': 'Аня', 'ts': 1000},
      fallbackName: 'Гость',
    );

    expect(handled, isTrue);
    expect(c.messages, hasLength(1));
    expect(c.messages.single.text, 'Привет');
    expect(c.messages.single.name, 'Аня');
    expect(c.messages.single.own, isFalse);
    expect(c.messages.single.sentAt.millisecondsSinceEpoch, 1000);
  });

  test('пакет чужого типа не трогает ленту', () {
    final handled = c.handlePacket(
      {'type': 'recording_approved'},
      fallbackName: 'Гость',
    );

    expect(handled, isFalse);
    expect(c.messages, isEmpty);
  });

  test('пустой текст игнорируется', () {
    final handled = c.handlePacket(
      {'type': 'chat_message', 'text': '   ', 'name': 'Аня'},
      fallbackName: 'Гость',
    );

    expect(handled, isFalse);
    expect(c.messages, isEmpty);
  });

  test('без имени берётся запасное', () {
    c.handlePacket(
      {'type': 'chat_message', 'text': 'Привет'},
      fallbackName: 'Гость',
    );

    expect(c.messages.single.name, 'Гость');
  });

  test('чужие сообщения при закрытой панели считаются непрочитанными', () {
    c.handlePacket({'type': 'chat_message', 'text': 'раз'}, fallbackName: 'Г');
    c.handlePacket({'type': 'chat_message', 'text': 'два'}, fallbackName: 'Г');

    expect(c.unread, 2);
  });

  test('открытие панели обнуляет счётчик', () {
    c.handlePacket({'type': 'chat_message', 'text': 'раз'}, fallbackName: 'Г');
    c.setOpen(true);

    expect(c.unread, 0);
    expect(c.isOpen, isTrue);
  });

  test('при открытой панели непрочитанные не копятся', () {
    c.setOpen(true);
    c.handlePacket({'type': 'chat_message', 'text': 'раз'}, fallbackName: 'Г');

    expect(c.unread, 0);
  });

  test('своё сообщение не считается непрочитанным', () {
    c.addOwn('Я', 'привет');

    expect(c.messages.single.own, isTrue);
    expect(c.unread, 0);
  });

  test('уведомляет слушателей о новом сообщении', () {
    var notified = 0;
    c.addListener(() => notified++);

    c.handlePacket({'type': 'chat_message', 'text': 'раз'}, fallbackName: 'Г');

    expect(notified, 1);
  });
}
```

- [ ] **Шаг 2: Убедиться, что тест падает**

Run: `cd ~/Downloads/taler_id_mobile && flutter test test/voice/room_chat_controller_test.dart`
Expected: FAIL — файл `room_chat_controller.dart` не найден

- [ ] **Шаг 3: Реализовать контроллер**

Создать `lib/features/voice/presentation/controllers/room_chat_controller.dart`:

```dart
import 'package:flutter/foundation.dart';

/// Одно сообщение в чате комнаты.
@immutable
class RoomChatMessage {
  final String name;
  final String text;
  final DateTime sentAt;
  final bool own;

  const RoomChatMessage({
    required this.name,
    required this.text,
    required this.sentAt,
    required this.own,
  });
}

/// Состояние чата комнаты: лента, счётчик непрочитанных, открыта ли панель.
///
/// Живёт ровно столько, сколько идёт звонок: истории у чата нет, вошедший
/// позже не видит написанного до него — это осознанное решение, см. спеку
/// 2026-09-03-room-chat-mobile-desktop-api-design.md.
///
/// Дедупликацией по `msgId` контроллер не занимается: она сделана
/// централизованно в начале `_handleDataReceived`, до разбора типа пакета.
class RoomChatController extends ChangeNotifier {
  final List<RoomChatMessage> _messages = [];
  int _unread = 0;
  bool _open = false;

  List<RoomChatMessage> get messages => List.unmodifiable(_messages);
  int get unread => _unread;
  bool get isOpen => _open;

  void setOpen(bool open) {
    _open = open;
    if (open) _unread = 0;
    notifyListeners();
  }

  /// Разбирает пакет из data-канала. Возвращает false, если это не сообщение
  /// чата или оно пустое — вызывающая сторона тогда ничего не делает.
  bool handlePacket(
    Map<String, dynamic> msg, {
    required String fallbackName,
  }) {
    if (msg['type'] != 'chat_message') return false;

    final text = (msg['text'] as String? ?? '').trim();
    if (text.isEmpty) return false;

    final rawName = (msg['name'] as String? ?? '').trim();
    final ts = msg['ts'];

    _append(RoomChatMessage(
      name: rawName.isEmpty ? fallbackName : rawName,
      text: text,
      sentAt: ts is int
          ? DateTime.fromMillisecondsSinceEpoch(ts)
          : DateTime.now(),
      own: false,
    ));
    return true;
  }

  /// Своё отправленное сообщение — показываем сразу, не дожидаясь эха.
  void addOwn(String name, String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return;
    _append(RoomChatMessage(
      name: name,
      text: trimmed,
      sentAt: DateTime.now(),
      own: true,
    ));
  }

  void _append(RoomChatMessage m) {
    _messages.add(m);
    if (!m.own && !_open) _unread++;
    notifyListeners();
  }
}
```

- [ ] **Шаг 4: Убедиться, что тесты проходят**

Run: `cd ~/Downloads/taler_id_mobile && flutter test test/voice/room_chat_controller_test.dart`
Expected: PASS, 9 тестов

- [ ] **Шаг 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/features/voice/presentation/controllers/room_chat_controller.dart test/voice/room_chat_controller_test.dart
git commit -m "feat(voice): контроллер состояния чата комнаты"
```

---

## Task 6: Панель чата

**Files:**
- Create: `lib/features/voice/presentation/widgets/room_chat_panel.dart`
- Test: `test/voice/room_chat_panel_test.dart`

- [ ] **Шаг 1: Написать падающий тест**

Создать `test/voice/room_chat_panel_test.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';
import 'package:taler_id_mobile/features/voice/presentation/controllers/room_chat_controller.dart';
import 'package:taler_id_mobile/features/voice/presentation/widgets/room_chat_panel.dart';

Widget _wrap(Widget child) => MaterialApp(
      locale: const Locale('ru'),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: Scaffold(body: child),
    );

void main() {
  testWidgets('показывает сообщения из контроллера', (tester) async {
    final c = RoomChatController()
      ..handlePacket(
        {'type': 'chat_message', 'text': 'Привет', 'name': 'Аня'},
        fallbackName: 'Гость',
      );

    await tester.pumpWidget(_wrap(
      RoomChatPanel(controller: c, onSend: (_) {}, onClose: () {}),
    ));

    expect(find.text('Привет'), findsOneWidget);
    expect(find.text('Аня'), findsOneWidget);
  });

  testWidgets('на пустой ленте показывает заглушку', (tester) async {
    await tester.pumpWidget(_wrap(
      RoomChatPanel(
        controller: RoomChatController(),
        onSend: (_) {},
        onClose: () {},
      ),
    ));

    expect(find.text('Пока никто ничего не написал'), findsOneWidget);
  });

  testWidgets('отдаёт введённый текст наружу и очищает поле', (tester) async {
    final sent = <String>[];

    await tester.pumpWidget(_wrap(
      RoomChatPanel(
        controller: RoomChatController(),
        onSend: sent.add,
        onClose: () {},
      ),
    ));

    await tester.enterText(find.byType(TextField), 'проверка');
    await tester.tap(find.byIcon(Icons.send_rounded));
    await tester.pump();

    expect(sent, ['проверка']);
    expect(tester.widget<TextField>(find.byType(TextField)).controller!.text, '');
  });

  testWidgets('пустое сообщение наружу не уходит', (tester) async {
    final sent = <String>[];

    await tester.pumpWidget(_wrap(
      RoomChatPanel(
        controller: RoomChatController(),
        onSend: sent.add,
        onClose: () {},
      ),
    ));

    await tester.enterText(find.byType(TextField), '   ');
    await tester.tap(find.byIcon(Icons.send_rounded));
    await tester.pump();

    expect(sent, isEmpty);
  });

  testWidgets('перерисовывается на новое сообщение', (tester) async {
    final c = RoomChatController();

    await tester.pumpWidget(_wrap(
      RoomChatPanel(controller: c, onSend: (_) {}, onClose: () {}),
    ));
    expect(find.text('Привет'), findsNothing);

    c.handlePacket(
      {'type': 'chat_message', 'text': 'Привет', 'name': 'Аня'},
      fallbackName: 'Гость',
    );
    await tester.pump();

    expect(find.text('Привет'), findsOneWidget);
  });
}
```

- [ ] **Шаг 2: Убедиться, что тест падает**

Run: `cd ~/Downloads/taler_id_mobile && flutter test test/voice/room_chat_panel_test.dart`
Expected: FAIL — файл `room_chat_panel.dart` не найден

- [ ] **Шаг 3: Реализовать панель**

Создать `lib/features/voice/presentation/widgets/room_chat_panel.dart`:

```dart
import 'package:flutter/material.dart';
import '../../../../l10n/app_localizations.dart';
import '../controllers/room_chat_controller.dart';

/// Панель чата комнаты. Раскладку выбирает вызывающая сторона: на узком экране
/// панель кладут поверх звонка, на широком окне — сбоку.
class RoomChatPanel extends StatefulWidget {
  final RoomChatController controller;
  final ValueChanged<String> onSend;
  final VoidCallback onClose;

  const RoomChatPanel({
    super.key,
    required this.controller,
    required this.onSend,
    required this.onClose,
  });

  @override
  State<RoomChatPanel> createState() => _RoomChatPanelState();
}

class _RoomChatPanelState extends State<RoomChatPanel> {
  final _input = TextEditingController();
  final _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onChanged);
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onChanged);
    _input.dispose();
    _scroll.dispose();
    super.dispose();
  }

  void _onChanged() {
    if (!mounted) return;
    setState(() {});
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  void _send() {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    widget.onSend(text);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final messages = widget.controller.messages;

    return Column(
      children: [
        Row(
          children: [
            const SizedBox(width: 16),
            Expanded(
              child: Text(
                l10n.voiceChat,
                style: theme.textTheme.titleMedium
                    ?.copyWith(fontWeight: FontWeight.w700),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.close_rounded),
              onPressed: widget.onClose,
            ),
          ],
        ),
        const Divider(height: 1),
        Expanded(
          child: messages.isEmpty
              ? Center(
                  child: Text(
                    l10n.voiceChatEmpty,
                    style: theme.textTheme.bodySmall,
                  ),
                )
              : ListView.builder(
                  controller: _scroll,
                  padding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 8),
                  itemCount: messages.length,
                  itemBuilder: (context, i) => _bubble(context, messages[i]),
                ),
        ),
        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 8, 12),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _input,
                  maxLength: 500,
                  textInputAction: TextInputAction.send,
                  onSubmitted: (_) => _send(),
                  decoration: InputDecoration(
                    hintText: l10n.voiceChatHint,
                    counterText: '',
                    isDense: true,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              IconButton.filled(
                tooltip: l10n.voiceChatSend,
                icon: const Icon(Icons.send_rounded),
                onPressed: _send,
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _bubble(BuildContext context, RoomChatMessage m) {
    final theme = Theme.of(context);
    final time = '${m.sentAt.hour.toString().padLeft(2, '0')}:'
        '${m.sentAt.minute.toString().padLeft(2, '0')}';

    return Align(
      alignment: m.own ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        constraints: const BoxConstraints(maxWidth: 280),
        decoration: BoxDecoration(
          color: m.own
              ? theme.colorScheme.primary
              : theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (!m.own)
              Text(
                m.name,
                style: theme.textTheme.labelSmall
                    ?.copyWith(fontWeight: FontWeight.w700),
              ),
            Text(
              m.text,
              style: TextStyle(
                color: m.own ? theme.colorScheme.onPrimary : null,
              ),
            ),
            Text(time, style: theme.textTheme.labelSmall),
          ],
        ),
      ),
    );
  }
}
```

- [ ] **Шаг 4: Убедиться, что тесты проходят**

Run: `cd ~/Downloads/taler_id_mobile && flutter test test/voice/room_chat_panel_test.dart`
Expected: PASS, 5 тестов

- [ ] **Шаг 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/features/voice/presentation/widgets/room_chat_panel.dart test/voice/room_chat_panel_test.dart
git commit -m "feat(voice): панель чата комнаты"
```

---

## Task 7: Подключение чата к экрану звонка

**Files:**
- Modify: `lib/features/voice/presentation/screens/voice_call_screen.dart`

Экран один на все платформы (`app_router.dart` импортирует единственный `voice_call_screen.dart`), поэтому эта задача закрывает и телефоны, и macOS/Windows/Linux.

- [ ] **Шаг 1: Добавить импорты**

В шапку файла, к остальным относительным импортам:

```dart
import '../controllers/room_chat_controller.dart';
import '../widgets/room_chat_panel.dart';
import '../../../../core/desktop/desktop_breakpoints.dart';
```

- [ ] **Шаг 2: Завести контроллер в состоянии экрана**

Рядом с `final Set<String> _processedMessageIds = {};` (строка 161):

```dart
  final RoomChatController _chat = RoomChatController();
```

В `dispose()` экрана, рядом с прочими освобождениями:

```dart
    _chat.dispose();
```

- [ ] **Шаг 3: Принять пакет чата**

В `_handleDataReceived` (строка 2416) в `switch (type)` добавить ветку перед `case 'recording_status':`:

```dart
        case 'chat_message':
          if (_chat.handlePacket(
            msg,
            fallbackName: participant?.name.isNotEmpty == true
                ? participant!.name
                : (participant?.identity ?? '—'),
          )) {
            setState(() {});
          }
          break;
```

- [ ] **Шаг 4: Отправка**

Рядом с `_broadcastData` (строка 2796) добавить:

```dart
  void _sendChatMessage(String text) {
    final me = _room?.localParticipant;
    final myName = (me?.name.isNotEmpty ?? false)
        ? me!.name
        : AppLocalizations.of(context)!.voiceYou;

    _broadcastData({
      'type': 'chat_message',
      'text': text,
      'name': myName,
      'ts': DateTime.now().millisecondsSinceEpoch,
    });

    _chat.addOwn(myName, text);
    setState(() {});
  }
```

- [ ] **Шаг 5: Кнопка чата в панели управления**

В `_buildLandscapeControlsRow()` (строка 4662), в список `children`, перед кнопкой микрофона:

```dart
      _ControlButton(
        compact: true,
        icon: _chat.unread > 0
            ? Icons.mark_chat_unread_rounded
            : Icons.chat_bubble_outline_rounded,
        label: l10n.voiceChat,
        color: _chat.isOpen ? colors.primary.withValues(alpha: 0.2) : colors.card,
        iconColor: _chat.unread > 0 ? colors.primary : null,
        onTap: _toggleChat,
      ),
```

И сам переключатель рядом с `_sendChatMessage`:

```dart
  void _toggleChat() {
    _chat.setOpen(!_chat.isOpen);
    setState(() {});
  }
```

- [ ] **Шаг 6: Вывести панель**

Экран звонка строится в `build`. Найти корневой `Stack` тела экрана и добавить последним ребёнком:

```dart
          if (_chat.isOpen)
            Builder(builder: (context) {
              final isWide =
                  MediaQuery.of(context).size.width >= kDesktopBreakpoint;
              final panel = Material(
                color: Theme.of(context).colorScheme.surface,
                child: SafeArea(
                  child: RoomChatPanel(
                    controller: _chat,
                    onSend: _sendChatMessage,
                    onClose: _toggleChat,
                  ),
                ),
              );

              // Широкое окно — панель сбоку, как в веб-комнате.
              // Узкое — поверх звонка на весь экран.
              return isWide
                  ? Align(
                      alignment: Alignment.centerRight,
                      child: SizedBox(width: 320, child: panel),
                    )
                  : Positioned.fill(child: panel);
            }),
```

- [ ] **Шаг 7: Проверить сборку и анализатор**

Run: `cd ~/Downloads/taler_id_mobile && flutter analyze lib/features/voice/`
Expected: новых замечаний на изменённые файлы нет. Старые замечания по репозиторию игнорировать — их сотни, чистого `analyze` в проекте не бывает.

Run: `cd ~/Downloads/taler_id_mobile && flutter test`
Expected: PASS, падений нет

- [ ] **Шаг 8: Проверить руками на эмуляторе**

```bash
flutter emulators --launch Pixel_XL_API_33
# подождать ~15 секунд
~/Library/Android/sdk/platform-tools/adb devices
cd ~/Downloads/taler_id_mobile && flutter run --flavor dev -t lib/main_dev.dart \
  --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol \
  -d emulator-5554
```

Зайти в комнату, открыть чат, отправить сообщение. Параллельно открыть ту же комнату в браузере на `https://staging.id.taler.tirol/room/<id>` и убедиться, что сообщения ходят в обе стороны.

Затем проверить десктопную раскладку — это тот же экран, но панель должна встать сбоку, а не поверх звонка:

```bash
cd ~/Downloads/taler_id_mobile && flutter run -d macos \
  --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol
```

Зайти в ту же комнату третьим участником, открыть чат, сузить окно до ширины меньше 600 логических точек и убедиться, что панель переключается на полноэкранную и обратно.

- [ ] **Шаг 9: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/features/voice/presentation/screens/voice_call_screen.dart
git commit -m "feat(voice): чат в экране звонка на мобилке и десктопе"
```

---

## Task 8: Tool ассистента

**Files:**
- Modify: `lib/features/assistant/tools/assistant_tools_schema.dart`
- Modify: `lib/features/assistant/tools/assistant_tools_executor.dart`

Активную комнату исполнитель берёт из `CallStateService` — у него есть `String? get roomName`.

- [ ] **Шаг 1: Объявить tool**

В `assistant_tools_schema.dart`, в тот же список, после объявления `web_search`:

```dart
          {
            'type': 'function',
            'name': 'send_room_chat',
            'description':
                'Send a text message to the chat of the voice room the user is currently in. '
                'Only works while a call is active. Use when the user asks to write something '
                'to the other participants of the current call.',
            'parameters': {
              'type': 'object',
              'properties': {
                'text': {
                  'type': 'string',
                  'description': 'The message text, up to 500 characters',
                },
              },
              'required': ['text'],
            },
          },
```

- [ ] **Шаг 2: Написать падающий тест исполнителя**

Создать `test/features/assistant/send_room_chat_tool_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:get_it/get_it.dart';
import 'package:taler_id_mobile/core/services/call_state_service.dart';
import 'package:taler_id_mobile/features/assistant/tools/assistant_tools_executor.dart';

void main() {
  setUp(() => GetIt.I.reset());

  test('вне звонка отказывает и не ходит в сеть', () async {
    GetIt.I.registerSingleton<CallStateService>(CallStateService());

    final executor = AssistantToolsExecutor();
    final out = await executor.execute('send_room_chat', {'text': 'привет'});

    expect(out.toLowerCase(), contains('call'));
  });
}
```

- [ ] **Шаг 3: Убедиться, что тест падает**

Run: `cd ~/Downloads/taler_id_mobile && flutter test test/features/assistant/send_room_chat_tool_test.dart`
Expected: FAIL — неизвестный tool, ответ не содержит упоминания звонка

- [ ] **Шаг 4: Реализовать исполнение**

В `assistant_tools_executor.dart`, в цепочку `else if` после ветки `web_search`:

```dart
      } else if (name == 'send_room_chat') {
        final roomName = sl<CallStateService>().roomName;
        if (roomName == null || roomName.isEmpty) {
          return 'There is no active call, so there is no room chat to write to.';
        }
        final text = (args['text'] as String? ?? '').trim();
        if (text.isEmpty) {
          return 'The message is empty, nothing to send.';
        }
        final data = await client.post<Map<String, dynamic>>(
          '/voice/rooms/$roomName/chat',
          data: {'text': text},
          fromJson: (d) => Map<String, dynamic>.from(d as Map),
        );
        output = jsonEncode(data);
```

Если `CallStateService` ещё не импортирован в файле, добавить импорт:

```dart
import '../../../core/services/call_state_service.dart';
```

- [ ] **Шаг 5: Убедиться, что тест проходит**

Run: `cd ~/Downloads/taler_id_mobile && flutter test test/features/assistant/send_room_chat_tool_test.dart`
Expected: PASS

- [ ] **Шаг 6: Коммит**

```bash
cd ~/Downloads/taler_id_mobile
git add lib/features/assistant/tools/ test/features/assistant/send_room_chat_tool_test.dart
git commit -m "feat(assistant): tool send_room_chat — писать в чат комнаты голосом"
```

---

## Task 9: E2E-тест ручки

**Files:**
- Create: `~/Downloads/taler_id_tests/room_chat_test.ts`
- Modify: `~/Downloads/taler_id_tests/package.json`

⚠️ `taler_id_tests` — это git-репозиторий, и в рабочей копии лежат чужие правки. `git add -A` там делать нельзя, добавлять только свои файлы поимённо.

Набор написан на TypeScript и гоняется через `ts-node` — именование файлов `*_test.ts`. Клиент LiveKit уже в зависимостях (`@livekit/rtc-node`), токен комнаты набор чеканит сам через `AccessToken` из `livekit-server-sdk`, как это делает `recording_test.ts`. Поэтому запуск идёт через `dotenv -e .env.dev`, откуда берётся `LIVEKIT_API_SECRET`.

Авторизуем запрос к ручке именно LiveKit-токеном: `RoomAccessGuard` принимает грант, выданный ровно на эту комнату, и это детерминированный гостевой путь — не зависит от того, попал ли тестовый юзер в `participantIds`.

- [ ] **Шаг 1: Написать тест**

Создать `room_chat_test.ts`:

```ts
/**
 * E2E чата комнаты: POST /voice/rooms/:roomName/chat публикует пакет
 * chat_message в data-канал, и подключённый к комнате клиент его получает.
 */
import { Room, RoomEvent } from '@livekit/rtc-node';
import { AccessToken } from 'livekit-server-sdk';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const LIVEKIT_URL =
  process.env.LIVEKIT_URL ?? 'wss://staging.id.taler.tirol/livekit/';
const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY ?? 'lkdevkey';
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
if (!LIVEKIT_API_SECRET) {
  throw new Error(
    'LIVEKIT_API_SECRET is required. Use `npm run test:room-chat` (loads .env.dev).',
  );
}

const ROOM = `chat-e2e-${Date.now()}`;
let passed = 0;
let failed = 0;

function check(name: string, ok: boolean, detail = '') {
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function roomToken(room: string): Promise<string> {
  const at = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET!, {
    identity: `chat-e2e-listener-${Date.now()}`,
  });
  at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
  return at.toJwt();
}

async function postChat(
  room: string,
  token: string,
  body: unknown,
): Promise<number> {
  const res = await fetch(`${BASE_URL}/voice/rooms/${room}/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  return res.status;
}

async function main() {
  console.log(`\nЧат комнаты — ${BASE_URL}\nКомната: ${ROOM}\n`);

  const token = await roomToken(ROOM);
  const room = new Room();

  const received: any[] = [];
  room.on(RoomEvent.DataReceived, (payload: Uint8Array) => {
    try {
      received.push(JSON.parse(Buffer.from(payload).toString('utf8')));
    } catch {
      /* не наш пакет */
    }
  });

  await room.connect(LIVEKIT_URL, token, {
    autoSubscribe: false,
    dynacast: false,
  });
  console.log('  подключились к комнате\n');

  try {
    // ── Доставка ──
    const status = await postChat(ROOM, token, {
      text: 'привет из теста',
      name: 'E2E',
    });
    check('POST /chat отвечает 201', status === 201, `получили ${status}`);

    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && received.length === 0) {
      await new Promise((r) => setTimeout(r, 200));
    }

    check('пакет дошёл до участника за 10 секунд', received.length > 0);
    const packet = received[0];
    check('тип пакета chat_message', packet?.type === 'chat_message');
    check('текст сохранился', packet?.text === 'привет из теста');
    check('имя отправителя сохранилось', packet?.name === 'E2E');
    check('в пакете есть msgId', typeof packet?.msgId === 'string');

    // ── Отказы ──
    check(
      'пустой текст отвергается',
      (await postChat(ROOM, token, { text: '   ' })) === 400,
    );
    check(
      'текст длиннее 500 символов отвергается',
      (await postChat(ROOM, token, { text: 'x'.repeat(501) })) === 400,
    );

    const foreign = await roomToken('another-room-entirely');
    check(
      'токен чужой комнаты не пускает',
      (await postChat(ROOM, foreign, { text: 'нельзя' })) === 403,
    );

    const anon = await fetch(`${BASE_URL}/voice/rooms/${ROOM}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'нельзя' }),
    });
    check('без токена не пускает', anon.status === 401);
  } finally {
    await room.disconnect();
  }

  console.log(`\n  Итого: ${passed} прошло, ${failed} упало\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

- [ ] **Шаг 2: Добавить записи в `package.json`**

Рядом с `test:recording`:

```json
    "test:room-chat": "dotenv -e .env.dev -- npx ts-node room_chat_test.ts",
    "test:room-chat:prod": "dotenv -e .env.prod -- npx ts-node room_chat_test.ts",
```

- [ ] **Шаг 3: Прогнать против DEV**

Run: `cd ~/Downloads/taler_id_tests && npm run test:room-chat`
Expected: 10 проверок, все зелёные

⚠️ Не гонять вплотную к другим наборам: на `/auth/login` в nginx стоит `limit_req burst=5`, и подряд идущие наборы дают 503, которые выглядят как регрессия. Разносить `sleep 20`.

- [ ] **Шаг 4: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add room_chat_test.ts package.json
git commit -m "test: E2E чата комнаты через POST /voice/rooms/:roomName/chat"
```

---

## Task 10: Раскатка

- [ ] **Шаг 1: Прогнать обязательную батарею перед деплоем**

Наборы из CLAUDE.md, с паузами между ними:

```bash
cd ~/Downloads/taler_id_mobile && flutter test
cd ~/Downloads/taler_id_tests && npm test
sleep 20 && npm run test:voice
sleep 20 && npm run test:room-chat
```

Expected: всё зелёное. При падении любого — не катить, сначала чинить.

- [ ] **Шаг 2: Бэкенд на DEV**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
```

Проверка: `cd ~/Downloads/taler_id_tests && npm run test:room-chat`

- [ ] **Шаг 3: Бэкенд на TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id'
```

Проверка: `cd ~/Downloads/taler_id_tests && npm run test:room-chat:prod`

- [ ] **Шаг 4: Бэкенд на PROD**

Только по явной команде пользователя. Поочерёдно по нодам, с ожиданием `health:200` на первой перед второй:

```bash
ssh dvolkov@77.73.131.137 "ssh do-app-1 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id && sleep 5 && curl -s -o /dev/null -w \"health:%{http_code}\n\" http://localhost:3000/health'"
```

Затем то же на `do-app-2`. Полный `npm ci`, не `--omit=dev`: nest CLI живёт в devDependencies.

Проверка: `cd ~/Downloads/taler_id_tests && npm run test:talerid`

- [ ] **Шаг 5: Сборки приложения**

Чат в приложении едет со следующей сборкой. Собрать APK, iOS и десктоп по процедурам из CLAUDE.md.

- [ ] **Шаг 6: Объявить версию — только после сборок**

Поднять `latest` и добавить запись в `APP_RELEASES` в `~/taler-id/src/app.controller.ts` (DEV+TEST), плюс `APP_LATEST_VERSION`/`APP_LATEST_BUILD` в `.env` обеих DO-нод (PROD). Строго после того, как артефакты легли на место: деплой бэкенда с новой записью `APP_RELEASES` сам рассылает пост в системный канал, и объявлять несуществующую сборку нельзя.

Проверка: `curl -s https://staging.id.taler.tirol/app/version | jq`, то же для `id.taler.tirol` и `api.talerid.io`.
