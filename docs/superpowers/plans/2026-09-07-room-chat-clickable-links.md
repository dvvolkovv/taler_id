# Чат комнаты: кликабельные ссылки — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ссылка, присланная в чат комнаты, открывается нажатием — в вебе, на телефоне и на десктопе.

**Architecture:** Протокол не меняется: текст остаётся текстом, ссылки узнаются на приёме. Правило разбора одно и то же на обеих сторонах и вынесено отдельно, с юнит-тестами: `splitRoomChatLinks` в приложении, `roomChatLinkParts` в вебе. Узнаются только `http://` и `https://`.

**Tech Stack:** ванильный JS (`public/room.html`), Flutter/Dart (`url_launcher` уже в зависимостях), `flutter test`.

**Спека:** `docs/superpowers/specs/2026-09-07-room-chat-links-images-read-api-design.md`, раздел «Ссылки».

**Порядок относительно других планов:** независим от `2026-09-07-room-chat-server-transport.md` — может идти параллельно или раньше. Ничего в бэкенде не трогает.

---

## Структура файлов

- Создать `lib/features/voice/domain/room_chat_links.dart` — разбиение текста на куски «текст / ссылка». Чистая функция без Flutter-виджетов, чтобы тестировалась без окружения.
- Создать `test/features/voice/room_chat_links_test.dart`.
- Изменить `lib/features/voice/presentation/widgets/room_chat_panel.dart:228` — `Text` заменяется на `Text.rich` со ссылками.
- Изменить `test/voice/room_chat_panel_test.dart` — проверка, что ссылка в пузыре стала кликабельной.
- Изменить `public/room.html` — функция `roomChatLinkNodes` и её вызов в `appendChatMessage`.

---

## Task 1: Разбор ссылок в приложении

**Files:**
- Create: `lib/features/voice/domain/room_chat_links.dart`
- Test: `test/features/voice/room_chat_links_test.dart`

- [ ] **Step 1: Написать падающий тест**

Создать `test/features/voice/room_chat_links_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/voice/domain/room_chat_links.dart';

void main() {
  group('splitRoomChatLinks', () {
    List<String> shapes(String text) => splitRoomChatLinks(text)
        .map((p) => '${p.isLink ? "link" : "text"}:${p.text}')
        .toList();

    test('текст без ссылок — один кусок', () {
      expect(shapes('просто сообщение'), ['text:просто сообщение']);
    });

    test('ссылка целиком — один кусок-ссылка', () {
      expect(shapes('https://talerid.io'), ['link:https://talerid.io']);
    });

    test('ссылка внутри фразы', () {
      expect(
        shapes('смотри https://talerid.io тут'),
        ['text:смотри ', 'link:https://talerid.io', 'text: тут'],
      );
    });

    test('точка в конце предложения в ссылку не заезжает', () {
      expect(
        shapes('открой https://talerid.io/doc.'),
        ['text:открой ', 'link:https://talerid.io/doc', 'text:.'],
      );
    });

    test('закрывающая скобка не заезжает, парная внутри остаётся', () {
      expect(
        shapes('(см. https://ru.wikipedia.org/wiki/Тест_(значения))'),
        [
          'text:(см. ',
          'link:https://ru.wikipedia.org/wiki/Тест_(значения)',
          'text:)',
        ],
      );
    });

    test('запятая и двоеточие в хвосте отрезаются', () {
      expect(
        shapes('вот https://talerid.io, и ещё https://talerid.io:'),
        [
          'text:вот ',
          'link:https://talerid.io',
          'text:, и ещё ',
          'link:https://talerid.io',
          'text::',
        ],
      );
    });

    test('несколько ссылок подряд', () {
      expect(
        shapes('https://a.io https://b.io'),
        ['link:https://a.io', 'text: ', 'link:https://b.io'],
      );
    });

    test('http тоже ссылка', () {
      expect(shapes('http://talerid.io'), ['link:http://talerid.io']);
    });

    test('голый домен ссылкой не считается', () {
      // «зайди на сайт.рф» в русской фразе ловился бы ложно.
      expect(shapes('зайди на talerid.io'), ['text:зайди на talerid.io']);
    });

    test('javascript: и data: ссылками не считаются', () {
      expect(shapes('javascript:alert(1)'), ['text:javascript:alert(1)']);
      expect(shapes('data:text/html,<b>'), ['text:data:text/html,<b>']);
    });

    test('пустой текст — пустой список', () {
      expect(splitRoomChatLinks(''), isEmpty);
    });
  });
}
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/features/voice/room_chat_links_test.dart`
Expected: FAIL — `Target of URI doesn't exist: room_chat_links.dart`.

- [ ] **Step 3: Написать разбор**

Создать `lib/features/voice/domain/room_chat_links.dart`:

```dart
import 'package:flutter/foundation.dart';

/// Кусок сообщения: либо обычный текст, либо ссылка.
@immutable
class RoomChatTextPart {
  final String text;
  final bool isLink;

  const RoomChatTextPart(this.text, {this.isLink = false});
}

/// Ищем только `http://` и `https://`.
///
/// Голые домены намеренно не узнаются: «зайди на сайт.рф» в обычной русской
/// фразе ловится ложно, и человек получает ссылку там, где её не писал.
/// Схемы вроде `javascript:` и `data:` не ссылки ни при каких условиях —
/// правило не «всё, где есть двоеточие», а именно эти две схемы.
final _urlPattern = RegExp(r'https?://[^\s<>"]+', caseSensitive: false);

/// Знаки, которые почти всегда принадлежат предложению, а не ссылке.
const _trailingPunctuation = '.,;:!?»"\'';

/// Разбивает текст сообщения на куски для отрисовки.
///
/// Правило хвоста: конечная пунктуация отрезается, а закрывающая скобка —
/// только если в ссылке нет парной ей открывающей. Иначе ссылки вида
/// `.../Тест_(значения)` теряли бы последний символ и вели в никуда.
List<RoomChatTextPart> splitRoomChatLinks(String text) {
  if (text.isEmpty) return const [];

  final parts = <RoomChatTextPart>[];
  var cursor = 0;

  for (final match in _urlPattern.allMatches(text)) {
    var url = match.group(0)!;
    var end = match.end;

    // Отрезаем хвост, пока он выглядит частью предложения.
    while (url.isNotEmpty) {
      final last = url[url.length - 1];
      final isPunctuation = _trailingPunctuation.contains(last);
      final isUnbalancedParen = last == ')' &&
          '('.allMatches(url).length < ')'.allMatches(url).length;
      if (!isPunctuation && !isUnbalancedParen) break;
      url = url.substring(0, url.length - 1);
      end--;
    }

    // От ссылки ничего не осталось — обращаться с ней как с текстом.
    if (url.length <= 'https://'.length) continue;

    if (match.start > cursor) {
      parts.add(RoomChatTextPart(text.substring(cursor, match.start)));
    }
    parts.add(RoomChatTextPart(url, isLink: true));
    cursor = end;
  }

  if (cursor < text.length) {
    parts.add(RoomChatTextPart(text.substring(cursor)));
  }
  return parts;
}
```

- [ ] **Step 4: Запустить тест и убедиться, что он проходит**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/features/voice/room_chat_links_test.dart`
Expected: PASS, 11 тестов.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/domain/room_chat_links.dart test/features/voice/room_chat_links_test.dart
git commit -m "feat(voice): разбор ссылок в сообщениях чата комнаты"
```

---

## Task 2: Ссылки в пузыре приложения

**Files:**
- Modify: `lib/features/voice/presentation/widgets/room_chat_panel.dart:228`
- Test: `test/voice/room_chat_panel_test.dart`

- [ ] **Step 1: Написать падающий тест**

Дописать в `test/voice/room_chat_panel_test.dart` внутрь существующего `group` (обёртку `pumpWidget` взять ту же, что в соседних тестах файла):

```dart
    testWidgets('ссылка в сообщении получает распознаватель нажатия',
        (tester) async {
      final controller = RoomChatController();
      controller.handlePacket({
        'type': 'chat_message',
        'text': 'смотри https://talerid.io тут',
        'name': 'Linkeon',
        'ts': 1000,
      }, fallbackName: '—');

      await tester.pumpWidget(_wrap(RoomChatPanel(
        controller: controller,
        onSend: (_) {},
        onClose: () {},
      )));
      await tester.pump();

      final rich = tester.widget<RichText>(
        find.byWidgetPredicate(
          (w) => w is RichText && w.text.toPlainText().contains('talerid.io'),
        ),
      );
      final spans = <InlineSpan>[];
      rich.text.visitChildren((s) { spans.add(s); return true; });

      final linkSpans = spans
          .whereType<TextSpan>()
          .where((s) => s.recognizer != null)
          .toList();
      expect(linkSpans, hasLength(1));
      expect(linkSpans.first.text, 'https://talerid.io');
    });
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/voice/room_chat_panel_test.dart`
Expected: FAIL — распознавателей нажатия ноль.

- [ ] **Step 3: Реализовать**

В `room_chat_panel.dart` дописать импорты:

```dart
import 'package:flutter/gestures.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../domain/room_chat_links.dart';
```

Заменить строку с телом сообщения:

```dart
            Text(m.text, style: TextStyle(color: textColor, fontSize: 15)),
```

на:

```dart
            _messageText(m.text, textColor, palette),
```

и добавить в класс метод:

```dart
  /// Тело сообщения со ссылками. Открываем во встроенном браузере — так же,
  /// как мессенджер: человек возвращается в звонок кнопкой «назад», а не
  /// переключением приложений.
  ///
  /// Распознаватели живут ровно столько же, сколько сам виджет: пузырь
  /// перестраивается на каждое новое сообщение, поэтому отдельно освобождать
  /// их не нужно — `RichText` роняет ссылки на них вместе со спанами.
  Widget _messageText(String text, Color textColor, _Palette palette) {
    final parts = splitRoomChatLinks(text);
    if (parts.every((p) => !p.isLink)) {
      return Text(text, style: TextStyle(color: textColor, fontSize: 15));
    }
    return Text.rich(
      TextSpan(
        children: [
          for (final part in parts)
            if (part.isLink)
              TextSpan(
                text: part.text,
                style: TextStyle(
                  color: palette.accent,
                  fontSize: 15,
                  decoration: TextDecoration.underline,
                  decorationColor: palette.accent,
                ),
                recognizer: TapGestureRecognizer()
                  ..onTap = () {
                    final uri = Uri.tryParse(part.text);
                    if (uri != null) {
                      launchUrl(uri, mode: LaunchMode.inAppBrowserView);
                    }
                  },
              )
            else
              TextSpan(
                text: part.text,
                style: TextStyle(color: textColor, fontSize: 15),
              ),
        ],
      ),
    );
  }
```

- [ ] **Step 4: Запустить тесты и убедиться, что они проходят**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/voice/ && flutter analyze lib/features/voice/`
Expected: PASS; новых замечаний по тронутым файлам нет.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/presentation/widgets/room_chat_panel.dart test/voice/room_chat_panel_test.dart
git commit -m "feat(voice): ссылки в чате комнаты открываются нажатием"
```

---

## Task 3: Ссылки в веб-комнате

**Files:**
- Modify: `public/room.html:3421-3448` (`appendChatMessage`)

- [ ] **Step 1: Написать разбор и отрисовку**

Добавить перед `appendChatMessage`:

```js
    // Ссылками считаются только http/https. Голые домены не трогаем: «зайди
    // на сайт.рф» в русской фразе ловится ложно. Схемы javascript:/data: не
    // ссылки ни при каких условиях.
    const CHAT_URL_RE = /https?:\/\/[^\s<>"]+/gi;
    const CHAT_TRAILING = '.,;:!?»"\'';

    /** Куски сообщения для отрисовки: {text, isLink}. Правило хвоста — как в
     *  приложении (lib/features/voice/domain/room_chat_links.dart): конечная
     *  пунктуация отрезается, закрывающая скобка — только непарная. */
    function roomChatLinkParts(text) {
      const parts = [];
      let cursor = 0;
      CHAT_URL_RE.lastIndex = 0;
      let match;
      while ((match = CHAT_URL_RE.exec(text)) !== null) {
        let url = match[0];
        let end = match.index + url.length;
        for (;;) {
          const last = url[url.length - 1];
          if (!last) break;
          const unbalanced =
            last === ')' &&
            (url.match(/\(/g) || []).length < (url.match(/\)/g) || []).length;
          if (CHAT_TRAILING.indexOf(last) === -1 && !unbalanced) break;
          url = url.slice(0, -1);
          end--;
        }
        if (url.length <= 'https://'.length) continue;
        if (match.index > cursor) {
          parts.push({ text: text.slice(cursor, match.index), isLink: false });
        }
        parts.push({ text: url, isLink: true });
        cursor = end;
      }
      if (cursor < text.length) {
        parts.push({ text: text.slice(cursor), isLink: false });
      }
      return parts;
    }

    /** Собирает тело сообщения. Только createElement и textContent: innerHTML
     *  здесь появиться не должен — текст приходит от других участников. */
    function roomChatTextNode(text) {
      const wrap = document.createElement('div');
      for (const part of roomChatLinkParts(text)) {
        if (part.isLink) {
          const a = document.createElement('a');
          a.href = part.text;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.style.color = 'var(--primary, #167EF2)';
          a.style.textDecoration = 'underline';
          a.textContent = part.text;
          wrap.appendChild(a);
        } else {
          wrap.appendChild(document.createTextNode(part.text));
        }
      }
      return wrap;
    }
```

- [ ] **Step 2: Подключить в отрисовку**

В `appendChatMessage` заменить:

```js
      const textEl = document.createElement('div');
      textEl.textContent = text;
      div.appendChild(textEl);
```

на:

```js
      div.appendChild(roomChatTextNode(text));
```

- [ ] **Step 3: Проверить руками, что разметка не исполняется**

Открыть комнату, отправить в чат три сообщения:

```
смотри https://talerid.io тут
<img src=x onerror=alert(1)>
javascript:alert(1)
```

Expected: первая ссылка кликабельна и открывается в новой вкладке; вторая строка видна как текст целиком, никакого диалога не появляется; третья остаётся обычным текстом.

- [ ] **Step 4: Проверить совпадение правил с приложением**

Отправить из веба `открой https://talerid.io/doc.` и убедиться, что и в браузере, и в приложении ссылка кончается на `/doc`, а точка осталась текстом.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add public/room.html
git commit -m "feat(room): ссылки в веб-чате комнаты кликабельны"
```

---

## Task 4: Раскатка

**Files:** нет — деплой и проверка.

- [ ] **Step 1: Выкатить бэкенд на DEV (веб-комната едет с ним)**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
```

- [ ] **Step 2: Прогнать тесты приложения**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test`
Expected: всё зелёное.

- [ ] **Step 3: Выкатить на TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id'
```

- [ ] **Step 4: PROD — только по явной команде**

```bash
ssh do-app-1 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id && sleep 5 && curl -s -o /dev/null -w "health:%{http_code}\n" http://localhost:3000/health'
# дождаться health:200, затем то же на do-app-2
```
