# TalerID MCP Server — Design

**Date:** 2026-07-24
**Status:** Approved (design), pending implementation plan
**Scope:** MVP — calendar, notes (reminders), messages. Phase 2 (out of scope): calls, B2B webhooks, partner admin UI.

## Цель

TalerID сегодня отдаёт внешним сервисам только аутентификацию/авторизацию (OIDC). Цель — отдавать и *функции* платформы (сообщения, календарь, напоминания; позже звонки) в виде MCP-сервера, чтобы их могли использовать:

- **(A) Личные AI-ассистенты пользователей** — Claude Desktop / claude.ai / ChatGPT / кастомные агенты. Юзер подключает TalerID к своему ассистенту и говорит «отправь сообщение Ивану», «поставь встречу на завтра».
- **(B) Внешние сервисы-партнёры (B2B)** — их агенты/бэкенды действуют от имени пользователей TalerID с их согласия.

## Ключевые решения

| Вопрос | Решение |
|--------|---------|
| Сколько серверов | **Один MCP endpoint** `api.talerid.io/mcp`, доступ к tools регулируется OAuth-scopes |
| Где живёт | **Внутри существующего NestJS** — новый модуль `src/mcp/`, деплой стандартным пайплайном DEV→TEST→PROD |
| Транспорт | **Streamable HTTP** (официальный `@modelcontextprotocol/sdk`), stateless-режим — работает на 2 DO app-нодах за LB без sticky-требований |
| Регистрация клиентов | **DCR открыт** (личные ассистенты) + **ручной статус «verified partner»** для B2B с расширенными правами |
| Входящие сообщения | **Pull-only** в MVP; realtime/webhooks — фаза 2 |
| Защита send_message | Отправка **только существующим контактам** юзера |

## Архитектура

```
AI-клиент (Claude Desktop / партнёрский агент)
        │  Streamable HTTP + OAuth 2.1 Bearer
        ▼
api.talerid.io/mcp  (nginx → NestJS, тот же LB)
        │
   src/mcp/
   ├── mcp.controller.ts      # POST/GET/DELETE /mcp (Streamable HTTP transport)
   ├── mcp-auth.guard.ts      # валидация access-token OIDC, извлечение userId+scopes
   ├── tools/
   │   ├── calendar.tools.ts  # → CalendarService (существующий)
   │   ├── notes.tools.ts     # → NotesService (существующий)
   │   └── messenger.tools.ts # → MessengerService (существующий)
   └── mcp.module.ts
```

- Tools вызывают **существующие сервисы напрямую** (in-process, не HTTP на самих себя) — та же бизнес-валидация и права, что у REST.
- Discovery: `/.well-known/oauth-protected-resource` указывает на наш OIDC-провайдер — стандартный путь автообнаружения авторизации MCP-клиентами.
- Stateless Streamable HTTP: без session-state в памяти процесса (multi-node DO). Если SDK требует session-id — хранить состояние сессии в Redis.

## Auth и scopes

- `oidc-provider@9.6.0` уже в проекте — включаем `features.registration` (Dynamic Client Registration) конфигом + rate-limit на endpoint регистрации. DCR отключаем env-переменной (kill-switch).
- **Новые scopes:** `mcp:calendar`, `mcp:notes`, `mcp:messages.read`, `mcp:messages.send`.
- **Consent-экран** (существующий `oidc-interaction.controller`) расширяется: ru/en описание запрашиваемых прав, юзер может снять отдельные галочки (частичный consent).
- **Verified partner (B2B):** флаг на записи OAuth-клиента, ставится вручную в БД (admin UI — фаза 2). Только verified-клиенты получают `offline_access` (refresh-токены) и повышенные rate-limits. DCR-клиенты — access-токены 2 часа, переавторизация силами клиента (Claude умеет).
- `tools/list` отдаёт **только tools, покрытые scopes токена** — клиент без `mcp:messages.send` не видит `send_message`.

## Tools (MVP)

**Календарь** (`mcp:calendar`) — напоминания живут внутри `CalendarEvent` (`reminderAt`/`reminderSent`):
- `list_calendar_events(from, to, cursor?)` — пагинация
- `get_calendar_event(id)`
- `create_calendar_event(title, start, end?, description?, reminder_minutes_before?)`
- `update_calendar_event(id, ...)` / `delete_calendar_event(id)`

**Заметки** (`mcp:notes`):
- `list_notes(cursor?)`, `create_note(...)`, `update_note(id, ...)`, `delete_note(id)`

**Сообщения** (`mcp:messages.read` / `mcp:messages.send`):
- `list_contacts()` — имя + id контактов (агенту нужно знать, кому можно писать)
- `list_conversations()` — с preview последнего сообщения
- `get_messages(conversation_id, cursor?)` — история, пагинация
- `search_messages(query)` — поиск по тексту
- `send_message(contact_id | conversation_id, text)` — **только контактам** (проверка в tool)

Каждый tool возвращает структурированный JSON + человекочитаемый текст (MCP-спека). Ошибки — внятные для агента: «контакт не найден», «недостаточно прав (scope mcp:messages.send)».

## Тестирование

- **Юнит (backend):** `mcp-auth.guard.spec.ts` + spec на каждый tools-файл (моки сервисов: маппинг аргументов, scope-фильтрация, contact-check).
- **E2E `test:mcp`** в `taler_id_tests` (по образцу `test:channels`):
  1. OAuth-флоу тестового клиента → access-token со scopes;
  2. MCP init → `tools/list` → проверка scope-фильтрации (без `mcp:messages.send` tool не виден);
  3. calendar: create (с reminder) → get → update → delete;
  4. notes: CRUD;
  5. messages: `send_message` между `integration_test` ↔ `integration_test_2` → `get_messages` подтверждает доставку → `search_messages`;
  6. негатив: отправка не-контакту → ошибка; вызов tool без scope → ошибка.
  Гоняется на DEV; добавить в обязательный пред-деплойный список CLAUDE.md.
- **Ручная проверка сценария A:** подключение Claude Desktop / claude.ai к `https://staging.id.taler.tirol/mcp` — DCR + consent + реальные вызовы tools.

## Раскатка

- Пайплайн: DEV → TEST → PROD (DO). Полностью серверная фича — мобильные релизы не требуются.
- Модуль не трогает существующие REST/Socket.IO пути; DCR за env-флагом.
- Assistant-first: внутренний голосовой ассистент не затрагивается (свои tools). Опционально фаза 2 — tool «показать/отозвать подключённые MCP-клиенты».

## Фаза 2 (вне этого спека)

- **Звонки:** определить семантику tool'а (инициировать звонок между юзерами TalerID; агент не участвует в аудио).
- **Webhooks для B2B:** подписки на входящие сообщения (retries, подпись payload).
- **Admin UI** управления verified-партнёрами.
- **Realtime MCP notifications** — когда поддержка в клиентах созреет.
