# Системный канал новостей TalerID — Design

**Date:** 2026-07-24
**Status:** Approved (design), pending implementation plan
**Scope:** серверная фича. Вне скоупа: client-side блокировка старых версий (фаза 2), новый мобильный UI (канал рендерится существующим UI каналов).

## Цель

Официальный канал «Taler ID — Новости» внутри мессенджера, куда попадают:
- **release-посты** — что нового в каждом релизе (автоматически из `APP_RELEASES`);
- **news-посты** — произвольные новости/анонсы (вручную);
- **critical-посты** — «версия ниже X.Y.Z перестанет работать, обновитесь» (вручную; push доходит даже при mute).

Все пользователи подписаны принудительно: отписаться нельзя, замьютить можно.

## Ключевые решения

| Вопрос | Решение |
|--------|---------|
| Механика | Существующие каналы (`Conversation type CHANNEL`) + флаг `isSystem` — не новая сущность |
| Публикация | Автопост релизов из `APP_RELEASES` + ручные посты (admin-эндпоинт / канальные роли) |
| Подписка | Авто для новых (в регистрации) + backfill существующих; отписка от `isSystem` → 403; mute разрешён |
| Critical | FCM-push игнорирует mute только для `newsType: 'critical'` |
| Enforcement старых версий | НЕ в этой фиче (только информирование); client-side блокировка — фаза 2 |
| Локализация постов | RU + EN секциями в одном сообщении (у сообщений нет i18n) |
| Мобилка/MCP/ассистент | Бесплатно: канал — обычная conversation, виден через существующие экраны и tools |

## Архитектура

### 1. Системный юзер и канал (seed)
- Идемпотентный seed при старте приложения (`SystemChannelService.onApplicationBootstrap`):
  - юзер `system@talerid.io`, username `talerid`, displayName «Taler ID», логин запрещён (нет пароля; guard от логина по флагу или невалидируемому хешу);
  - канал «Taler ID — Новости» `type: CHANNEL`, `isSystem: true`, owner = системный юзер;
  - backfill подписок: все существующие юзеры → `ConversationParticipant` (INSERT … ON CONFLICT DO NOTHING, батчами).
- Prisma: `Conversation.isSystem Boolean @default(false)`.
- Один канал на окружение (каждая БД сеет свой).

### 2. Подписка
- Регистрация: в транзакции создания юзера — подписка на все `isSystem`-каналы.
- `unsubscribeChannel` (и `leaveGroup`, если применим к каналам): для `isSystem` → `ForbiddenException('Нельзя отписаться от системного канала')`.
- Mute — существующий механизм, без изменений.

### 3. Посты
- `Message.metadata`: `{ newsType: 'release' | 'news' | 'critical', version?: string, minVersion?: string }`.
- Доставка — существующий канальный broadcast/fan-out.
- **Critical сквозь mute:** в push-ветке fan-out'а (`isParticipantMuted`-проверка) — если `metadata.newsType === 'critical'`, mute игнорируется.

### 4. Автопост релизов
- При старте бэкенда: взять первую запись `APP_RELEASES` (уже содержит `version`, `notes_ru`, `notes_en`), сравнить с последним `release`-постом канала (`metadata.version`); если новее — запостить от системного юзера:
  формат «🚀 Taler ID X.Y.Z\n\n<notes_ru>\n\n— EN —\n<notes_en>», `metadata: { newsType: 'release', version }`.
- Следствие: деплой бэкенда с новым релизом = пост появляется сам, ручных шагов нет. Идемпотентно (по version).

### 5. Ручные посты
- `POST /admin/system-channel/post` (существующий admin-guard): `{ type: 'news' | 'critical', text_ru, text_en?, minVersion? }` → постит от системного юзера с соответствующей metadata.
- Дополнительно админам можно выдать ADMIN-роль в канале — обычный `postToChannel` тоже работает (без metadata → трактуется как `news`).

### 6. Тестирование
- Юнит: seed идемпотентен (повторный запуск не дублирует), отписка → 403, critical-push сквозь mute (fan-out тест), автопост при новой version / скип при совпадении.
- E2E `test:system-channel` в `taler_id_tests`: канал в списке у обоих тест-юзеров с `isSystem`; отписка → 403; история содержит release-пост текущей версии `/app/version`; mute работает (сам факт мьюта, без проверки push).
- Прогон существующих `test:channels` — регрессия каналов.

## Раскатка
- DEV → TEST → PROD стандартным пайплайном; миграция аддитивная (`isSystem`).
- На каждом окружении seed сам создаст юзера/канал/подписки при первом старте.
- Backfill подписок на PROD (~сотни юзеров) — незаметен.

## Фаза 2 (вне спека)
- `minSupportedVersion` в `/app/version` + блокирующий экран в мобилке.
- Локализация постов по locale юзера (если появится i18n сообщений).
- UI-бейдж «официальный канал» в мобилке.
