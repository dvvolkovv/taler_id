# Pinned Messages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Дать чатам закреплённые сообщения по образцу Telegram (несколько пинов, плашка с переключением, экран списка, «открепить всё», скрытие у себя, сервисное сообщение + push) и повесить с их помощью объявление «это TEST, переходите на PROD» в системном канале на TEST.

**Architecture:** Состояние пина живёт на самом сообщении (`Message.pinnedAt`, `Message.pinnedById`) — без отдельной таблицы, поэтому удаление сообщения снимает пин само. Скрытие плашки — отметка времени на участнике (`ConversationParticipant.pinsDismissedAt`). Права: `CHANNEL`/`GROUP` → OWNER/ADMIN, остальные типы бесед → любой участник. Реалтайм — три socket-события, push — за счёт обычного системного сообщения, идущего через `deliverNewMessage`.

**Tech Stack:** NestJS + Prisma + PostgreSQL + Socket.io (бэкенд), Flutter + BLoC + freezed (мобилка), ts-node + axios (e2e).

**Репозитории (пути на машине Дмитрия):**
- Бэкенд: `/Users/dmitry/taler-id` (ветка `feature/pinned-messages`, уже создана, в ней лежит спека)
- Мобилка: `/Users/dmitry/Downloads/taler_id_mobile` (ветку `feature/pinned-messages` создать от `dev`)
- Тесты: `/Users/dmitry/Downloads/taler_id_tests` — **git-репозиторий**, remote `git@github.com:dvvolkovv/taler_id_tests.git`, ветка `main`. (В CLAUDE.md в таблице репозиториев у него до сих пор стоит «—» в колонке GitHub — таблица устарела.) В рабочей копии лежат чужие незакоммиченные правки (`api_smoke_test.ts`, `mail_test.ts`), поэтому коммитить, если понадобится, только свои файлы поимённо.

**Спека:** `docs/superpowers/specs/2026-08-08-pinned-messages-design.md`

---

## Часть 1 — Бэкенд (`/Users/dmitry/taler-id`)

### Task 1: Схема и миграция

**Files:**
- Modify: `prisma/schema.prisma` (модель `Message`, модель `ConversationParticipant`)
- Create: `prisma/migrations/20260808000000_pinned_messages/migration.sql`

- [ ] **Step 1: Добавить поля в `Message`**

В `prisma/schema.prisma`, в модель `Message`, после строки `metadata Json?` добавить:

```prisma
  pinnedAt           DateTime?
  pinnedById         String?
```

и рядом с существующим `@@index([conversationId, sentAt])` добавить:

```prisma
  @@index([conversationId, pinnedAt])
```

- [ ] **Step 2: Добавить поле в `ConversationParticipant`**

В модель `ConversationParticipant`, после `lastReadMessageId String?`, добавить:

```prisma
  pinsDismissedAt   DateTime?
```

- [ ] **Step 3: Написать миграцию руками**

Миграции в этом репозитории пишутся вручную (см. `prisma/migrations/20260804000000_trusted_devices/migration.sql`), `prisma migrate dev` локально не гоняем — нет локальной БД.

Создать `prisma/migrations/20260808000000_pinned_messages/migration.sql`:

```sql
-- AlterTable
ALTER TABLE "Message" ADD COLUMN "pinnedAt" TIMESTAMP(3);
ALTER TABLE "Message" ADD COLUMN "pinnedById" TEXT;

-- CreateIndex
CREATE INDEX "Message_conversationId_pinnedAt_idx" ON "Message"("conversationId", "pinnedAt");

-- AlterTable
ALTER TABLE "ConversationParticipant" ADD COLUMN "pinsDismissedAt" TIMESTAMP(3);
```

Все колонки nullable, без DEFAULT и без NOT NULL — это обязательное условие: на PROD деплой rolling, и нода со старым кодом должна продолжать писать в таблицу во время выкатки.

- [ ] **Step 4: Сгенерировать клиент и убедиться, что схема валидна**

Run: `cd /Users/dmitry/taler-id && npx prisma generate`
Expected: `✔ Generated Prisma Client`, без ошибок валидации схемы.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/taler-id
git add prisma/schema.prisma prisma/migrations/20260808000000_pinned_messages
git commit -m "feat(messenger): schema for pinned messages"
```

---

### Task 2: `pinMessage` / `unpinMessage` в сервисе

**Files:**
- Modify: `src/messenger/messenger.service.ts`
- Test: `src/messenger/messenger.service.pins.spec.ts` (создать)

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/messenger.service.pins.spec.ts`:

```ts
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

describe('MessengerService pin/unpin', () => {
  let service: MessengerService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      conversation: { findUnique: jest.fn() },
      conversationParticipant: { findUnique: jest.fn(), update: jest.fn() },
      message: {
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
        findMany: jest.fn(),
        count: jest.fn().mockResolvedValue(1),
        create: jest.fn(),
      },
      user: { findUnique: jest.fn() },
    };
    service = new MessengerService(prisma, {} as any);
  });

  const conv = (type: string) => ({ id: 'conv-1', type });

  it('позволяет OWNER канала закрепить сообщение', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('CHANNEL'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'OWNER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt: null,
    });
    prisma.message.update.mockResolvedValue({ id: 'msg-1', pinnedAt: new Date('2026-08-08T10:00:00Z') });

    const res = await service.pinMessage('conv-1', 'msg-1', 'u-owner', { silent: true });

    expect(res.pinnedAt).toEqual(new Date('2026-08-08T10:00:00Z'));
    expect(res.alreadyPinned).toBe(false);
    expect(prisma.message.update).toHaveBeenCalled();
  });

  it('запрещает SUBSCRIBER закреплять в канале', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('CHANNEL'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'SUBSCRIBER' });

    await expect(
      service.pinMessage('conv-1', 'msg-1', 'u-sub'),
    ).rejects.toThrow(ForbiddenException);
    expect(prisma.message.update).not.toHaveBeenCalled();
  });

  it('в DIRECT закрепить может любой участник', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt: null,
    });
    prisma.message.update.mockResolvedValue({ id: 'msg-1', pinnedAt: new Date() });

    await expect(
      service.pinMessage('conv-1', 'msg-1', 'u-member', { silent: true }),
    ).resolves.toMatchObject({ alreadyPinned: false });
  });

  it('не даёт закрепить чужое сообщение из другой беседы', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-9', conversationId: 'other-conv', deletedAt: null, pinnedAt: null,
    });

    await expect(
      service.pinMessage('conv-1', 'msg-9', 'u-member'),
    ).rejects.toThrow(NotFoundException);
  });

  it('повторный пин идемпотентен — pinnedAt не переписывается', async () => {
    const pinnedAt = new Date('2026-08-01T00:00:00Z');
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt,
    });

    const res = await service.pinMessage('conv-1', 'msg-1', 'u-member');

    expect(res.alreadyPinned).toBe(true);
    expect(res.pinnedAt).toEqual(pinnedAt);
    expect(prisma.message.update).not.toHaveBeenCalled();
  });

  it('unpin снимает оба поля', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('GROUP'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'ADMIN' });
    prisma.message.updateMany.mockResolvedValue({ count: 1 });
    prisma.message.count.mockResolvedValue(0);

    const res = await service.unpinMessage('conv-1', 'msg-1', 'u-admin');

    expect(res.pinnedCount).toBe(0);
    expect(prisma.message.updateMany).toHaveBeenCalledWith({
      where: { id: 'msg-1', conversationId: 'conv-1' },
      data: { pinnedAt: null, pinnedById: null },
    });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger/messenger.service.pins.spec.ts`
Expected: FAIL — `service.pinMessage is not a function`.

- [ ] **Step 3: Реализовать**

В `src/messenger/messenger.service.ts`, в секцию `// ─── Helpers ───` (рядом с `_getConversationOrThrow`, ~строка 1201) добавить:

```ts
  /** Кто может закреплять: в канале и группе — только OWNER/ADMIN,
   *  в остальных типах бесед (DIRECT, SAVED, AI_*) — любой участник. */
  private async _assertCanPin(
    conv: { id: string; type: string },
    userId: string,
  ) {
    const me = await this.assertParticipant(conv.id, userId);
    if (
      (conv.type === 'CHANNEL' || conv.type === 'GROUP') &&
      me.role !== 'OWNER' &&
      me.role !== 'ADMIN'
    ) {
      throw new ForbiddenException('Only admins can pin in this conversation');
    }
    return me;
  }

  private _pinnedCount(conversationId: string): Promise<number> {
    return this.prisma.message.count({
      where: { conversationId, pinnedAt: { not: null }, deletedAt: null },
    });
  }
```

И публичные методы (положить рядом, перед `// ─── Polls ───`):

```ts
  // ─── Pinned messages ───

  /** Закрепить сообщение. opts.silent — не создавать сервисное сообщение
   *  (используется админским постом с pin: true, чтобы не слать второй push). */
  async pinMessage(
    conversationId: string,
    messageId: string,
    userId: string,
    opts: { silent?: boolean } = {},
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    await this._assertCanPin(conv, userId);

    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
    });
    if (!msg || msg.conversationId !== conversationId || msg.deletedAt) {
      throw new NotFoundException('Message not found');
    }
    if (msg.pinnedAt) {
      return {
        pinnedAt: msg.pinnedAt,
        pinnedCount: await this._pinnedCount(conversationId),
        alreadyPinned: true,
        systemMessageId: null as string | null,
      };
    }

    const updated = await this.prisma.message.update({
      where: { id: messageId },
      data: { pinnedAt: new Date(), pinnedById: userId },
    });

    let systemMessageId: string | null = null;
    if (!opts.silent) {
      const preview = (msg.content ?? '').slice(0, 80);
      const sys = await this._createSystemMessage(
        conversationId,
        userId,
        'message_pinned',
        undefined,
        preview,
      );
      systemMessageId = sys.id;
    }

    return {
      pinnedAt: updated.pinnedAt,
      pinnedCount: await this._pinnedCount(conversationId),
      alreadyPinned: false,
      systemMessageId,
    };
  }

  async unpinMessage(
    conversationId: string,
    messageId: string,
    userId: string,
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    await this._assertCanPin(conv, userId);
    await this.prisma.message.updateMany({
      where: { id: messageId, conversationId },
      data: { pinnedAt: null, pinnedById: null },
    });
    return { pinnedCount: await this._pinnedCount(conversationId) };
  }
```

- [ ] **Step 4: Добавить ветку в `_createSystemMessage`**

В `switch (action)` внутри `_createSystemMessage` (~строка 1220), перед `default:`, добавить:

```ts
      case 'message_pinned':
        content = JSON.stringify({
          action,
          actor: actorName,
          preview: extra ?? '',
        });
        break;
```

- [ ] **Step 5: Прогнать тест**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger/messenger.service.pins.spec.ts`
Expected: PASS, 6 тестов.

- [ ] **Step 6: Commit**

```bash
cd /Users/dmitry/taler-id
git add src/messenger/messenger.service.ts src/messenger/messenger.service.pins.spec.ts
git commit -m "feat(messenger): pin/unpin message with role checks"
```

---

### Task 3: `listPinned`, `unpinAll`, `dismissPins`

**Files:**
- Modify: `src/messenger/messenger.service.ts`
- Test: `src/messenger/messenger.service.pins.spec.ts`

- [ ] **Step 1: Дописать падающие тесты**

Добавить в конец `describe('MessengerService pin/unpin', …)` в `src/messenger/messenger.service.pins.spec.ts`:

```ts
  it('listPinned отдаёт закреплённые от новых к старым с senderName', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findMany.mockResolvedValue([
      {
        id: 'm2', content: 'second', pinnedAt: new Date('2026-08-02'),
        sender: { username: 'bob', profile: { firstName: 'Bob', lastName: null } },
      },
      {
        id: 'm1', content: 'first', pinnedAt: new Date('2026-08-01'),
        sender: { username: 'ann', profile: null },
      },
    ]);
    prisma.message.count.mockResolvedValue(2);

    const res = await service.listPinned('conv-1', 'u-member');

    expect(res.total).toBe(2);
    expect(res.messages.map((m: any) => m.id)).toEqual(['m2', 'm1']);
    expect(res.messages[0].senderName).toBe('Bob');
    expect(res.messages[1].senderName).toBe('ann');
    expect(res.messages[0].sender).toBeUndefined();
  });

  it('unpinAll снимает все пины беседы и требует прав админа', async () => {
    prisma.conversation.findUnique.mockResolvedValue({ id: 'conv-1', type: 'CHANNEL' });
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'SUBSCRIBER' });
    await expect(service.unpinAll('conv-1', 'u-sub')).rejects.toThrow(ForbiddenException);

    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'ADMIN' });
    prisma.message.updateMany.mockResolvedValue({ count: 3 });
    await expect(service.unpinAll('conv-1', 'u-admin')).resolves.toEqual({ unpinned: 3 });
  });

  it('dismissPins ставит отметку времени участнику', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.conversationParticipant.update.mockResolvedValue({});

    const res = await service.dismissPins('conv-1', 'u-member');

    expect(res.pinsDismissedAt).toBeInstanceOf(Date);
    expect(prisma.conversationParticipant.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { conversationId_userId: { conversationId: 'conv-1', userId: 'u-member' } },
      }),
    );
  });
```

- [ ] **Step 2: Убедиться, что новые тесты падают**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger/messenger.service.pins.spec.ts`
Expected: FAIL — `service.listPinned is not a function`.

- [ ] **Step 3: Реализовать**

Дописать в секцию `// ─── Pinned messages ───` в `src/messenger/messenger.service.ts`:

```ts
  async listPinned(
    conversationId: string,
    userId: string,
    limit = 50,
    offset = 0,
  ) {
    await this.assertParticipant(conversationId, userId);
    const rows = await this.prisma.message.findMany({
      where: {
        conversationId,
        pinnedAt: { not: null },
        deletedAt: null,
        NOT: { hiddenFor: { some: { userId } } },
      },
      include: {
        sender: {
          select: {
            username: true,
            profile: { select: { firstName: true, lastName: true } },
          },
        },
      },
      orderBy: { pinnedAt: 'desc' },
      take: Math.min(Math.max(limit, 1), 100),
      skip: offset,
    });
    const messages = rows.map((m: any) => {
      const u = m.sender;
      const firstLast = u
        ? [u.profile?.firstName, u.profile?.lastName]
            .filter(Boolean)
            .join(' ')
            .trim() || null
        : null;
      const { sender, ...rest } = m;
      return { ...rest, senderName: firstLast ?? u?.username ?? null };
    });
    return { messages, total: await this._pinnedCount(conversationId) };
  }

  async unpinAll(conversationId: string, userId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    await this._assertCanPin(conv, userId);
    const res = await this.prisma.message.updateMany({
      where: { conversationId, pinnedAt: { not: null } },
      data: { pinnedAt: null, pinnedById: null },
    });
    return { unpinned: res.count };
  }

  /** Спрятать плашку закреплённых лично для себя. Плашка вернётся,
   *  когда появится пин с pinnedAt позже этой отметки. */
  async dismissPins(conversationId: string, userId: string) {
    await this.assertParticipant(conversationId, userId);
    const pinsDismissedAt = new Date();
    await this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { pinsDismissedAt },
    });
    return { pinsDismissedAt };
  }
```

- [ ] **Step 4: Прогнать тест**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger/messenger.service.pins.spec.ts`
Expected: PASS, 9 тестов.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/taler-id
git add src/messenger/messenger.service.ts src/messenger/messenger.service.pins.spec.ts
git commit -m "feat(messenger): list pinned, unpin all, dismiss pins"
```

---

### Task 4: Пины в payload беседы

**Files:**
- Modify: `src/messenger/messenger.service.ts` (`getConversations`, `_formatConversation`)
- Test: `src/messenger/messenger.service.pins.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Добавить в `src/messenger/messenger.service.pins.spec.ts` новый блок (после существующего `describe`):

```ts
describe('MessengerService conversation payload — pins', () => {
  it('_formatConversation отдаёт pinnedCount, topPinned и pinsDismissedAt', () => {
    const service = new MessengerService({} as any, {} as any);
    const dismissedAt = new Date('2026-08-05T00:00:00Z');
    const pinnedAt = new Date('2026-08-06T00:00:00Z');

    const out = (service as any)._formatConversation(
      {
        id: 'conv-1',
        type: 'CHANNEL',
        participants: [{ userId: 'me', role: 'SUBSCRIBER', pinsDismissedAt: dismissedAt }],
        messages: [],
        _count: { participants: 100 },
      },
      'me',
      { sys: { username: 'talerid', profile: { firstName: 'Taler ID', lastName: '' } } },
      undefined,
      undefined,
      {
        'conv-1': {
          count: 2,
          top: { id: 'm9', content: 'x'.repeat(500), senderId: 'sys', sentAt: pinnedAt, pinnedAt },
        },
      },
    );

    expect(out.pinnedCount).toBe(2);
    expect(out.topPinned.id).toBe('m9');
    expect(out.topPinned.content).toHaveLength(200);
    expect(out.topPinned.senderName).toBe('Taler ID');
    expect(out.pinsDismissedAt).toEqual(dismissedAt);
  });

  it('без пинов отдаёт pinnedCount 0 и topPinned null', () => {
    const service = new MessengerService({} as any, {} as any);
    const out = (service as any)._formatConversation(
      { id: 'c', type: 'DIRECT', participants: [{ userId: 'me' }], messages: [] },
      'me',
    );
    expect(out.pinnedCount).toBe(0);
    expect(out.topPinned).toBeNull();
    expect(out.pinsDismissedAt).toBeNull();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger/messenger.service.pins.spec.ts -t "pinnedCount"`
Expected: FAIL — `expect(received).toBe(2)`, получено `undefined`.

- [ ] **Step 3: Расширить `_formatConversation`**

В `src/messenger/messenger.service.ts` изменить сигнатуру (строка ~458) — добавить шестой параметр:

```ts
  private _formatConversation(
    conv: any,
    currentUserId: string,
    userMap?: Record<string, any>,
    activeCallMap?: Record<string, string>,
    aliasMap?: Record<string, string>,
    pinnedMap?: Record<string, { count: number; top: any }>,
  ) {
```

Внутри, сразу после `const lastMsg = conv.messages?.[0] ?? null;`, добавить:

```ts
    const pin = pinnedMap?.[conv.id];
    const pinSender = pin?.top && userMap ? userMap[pin.top.senderId] : null;
    const pinSenderName = pinSender
      ? [pinSender.profile?.firstName, pinSender.profile?.lastName]
          .filter(Boolean)
          .join(' ')
          .trim() ||
        pinSender.username ||
        null
      : null;
```

И в возвращаемый объект, перед строкой `isSystem: conv.isSystem ? true : undefined,`, добавить:

```ts
      pinnedCount: pin?.count ?? 0,
      topPinned: pin?.top
        ? {
            id: pin.top.id,
            // Плашке хватает превью; системные посты бывают на несколько экранов.
            content: (pin.top.content ?? '').slice(0, 200),
            senderName: pinSenderName,
            sentAt: pin.top.sentAt,
            pinnedAt: pin.top.pinnedAt,
          }
        : null,
      pinsDismissedAt: myParticipant?.pinsDismissedAt ?? null,
```

- [ ] **Step 4: Наполнить `pinnedMap` в `getConversations`**

В `getConversations`, сразу после блока, где собирается массив `conversations` (`const conversations = bare.map((c) => ({ …, participants: partsByConv[c.id] ?? [] }));`), вставить:

```ts
    // Пины беседы одним запросом: rows отсортированы по pinnedAt desc,
    // поэтому первый встреченный per-conversation и есть верхний пин.
    const pinnedRows = await this.prisma.message.findMany({
      where: {
        conversationId: { in: conversations.map((c) => c.id) },
        pinnedAt: { not: null },
        deletedAt: null,
      },
      orderBy: { pinnedAt: 'desc' },
      select: {
        id: true,
        conversationId: true,
        content: true,
        senderId: true,
        sentAt: true,
        pinnedAt: true,
      },
    });
    const pinnedMap: Record<string, { count: number; top: any }> = {};
    for (const r of pinnedRows) {
      const entry = (pinnedMap[r.conversationId] ??= { count: 0, top: null });
      entry.count++;
      if (!entry.top) entry.top = r;
    }
```

В формирование `allUserIds` (следующий блок) добавить отправителей пинов, иначе `senderName` верхнего пина будет `null`:

```ts
        ...pinnedRows.map((r) => r.senderId),
```

(строкой ниже существующего `.filter((id): id is string => !!id),` — как ещё один элемент спреда внутри `new Set([...])`).

И в вызов `_formatConversation` внутри `conversations.map` (строка ~447) добавить шестой аргумент `pinnedMap`:

```ts
    return conversations.map((conv) => ({
      ...this._formatConversation(
        conv,
        userId,
        userMap,
        activeCallMap,
        aliasMap,
        pinnedMap,
      ),
      unreadCount: unreadMap[conv.id] ?? 0,
    }));
```

- [ ] **Step 5: Прогнать тесты**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger/messenger.service.pins.spec.ts`
Expected: PASS, 11 тестов.

- [ ] **Step 6: Прогнать весь набор мессенджера — проверить, что ничего не сломалось**

Run: `cd /Users/dmitry/taler-id && npx jest src/messenger`
Expected: PASS, все существующие спеки зелёные.

- [ ] **Step 7: Commit**

```bash
cd /Users/dmitry/taler-id
git add src/messenger/messenger.service.ts src/messenger/messenger.service.pins.spec.ts
git commit -m "feat(messenger): expose pinnedCount/topPinned in conversation payload"
```

---

### Task 5: REST-эндпоинты и socket-события

**Files:**
- Modify: `src/messenger/messenger.controller.ts`

- [ ] **Step 1: Добавить эндпоинты**

В `src/messenger/messenger.controller.ts`, перед секцией `// ─── Polls ───` (~строка 1176), вставить:

```ts
  // ─── Pinned messages ───

  @Post('conversations/:id/messages/:msgId/pin')
  async pinMessage(
    @Param('id') id: string,
    @Param('msgId') msgId: string,
    @CurrentUser() user: any,
  ) {
    const res = await this.service.pinMessage(id, msgId, user.sub);
    this.gateway.server.to(id).emit('message_pinned', {
      conversationId: id,
      messageId: msgId,
      pinnedById: user.sub,
      pinnedAt: res.pinnedAt,
      pinnedCount: res.pinnedCount,
    });
    // Сервисное сообщение доставляется обычным путём — оно же даёт push.
    if (res.systemMessageId) {
      const full = await this.service.getMessageById(res.systemMessageId);
      if (full) {
        await this.gateway.deliverNewMessage(
          {
            ...full,
            senderName: await this.service.getUserDisplayName(user.sub),
            reactions: [],
          },
          user.sub,
          id,
        );
      }
    }
    return res;
  }

  @Delete('conversations/:id/messages/:msgId/pin')
  async unpinMessage(
    @Param('id') id: string,
    @Param('msgId') msgId: string,
    @CurrentUser() user: any,
  ) {
    const res = await this.service.unpinMessage(id, msgId, user.sub);
    this.gateway.server.to(id).emit('message_unpinned', {
      conversationId: id,
      messageId: msgId,
      pinnedCount: res.pinnedCount,
    });
    return res;
  }

  @Get('conversations/:id/pinned')
  async listPinned(
    @Param('id') id: string,
    @Query('limit') limit: string | undefined,
    @Query('offset') offset: string | undefined,
    @CurrentUser() user: any,
  ) {
    return this.service.listPinned(
      id,
      user.sub,
      limit ? parseInt(limit, 10) : 50,
      offset ? parseInt(offset, 10) : 0,
    );
  }

  @Delete('conversations/:id/pinned')
  async unpinAll(@Param('id') id: string, @CurrentUser() user: any) {
    const res = await this.service.unpinAll(id, user.sub);
    this.gateway.server.to(id).emit('pins_cleared', { conversationId: id });
    return res;
  }

  @Post('conversations/:id/pinned/dismiss')
  async dismissPins(
    @Param('id') id: string,
    @Body() body: { upTo?: string },
    @CurrentUser() user: any,
  ) {
    // upTo — pinnedAt верхнего пина, который клиент реально видел. Мусор молча
    // игнорируем: сервис сам возьмёт максимальный pinnedAt беседы.
    const parsed = body?.upTo ? new Date(body.upTo) : undefined;
    const upTo =
      parsed && !Number.isNaN(parsed.getTime()) ? parsed : undefined;
    return this.service.dismissPins(id, user.sub, upTo);
  }
```

- [ ] **Step 2: Проверить сборку**

Run: `cd /Users/dmitry/taler-id && npm run build`
Expected: сборка без ошибок (`Successfully compiled`).

- [ ] **Step 3: Commit**

```bash
cd /Users/dmitry/taler-id
git add src/messenger/messenger.controller.ts
git commit -m "feat(messenger): REST endpoints + socket events for pins"
```

---

### Task 6: Админский путь для системного канала

**Files:**
- Modify: `src/system-channel/system-channel.service.ts`
- Modify: `src/admin/admin.controller.ts`
- Test: `src/system-channel/system-channel.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Добавить в `src/system-channel/system-channel.service.spec.ts` новый блок в конец файла:

```ts
describe('SystemChannelService.postNews with pin', () => {
  it('закрепляет пост молча — без сервисного сообщения', async () => {
    const prisma: any = {
      conversation: { findFirst: jest.fn().mockResolvedValue({ id: 'chan-1' }) },
      user: { findUnique: jest.fn().mockResolvedValue({ id: 'sys-1' }) },
      message: { findFirst: jest.fn() },
    };
    const messenger: any = {
      createMessage: jest.fn().mockResolvedValue({ id: 'msg-1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'msg-1', content: 'x' }),
      pinMessage: jest.fn().mockResolvedValue({ pinnedAt: new Date(), pinnedCount: 1 }),
    };
    const gateway: any = { deliverNewMessage: jest.fn() };
    const redis: any = { getClient: () => ({ set: jest.fn() }) };

    const svc = new SystemChannelService(prisma, gateway, messenger, redis);
    const res = await svc.postNews({ type: 'news', text_ru: 'Тест', pin: true });

    expect(res).toMatchObject({ messageId: 'msg-1', pinned: true });
    expect(messenger.pinMessage).toHaveBeenCalledWith(
      'chan-1', 'msg-1', 'sys-1', { silent: true },
    );
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd /Users/dmitry/taler-id && npx jest src/system-channel --t "закрепляет пост"`
Expected: FAIL — `pinMessage` не вызывался / `pinned` отсутствует.

- [ ] **Step 3: Реализовать в `SystemChannelService`**

В `src/system-channel/system-channel.service.ts` заменить сигнатуру и тело `postNews`:

```ts
  async postNews(dto: {
    type: 'news' | 'critical';
    text_ru: string;
    text_en?: string;
    minVersion?: string;
    pin?: boolean;
  }): Promise<{ messageId: string; pinned: boolean }> {
    const channel = await this.prisma.conversation.findFirst({ where: { isSystem: true } });
    const sysUser = await this.prisma.user.findUnique({ where: { email: SYSTEM_USER_EMAIL } });
    if (!channel || !sysUser) throw new NotFoundException('System channel is not seeded');
    const content = dto.text_en
      ? `${dto.text_ru}\n\n— EN —\n\n${dto.text_en}`
      : dto.text_ru;
    const posted = await this.post(channel.id, sysUser.id, content, {
      newsType: dto.type,
      ...(dto.minVersion ? { minVersion: dto.minVersion } : {}),
    });
    if (dto.pin) {
      // silent: сервисное сообщение о закрепе дало бы подписчикам второй push
      // сразу за самим объявлением.
      await this.messenger.pinMessage(
        channel.id,
        posted.messageId,
        sysUser.id,
        { silent: true },
      );
    }
    return { messageId: posted.messageId, pinned: !!dto.pin };
  }

  /** Закрепить/открепить существующий пост системного канала (админ-путь:
   *  живых OWNER/ADMIN в этом канале нет — владелец системный юзер). */
  async pinPost(messageId: string, pin: boolean) {
    const channel = await this.prisma.conversation.findFirst({ where: { isSystem: true } });
    const sysUser = await this.prisma.user.findUnique({ where: { email: SYSTEM_USER_EMAIL } });
    if (!channel || !sysUser) throw new NotFoundException('System channel is not seeded');
    return pin
      ? this.messenger.pinMessage(channel.id, messageId, sysUser.id, { silent: true })
      : this.messenger.unpinMessage(channel.id, messageId, sysUser.id);
  }
```

- [ ] **Step 4: Добавить эндпоинты в админ-контроллер**

В `src/admin/admin.controller.ts` заменить тело `postSystemNews` и добавить два эндпоинта:

```ts
  @Post('system-channel/post')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  async postSystemNews(
    @Body()
    body: {
      type: 'news' | 'critical';
      text_ru: string;
      text_en?: string;
      minVersion?: string;
      pin?: boolean;
    },
  ) {
    if (!body?.text_ru || !['news', 'critical'].includes(body?.type)) {
      throw new BadRequestException('type (news|critical) and text_ru are required');
    }
    return this.systemChannel.postNews(body);
  }

  @Post('system-channel/pin')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  async pinSystemPost(@Body() body: { messageId: string }) {
    if (!body?.messageId) throw new BadRequestException('messageId is required');
    return this.systemChannel.pinPost(body.messageId, true);
  }

  @Post('system-channel/unpin')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  async unpinSystemPost(@Body() body: { messageId: string }) {
    if (!body?.messageId) throw new BadRequestException('messageId is required');
    return this.systemChannel.pinPost(body.messageId, false);
  }
```

- [ ] **Step 5: Прогнать тесты и сборку**

Run: `cd /Users/dmitry/taler-id && npx jest src/system-channel && npm run build`
Expected: тесты PASS, сборка без ошибок.

- [ ] **Step 6: Commit**

```bash
cd /Users/dmitry/taler-id
git add src/system-channel/system-channel.service.ts src/system-channel/system-channel.service.spec.ts src/admin/admin.controller.ts
git commit -m "feat(admin): pin system-channel posts"
```

---

## Часть 2 — E2E тесты (`/Users/dmitry/Downloads/taler_id_tests`)

### Task 7: Набор `test:pins`

**Files:**
- Create: `/Users/dmitry/Downloads/taler_id_tests/pins_test.ts`
- Modify: `/Users/dmitry/Downloads/taler_id_tests/package.json`

- [ ] **Step 1: Написать тест**

Создать `/Users/dmitry/Downloads/taler_id_tests/pins_test.ts`:

```ts
import axios from 'axios';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const USER1 = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };
const USER2 = { email: 'integration_test_2@taler-test.com', password: 'IntegrationTest123!' };

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true });

async function login(creds: { email: string; password: string }): Promise<string> {
  const res = await http.post('/auth/login', creds);
  if (res.status !== 200) throw new Error(`login ${res.status}: ${JSON.stringify(res.data)}`);
  return res.data.accessToken as string;
}
function auth(token: string) { return { headers: { Authorization: `Bearer ${token}` } }; }

let failed = 0, passed = 0;
function check(name: string, cond: boolean, info?: unknown) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`, info ?? ''); failed++; }
}

async function main() {
  const t1 = await login(USER1);
  const t2 = await login(USER2);
  console.log('Logged in both users');

  // Канал: user1 — OWNER, user2 — SUBSCRIBER
  const ch = await http.post('/messenger/channels',
    { name: `PinCh ${Date.now()}`, description: 'pins smoke' }, auth(t1));
  const channelId = ch.data?.id as string;
  check('0. канал создан', typeof channelId === 'string', ch.data);
  await http.post(`/messenger/channels/${channelId}/subscribe`, {}, auth(t2));

  const p1 = await http.post(`/messenger/channels/${channelId}/post`, { content: 'первый' }, auth(t1));
  const p2 = await http.post(`/messenger/channels/${channelId}/post`, { content: 'второй' }, auth(t1));
  const m1 = p1.data?.messageId as string;
  const m2 = p2.data?.messageId as string;
  check('0b. два поста созданы', !!m1 && !!m2, { m1, m2 });

  // 1. OWNER закрепляет
  const pin1 = await http.post(`/messenger/conversations/${channelId}/messages/${m1}/pin`, {}, auth(t1));
  check('1. OWNER pin → 200/201', pin1.status === 200 || pin1.status === 201, pin1.data);
  check('1b. pinnedCount === 1', pin1.data?.pinnedCount === 1, pin1.data);

  // 2. идемпотентность
  const pin1again = await http.post(`/messenger/conversations/${channelId}/messages/${m1}/pin`, {}, auth(t1));
  check('2. повторный pin → alreadyPinned', pin1again.data?.alreadyPinned === true, pin1again.data);
  check('2b. pinnedCount не вырос', pin1again.data?.pinnedCount === 1, pin1again.data);

  // 3. SUBSCRIBER не может
  const pinU2 = await http.post(`/messenger/conversations/${channelId}/messages/${m2}/pin`, {}, auth(t2));
  check('3. SUBSCRIBER pin → 403', pinU2.status === 403, pinU2.status);

  // 4. второй пин + порядок
  await http.post(`/messenger/conversations/${channelId}/messages/${m2}/pin`, {}, auth(t1));
  const list = await http.get(`/messenger/conversations/${channelId}/pinned`, auth(t2));
  check('4. GET /pinned → 200', list.status === 200);
  check('4b. total === 2', list.data?.total === 2, list.data);
  check('4c. новый пин первым', list.data?.messages?.[0]?.id === m2, list.data?.messages?.map((m: any) => m.id));

  // 5. пины в payload беседы
  const convs = await http.get('/messenger/conversations', auth(t2));
  const conv = (convs.data as any[]).find(c => c.id === channelId);
  check('5. pinnedCount в списке бесед === 2', conv?.pinnedCount === 2, conv?.pinnedCount);
  check('5b. topPinned — последний закреплённый', conv?.topPinned?.id === m2, conv?.topPinned);
  check('5c. pinsDismissedAt пуст', conv?.pinsDismissedAt == null, conv?.pinsDismissedAt);

  // 6. dismiss
  const dismiss = await http.post(`/messenger/conversations/${channelId}/pinned/dismiss`, {}, auth(t2));
  check('6. dismiss → 200/201', dismiss.status === 200 || dismiss.status === 201, dismiss.data);
  const convs2 = await http.get('/messenger/conversations', auth(t2));
  const conv2 = (convs2.data as any[]).find(c => c.id === channelId);
  check('6b. pinsDismissedAt выставлен', !!conv2?.pinsDismissedAt, conv2?.pinsDismissedAt);
  // ⚠️ Именно строгое равенство. `>=` здесь бесполезно: ему удовлетворяет и
  // правильное поведение (штамп = MAX(pinnedAt)), и регрессия обратно к
  // `new Date()`, от которой ушли в Task 3. Проверка, которая не может
  // упасть, хуже её отсутствия — она создаёт ложную уверенность.
  check('6c. dismissedAt равен pinnedAt верхнего пина (сервер взял MAX, а не «сейчас»)',
    new Date(conv2.pinsDismissedAt).getTime() === new Date(conv2.topPinned.pinnedAt).getTime(),
    { d: conv2?.pinsDismissedAt, p: conv2?.topPinned?.pinnedAt });

  // 7. новый пин возвращает плашку
  const p3 = await http.post(`/messenger/channels/${channelId}/post`, { content: 'третий' }, auth(t1));
  const m3 = p3.data?.messageId as string;
  await http.post(`/messenger/conversations/${channelId}/messages/${m3}/pin`, {}, auth(t1));
  const convs3 = await http.get('/messenger/conversations', auth(t2));
  const conv3 = (convs3.data as any[]).find(c => c.id === channelId);
  check('7. после нового пина плашка снова видна',
    new Date(conv3.topPinned.pinnedAt) > new Date(conv3.pinsDismissedAt),
    { p: conv3?.topPinned?.pinnedAt, d: conv3?.pinsDismissedAt });

  // 8. unpin
  const unpin = await http.delete(`/messenger/conversations/${channelId}/messages/${m3}/pin`, auth(t1));
  check('8. unpin → 200', unpin.status === 200, unpin.data);
  check('8b. pinnedCount === 2', unpin.data?.pinnedCount === 2, unpin.data);

  // 9. SUBSCRIBER не может открепить всё
  const clearU2 = await http.delete(`/messenger/conversations/${channelId}/pinned`, auth(t2));
  check('9. SUBSCRIBER unpin-all → 403', clearU2.status === 403, clearU2.status);

  // 10. unpin all
  const clear = await http.delete(`/messenger/conversations/${channelId}/pinned`, auth(t1));
  check('10. unpin all → 200', clear.status === 200, clear.data);
  const listAfter = await http.get(`/messenger/conversations/${channelId}/pinned`, auth(t1));
  check('10b. пинов не осталось', listAfter.data?.total === 0, listAfter.data);

  // 11. не-участник не видит список
  const stranger = await http.get(`/messenger/conversations/${channelId}/pinned`);
  check('11. без токена → 401', stranger.status === 401, stranger.status);

  // cleanup
  await http.delete(`/messenger/channels/${channelId}`, auth(t1));

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 2: Добавить npm-скрипты**

В `/Users/dmitry/Downloads/taler_id_tests/package.json`, в `scripts`, рядом с `test:channels`, добавить:

```json
    "test:pins": "BASE_URL=https://staging.id.taler.tirol npx ts-node pins_test.ts",
    "test:pins:prod": "BASE_URL=https://id.taler.tirol npx ts-node pins_test.ts",
```

- [ ] **Step 3: Прогнать (после деплоя на DEV в Task 14 — сейчас должен падать)**

Run: `cd /Users/dmitry/Downloads/taler_id_tests && npm run test:pins`
Expected сейчас: FAIL на шаге 1 (404, эндпоинта на DEV ещё нет). Это ожидаемо — набор зелёный только после Task 14.

---

## Часть 3 — Мобилка (`/Users/dmitry/Downloads/taler_id_mobile`)

### Task 8: Ветка и модели данных

**Files:**
- Modify: `lib/features/messenger/domain/entities/message_entity.dart`
- Modify: `lib/features/messenger/domain/entities/conversation_entity.dart`
- Create: `lib/features/messenger/domain/entities/pinned_preview_entity.dart`

- [ ] **Step 1: Создать ветку от `dev`**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git fetch origin --quiet
git checkout dev && git pull --ff-only
git checkout -b feature/pinned-messages
```

- [ ] **Step 2: Добавить поля в `MessageEntity`**

В `lib/features/messenger/domain/entities/message_entity.dart`, в конструктор, после `String? transport,`, добавить:

```dart
    /// Закрепление: null — сообщение не закреплено.
    DateTime? pinnedAt,
    String? pinnedById,
```

- [ ] **Step 3: Создать `PinnedPreviewEntity`**

Создать `lib/features/messenger/domain/entities/pinned_preview_entity.dart`:

```dart
import 'package:freezed_annotation/freezed_annotation.dart';

part 'pinned_preview_entity.freezed.dart';
part 'pinned_preview_entity.g.dart';

/// Превью верхнего закреплённого сообщения — приходит в payload беседы,
/// чтобы плашка отрисовалась до загрузки полного списка пинов.
@freezed
class PinnedPreviewEntity with _$PinnedPreviewEntity {
  const factory PinnedPreviewEntity({
    required String id,
    @Default('') String content,
    String? senderName,
    DateTime? sentAt,
    DateTime? pinnedAt,
  }) = _PinnedPreviewEntity;

  factory PinnedPreviewEntity.fromJson(Map<String, dynamic> json) =>
      _$PinnedPreviewEntityFromJson(json);
}
```

- [ ] **Step 4: Добавить поля в `ConversationEntity`**

В `lib/features/messenger/domain/entities/conversation_entity.dart` добавить импорт:

```dart
import 'pinned_preview_entity.dart';
```

и в конструктор, после `int? autoDeleteDays,`, добавить:

```dart
    @Default(0) int pinnedCount,
    PinnedPreviewEntity? topPinned,
    DateTime? pinsDismissedAt,
```

- [ ] **Step 5: Перегенерировать freezed/json**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && dart run build_runner build --delete-conflicting-outputs`
Expected: `Succeeded after …` без ошибок; появились `pinned_preview_entity.freezed.dart` и `.g.dart`.

- [ ] **Step 6: Проверить анализатор**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib/features/messenger/domain`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай.

- [ ] **Step 7: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/messenger/domain/entities
git commit -m "feat(messenger): pin fields on message and conversation entities"
```

---

### Task 9: Datasource — REST-методы и socket-стримы

**Files:**
- Modify: `lib/features/messenger/data/datasources/messenger_remote_datasource.dart`
- Modify: `lib/features/messenger/domain/repositories/i_messenger_repository.dart`
- Modify: `lib/features/messenger/data/repositories/messenger_repository_impl.dart`

- [ ] **Step 1: Добавить стримы в datasource**

В `lib/features/messenger/data/datasources/messenger_remote_datasource.dart`, рядом с другими контроллерами (`_groupUpdatedCtrl` и соседями), объявить:

```dart
  final _messagePinnedCtrl = StreamController<Map<String, dynamic>>.broadcast();
  final _messageUnpinnedCtrl = StreamController<Map<String, dynamic>>.broadcast();
  final _pinsClearedCtrl = StreamController<Map<String, dynamic>>.broadcast();

  Stream<Map<String, dynamic>> get messagePinnedStream => _messagePinnedCtrl.stream;
  Stream<Map<String, dynamic>> get messageUnpinnedStream => _messageUnpinnedCtrl.stream;
  Stream<Map<String, dynamic>> get pinsClearedStream => _pinsClearedCtrl.stream;
```

- [ ] **Step 2: Подписаться на socket-события**

В том же файле, в блоке где регистрируются `_socket!.on('group_…')` (~строка 162), добавить:

```dart
    // Pinned messages
    _socket!.on('message_pinned', (d) {
      try { _messagePinnedCtrl.add(Map<String, dynamic>.from(d as Map)); } catch (_) {}
    });
    _socket!.on('message_unpinned', (d) {
      try { _messageUnpinnedCtrl.add(Map<String, dynamic>.from(d as Map)); } catch (_) {}
    });
    _socket!.on('pins_cleared', (d) {
      try { _pinsClearedCtrl.add(Map<String, dynamic>.from(d as Map)); } catch (_) {}
    });
```

- [ ] **Step 3: Добавить REST-методы**

В тот же файл, рядом с `muteConversation` (~строка 625), добавить:

```dart
  Future<Map<String, dynamic>> pinMessage(String conversationId, String messageId) {
    return _http.post(
      '/messenger/conversations/$conversationId/messages/$messageId/pin',
      data: {},
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
  }

  Future<Map<String, dynamic>> unpinMessage(String conversationId, String messageId) {
    return _http.delete(
      '/messenger/conversations/$conversationId/messages/$messageId/pin',
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
  }

  Future<List<MessageEntity>> getPinnedMessages(String conversationId) async {
    final data = await _http.get<Map<String, dynamic>>(
      '/messenger/conversations/$conversationId/pinned',
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
    final list = (data['messages'] as List?) ?? const [];
    return list
        .map((e) => MessageEntity.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<Map<String, dynamic>> unpinAll(String conversationId) {
    return _http.delete(
      '/messenger/conversations/$conversationId/pinned',
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
  }

  /// [upTo] — pinnedAt верхнего пина, который пользователь реально видел.
  /// Без него бэкенд возьмёт максимальный pinnedAt беседы, и пин, прилетевший
  /// пока запрос шёл, окажется скрыт молча.
  Future<Map<String, dynamic>> dismissPins(String conversationId, {DateTime? upTo}) {
    return _http.post(
      '/messenger/conversations/$conversationId/pinned/dismiss',
      data: {if (upTo != null) 'upTo': upTo.toUtc().toIso8601String()},
      fromJson: (d) => Map<String, dynamic>.from(d as Map),
    );
  }
```

Если у `_http` сигнатура `delete` отличается от использованной — свериться с соседним вызовом `unsubscribeFromChannel` в этом же файле и повторить его форму.

- [ ] **Step 4: Пробросить через репозиторий**

В `lib/features/messenger/domain/repositories/i_messenger_repository.dart`, рядом с `muteConversation` (строка ~64), добавить:

```dart
  Future<Map<String, dynamic>> pinMessage(String conversationId, String messageId);
  Future<Map<String, dynamic>> unpinMessage(String conversationId, String messageId);
  Future<List<MessageEntity>> getPinnedMessages(String conversationId);
  Future<Map<String, dynamic>> unpinAll(String conversationId);
  Future<Map<String, dynamic>> dismissPins(String conversationId, {DateTime? upTo});
  Stream<Map<String, dynamic>> get messagePinnedStream;
  Stream<Map<String, dynamic>> get messageUnpinnedStream;
  Stream<Map<String, dynamic>> get pinsClearedStream;
```

В `lib/features/messenger/data/repositories/messenger_repository_impl.dart`, рядом с реализацией `muteConversation` (строка ~396), добавить:

```dart
  @override
  Future<Map<String, dynamic>> pinMessage(String conversationId, String messageId) =>
      _remote.pinMessage(conversationId, messageId);

  @override
  Future<Map<String, dynamic>> unpinMessage(String conversationId, String messageId) =>
      _remote.unpinMessage(conversationId, messageId);

  @override
  Future<List<MessageEntity>> getPinnedMessages(String conversationId) =>
      _remote.getPinnedMessages(conversationId);

  @override
  Future<Map<String, dynamic>> unpinAll(String conversationId) =>
      _remote.unpinAll(conversationId);

  @override
  Future<Map<String, dynamic>> dismissPins(String conversationId, {DateTime? upTo}) =>
      _remote.dismissPins(conversationId, upTo: upTo);

  @override
  Stream<Map<String, dynamic>> get messagePinnedStream => _remote.messagePinnedStream;

  @override
  Stream<Map<String, dynamic>> get messageUnpinnedStream => _remote.messageUnpinnedStream;

  @override
  Stream<Map<String, dynamic>> get pinsClearedStream => _remote.pinsClearedStream;
```

Имя приватного поля datasource в этом файле может отличаться (`_remote` / `_dataSource`) — свериться с соседней реализацией `muteConversation` и использовать то же.

- [ ] **Step 5: Проверить анализатор**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib/features/messenger/data lib/features/messenger/domain`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай.

- [ ] **Step 6: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/messenger/data lib/features/messenger/domain
git commit -m "feat(messenger): datasource + repository plumbing for pins"
```

---

### Task 10: BLoC — события и обработчики

**Files:**
- Modify: `lib/features/messenger/presentation/bloc/messenger_event.dart`
- Modify: `lib/features/messenger/presentation/bloc/messenger_bloc.dart`

- [ ] **Step 1: Добавить события**

В `lib/features/messenger/presentation/bloc/messenger_event.dart`, в конец файла:

```dart
class PinMessage extends MessengerEvent {
  final String conversationId;
  final String messageId;
  const PinMessage(this.conversationId, this.messageId);
  @override
  List<Object?> get props => [conversationId, messageId];
}

class UnpinMessage extends MessengerEvent {
  final String conversationId;
  final String messageId;
  const UnpinMessage(this.conversationId, this.messageId);
  @override
  List<Object?> get props => [conversationId, messageId];
}

class UnpinAllMessages extends MessengerEvent {
  final String conversationId;
  const UnpinAllMessages(this.conversationId);
  @override
  List<Object?> get props => [conversationId];
}

class DismissPins extends MessengerEvent {
  final String conversationId;
  /// pinnedAt верхнего пина, который пользователь видел в плашке.
  final DateTime? upTo;
  const DismissPins(this.conversationId, {this.upTo});
  @override
  List<Object?> get props => [conversationId, upTo];
}

/// Socket: message_pinned / message_unpinned / pins_cleared
class PinEventReceived extends MessengerEvent {
  final String type;
  final Map<String, dynamic> data;
  const PinEventReceived(this.type, this.data);
  @override
  List<Object?> get props => [type, data];
}
```

Базовый класс событий в этом файле — `MessengerEvent` с `Equatable`; свериться с соседним событием (например `MarkConversationRead`) и повторить его форму, если конструкторы там не `const`.

- [ ] **Step 2: Подписаться на стримы**

В `lib/features/messenger/presentation/bloc/messenger_bloc.dart`, там где идут подписки на групповые стримы (~строка 255), добавить поля и подписки:

```dart
  StreamSubscription? _pinnedSub;
  StreamSubscription? _unpinnedSub;
  StreamSubscription? _pinsClearedSub;
```

```dart
    _pinnedSub?.cancel();
    _pinnedSub = _repo.messagePinnedStream.listen((data) {
      add(PinEventReceived('message_pinned', data));
    });
    _unpinnedSub?.cancel();
    _unpinnedSub = _repo.messageUnpinnedStream.listen((data) {
      add(PinEventReceived('message_unpinned', data));
    });
    _pinsClearedSub?.cancel();
    _pinsClearedSub = _repo.pinsClearedStream.listen((data) {
      add(PinEventReceived('pins_cleared', data));
    });
```

В `close()` (там же, где отменяются остальные подписки) добавить:

```dart
    _pinnedSub?.cancel();
    _unpinnedSub?.cancel();
    _pinsClearedSub?.cancel();
```

- [ ] **Step 3: Зарегистрировать обработчики**

В конструкторе блока, рядом с другими `on<…>` регистрациями, добавить:

```dart
    on<PinMessage>(_onPinMessage);
    on<UnpinMessage>(_onUnpinMessage);
    on<UnpinAllMessages>(_onUnpinAll);
    on<DismissPins>(_onDismissPins);
    on<PinEventReceived>(_onPinEvent);
```

И сами обработчики (в конец класса):

```dart
  Future<void> _onPinMessage(PinMessage e, Emitter<MessengerState> emit) async {
    try {
      final res = await _repo.pinMessage(e.conversationId, e.messageId);
      emit(_withPinCount(state, e.conversationId, res['pinnedCount'] as int? ?? 0));
    } catch (err) {
      emit(state.copyWith(error: err.toString()));
    }
  }

  Future<void> _onUnpinMessage(UnpinMessage e, Emitter<MessengerState> emit) async {
    try {
      final res = await _repo.unpinMessage(e.conversationId, e.messageId);
      emit(_withPinCount(state, e.conversationId, res['pinnedCount'] as int? ?? 0));
    } catch (err) {
      emit(state.copyWith(error: err.toString()));
    }
  }

  Future<void> _onUnpinAll(UnpinAllMessages e, Emitter<MessengerState> emit) async {
    try {
      await _repo.unpinAll(e.conversationId);
      emit(_withPinCount(state, e.conversationId, 0));
    } catch (err) {
      emit(state.copyWith(error: err.toString()));
    }
  }

  Future<void> _onDismissPins(DismissPins e, Emitter<MessengerState> emit) async {
    try {
      final res = await _repo.dismissPins(e.conversationId, upTo: e.upTo);
      final at = DateTime.tryParse(res['pinsDismissedAt']?.toString() ?? '');
      emit(state.copyWith(
        conversations: state.conversations
            .map((c) => c.id == e.conversationId ? c.copyWith(pinsDismissedAt: at) : c)
            .toList(),
      ));
    } catch (err) {
      emit(state.copyWith(error: err.toString()));
    }
  }

  Future<void> _onPinEvent(PinEventReceived e, Emitter<MessengerState> emit) async {
    final convId = e.data['conversationId'] as String?;
    if (convId == null) return;
    final count = e.type == 'pins_cleared'
        ? 0
        : (e.data['pinnedCount'] as int? ?? 0);
    emit(_withPinCount(state, convId, count));
  }

  /// Обновляет счётчик пинов беседы. Сам список пинов плашка перезапрашивает
  /// сама, увидев изменившийся pinnedCount — держать его в state незачем.
  MessengerState _withPinCount(MessengerState s, String convId, int count) {
    return s.copyWith(
      conversations: s.conversations
          .map((c) => c.id == convId ? c.copyWith(pinnedCount: count) : c)
          .toList(),
    );
  }
```

- [ ] **Step 4: Проверить анализатор**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib/features/messenger/presentation/bloc`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/messenger/presentation/bloc
git commit -m "feat(messenger): bloc events and handlers for pins"
```

---

### Task 11: Строки локализации

**Files:**
- Modify: `lib/l10n/app_en.arb`
- Modify: `lib/l10n/app_ru.arb`

- [ ] **Step 1: Добавить ключи в `app_en.arb`**

Вставить (перед закрывающей скобкой файла, с запятой после предыдущего ключа):

```json
  "pinnedMessage": "Pinned message",
  "@pinnedMessage": {},
  "pinnedMessagesTitle": "Pinned",
  "@pinnedMessagesTitle": {},
  "pinAction": "Pin",
  "@pinAction": {},
  "unpinAction": "Unpin",
  "@unpinAction": {},
  "unpinAllAction": "Unpin all",
  "@unpinAllAction": {},
  "noPinnedMessages": "No pinned messages",
  "@noPinnedMessages": {},
  "pinnedCounter": "{current} of {total}",
  "@pinnedCounter": {
    "placeholders": { "current": { "type": "int" }, "total": { "type": "int" } }
  },
  "messagePinnedBy": "{actor} pinned a message",
  "@messagePinnedBy": {
    "placeholders": { "actor": { "type": "String" } }
  },
  "unpinAllConfirm": "Unpin all messages in this chat?",
  "@unpinAllConfirm": {}
```

- [ ] **Step 2: Добавить те же ключи в `app_ru.arb`**

```json
  "pinnedMessage": "Закреплённое сообщение",
  "pinnedMessagesTitle": "Закреплённые",
  "pinAction": "Закрепить",
  "unpinAction": "Открепить",
  "unpinAllAction": "Открепить всё",
  "noPinnedMessages": "Нет закреплённых сообщений",
  "pinnedCounter": "{current} из {total}",
  "messagePinnedBy": "{actor} закрепил сообщение",
  "unpinAllConfirm": "Открепить все сообщения в этом чате?"
```

Остальные 22 локали руками не трогаем — `gen-l10n` дотянет их из английского шаблона (так сделаны все прошлые фичи, см. коммит `5cf9894`).

- [ ] **Step 3: Сгенерировать локализации**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter gen-l10n`
Expected: без ошибок; в `lib/l10n/app_localizations.dart` появились новые геттеры.

- [ ] **Step 4: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/l10n
git commit -m "i18n: strings for pinned messages"
```

---

### Task 12: Плашка закреплённого в чате

**Files:**
- Create: `lib/features/messenger/presentation/widgets/pinned_banner.dart`
- Modify: `lib/features/messenger/presentation/screens/chat_room_screen.dart`
- Test: `test/features/messenger/pinned_banner_test.dart` (создать)

> ⚠️ **Счётчик рисуем по загруженному списку, а не по `pinnedCount`.** `pinnedCount` пишут двое: ответ REST-вызова и собственное socket-эхо того же действия (бэкенд рассылает `server.to(room)`, то есть и инициатору тоже), причём порядок между двумя очередями событий не гарантирован — счётчик может кратковременно разъехаться. Поэтому плашка использует `pinnedCount` **только как триггер перезагрузки списка**, а показывает `pins.length`: тогда неверный счётчик стоит лишнего перезапроса, но никогда не даёт неверную картинку. (Нашло ревью Task 10.)

- [ ] **Step 1: Написать падающий виджет-тест**

Создать `test/features/messenger/pinned_banner_test.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';
import 'package:taler_id_mobile/features/messenger/domain/entities/message_entity.dart';
import 'package:taler_id_mobile/features/messenger/presentation/widgets/pinned_banner.dart';

MessageEntity pin(String id, String text, DateTime at) => MessageEntity(
      id: id,
      conversationId: 'c1',
      senderId: 's1',
      content: text,
      sentAt: at,
      pinnedAt: at,
    );

Widget wrap(Widget child) => MaterialApp(
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      supportedLocales: const [Locale('en')],
      home: Scaffold(body: child),
    );

void main() {
  final now = DateTime(2026, 8, 8, 12);

  testWidgets('показывает текст верхнего пина и счётчик', (tester) async {
    await tester.pumpWidget(wrap(PinnedBanner(
      pins: [pin('m2', 'второй', now), pin('m1', 'первый', now.subtract(const Duration(days: 1)))],
      onJump: (_) {},
      onDismiss: () {},
      onOpenList: () {},
    )));

    expect(find.text('второй'), findsOneWidget);
    expect(find.text('1 of 2'), findsOneWidget);
  });

  testWidgets('тап переключает на следующий пин', (tester) async {
    await tester.pumpWidget(wrap(PinnedBanner(
      pins: [pin('m2', 'второй', now), pin('m1', 'первый', now.subtract(const Duration(days: 1)))],
      onJump: (_) {},
      onDismiss: () {},
      onOpenList: () {},
    )));

    await tester.tap(find.text('второй'));
    await tester.pumpAndSettle();

    expect(find.text('первый'), findsOneWidget);
    expect(find.text('2 of 2'), findsOneWidget);
  });

  testWidgets('крестик зовёт onDismiss', (tester) async {
    var dismissed = false;
    await tester.pumpWidget(wrap(PinnedBanner(
      pins: [pin('m1', 'первый', now)],
      onJump: (_) {},
      onDismiss: () => dismissed = true,
      onOpenList: () {},
    )));

    await tester.tap(find.byIcon(Icons.close_rounded));
    await tester.pump();

    expect(dismissed, isTrue);
  });

  testWidgets('пустой список — ничего не рисует', (tester) async {
    await tester.pumpWidget(wrap(PinnedBanner(
      pins: const [],
      onJump: (_) {},
      onDismiss: () {},
      onOpenList: () {},
    )));

    expect(find.byIcon(Icons.close_rounded), findsNothing);
  });
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter test test/features/messenger/pinned_banner_test.dart`
Expected: FAIL — `Error: Couldn't resolve the package 'pinned_banner.dart'`.

- [ ] **Step 3: Написать виджет**

Создать `lib/features/messenger/presentation/widgets/pinned_banner.dart`:

```dart
import 'package:flutter/material.dart';

import '../../../../core/theme/app_colors.dart';
import '../../../../l10n/app_localizations.dart';
import '../../domain/entities/message_entity.dart';

/// Плашка закреплённых сообщений — по образцу Telegram.
/// Тап по тексту прыгает к текущему пину и переключает на следующий,
/// «×» прячет плашку у себя, иконка списка открывает экран закреплённых.
class PinnedBanner extends StatefulWidget {
  final List<MessageEntity> pins;
  final void Function(String messageId) onJump;
  final VoidCallback onDismiss;
  final VoidCallback onOpenList;

  const PinnedBanner({
    super.key,
    required this.pins,
    required this.onJump,
    required this.onDismiss,
    required this.onOpenList,
  });

  @override
  State<PinnedBanner> createState() => _PinnedBannerState();
}

class _PinnedBannerState extends State<PinnedBanner> {
  int _index = 0;

  @override
  void didUpdateWidget(covariant PinnedBanner oldWidget) {
    super.didUpdateWidget(oldWidget);
    // Список пинов мог схлопнуться (открепили) — не оставлять индекс за краем.
    if (_index >= widget.pins.length) _index = 0;
  }

  void _next() {
    if (widget.pins.isEmpty) return;
    widget.onJump(widget.pins[_index].id);
    setState(() => _index = (_index + 1) % widget.pins.length);
  }

  @override
  Widget build(BuildContext context) {
    if (widget.pins.isEmpty) return const SizedBox.shrink();
    final l10n = AppLocalizations.of(context)!;
    final colors = AppColors.of(context);
    final current = widget.pins[_index];
    final preview = current.content.replaceAll('\n', ' ').trim();

    return Material(
      color: colors.surface,
      child: InkWell(
        onTap: _next,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(color: colors.primary.withValues(alpha: 0.2)),
            ),
          ),
          child: Row(
            children: [
              Container(width: 3, height: 32, color: colors.primary),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      widget.pins.length > 1
                          ? l10n.pinnedCounter(_index + 1, widget.pins.length)
                          : l10n.pinnedMessage,
                      style: TextStyle(
                        color: colors.primary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    Text(
                      preview,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(color: colors.textSecondary, fontSize: 13),
                    ),
                  ],
                ),
              ),
              IconButton(
                icon: const Icon(Icons.format_list_bulleted_rounded, size: 18),
                color: colors.textSecondary,
                tooltip: l10n.pinnedMessagesTitle,
                onPressed: widget.onOpenList,
              ),
              IconButton(
                icon: const Icon(Icons.close_rounded, size: 18),
                color: colors.textSecondary,
                onPressed: widget.onDismiss,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

Если в `AppColors` нет полей `surface` / `textSecondary` / `primary` под этими именами — свериться с `_ConnectivityBanner` в `chat_room_screen.dart` и взять те же.

- [ ] **Step 4: Прогнать тест**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter test test/features/messenger/pinned_banner_test.dart`
Expected: PASS, 4 теста.

- [ ] **Step 5: Встроить плашку в чат**

В `lib/features/messenger/presentation/screens/chat_room_screen.dart` добавить импорты:

```dart
import '../widgets/pinned_banner.dart';
import 'pinned_messages_screen.dart';
```

В состояние экрана (`_ChatRoomScreenState`) добавить поля и загрузку:

```dart
  List<MessageEntity> _pins = const [];
  int _pinsLoadedForCount = -1;

  Future<void> _loadPins(int pinnedCount) async {
    if (_pinsLoadedForCount == pinnedCount) return;
    _pinsLoadedForCount = pinnedCount;
    if (pinnedCount == 0) {
      if (mounted) setState(() => _pins = const []);
      return;
    }
    try {
      final pins = await sl<IMessengerRepository>()
          .getPinnedMessages(widget.conversationId);
      if (mounted) setState(() => _pins = pins);
    } catch (_) {
      // Плашка — украшение поверх чата: молча остаёмся без неё.
    }
  }
```

`sl` и `IMessengerRepository` уже импортированы в файле; если нет — добавить `import '../../../../core/di/service_locator.dart';` и импорт интерфейса репозитория (свериться с тем, как экран получает другие зависимости).

В `builder:` блока `BlocBuilder` (~строка 2289), сразу после `final conv = _resolveConv(state.conversations);`, добавить:

```dart
          final pinnedCount = conv?.pinnedCount ?? 0;
          // Плашку прячем, если пользователь её закрыл и с тех пор новых пинов не было.
          final dismissedAt = conv?.pinsDismissedAt;
          final topPinnedAt = conv?.topPinned?.pinnedAt;
          final pinsHidden = dismissedAt != null &&
              (topPinnedAt == null || !topPinnedAt.isAfter(dismissedAt));
          WidgetsBinding.instance.addPostFrameCallback((_) => _loadPins(pinnedCount));
```

И в `Column(children: [...])` (~строка 2305), сразу после `_ConnectivityBanner`, добавить:

```dart
              if (pinnedCount > 0 && !pinsHidden && _pins.isNotEmpty)
                PinnedBanner(
                  pins: _pins,
                  onJump: (messageId) {
                    final msgs = _messengerBloc.state.messages[widget.conversationId] ?? [];
                    final idx = msgs.indexWhere((m) => m.id == messageId);
                    if (idx >= 0) {
                      setState(() {
                        _searchMatchChronIndices = [idx];
                        _searchCurrentMatchIdx = 0;
                      });
                      _scrollToChronIndex(idx);
                    }
                  },
                  // upTo — pinnedAt самого свежего пина, который пользователь
                  // видел; без него бэкенд скроет и пин, прилетевший в момент
                  // нажатия «×».
                  onDismiss: () => _messengerBloc.add(DismissPins(
                    widget.conversationId,
                    upTo: _pins.first.pinnedAt,
                  )),
                  onOpenList: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => PinnedMessagesScreen(
                        conversationId: widget.conversationId,
                        canUnpin: _canPin(conv),
                      ),
                    ),
                  ),
                ),
```

- [ ] **Step 6: Добавить хелпер прав**

В `_ChatRoomScreenState` добавить:

```dart
  /// Кто может закреплять: в канале и группе — OWNER/ADMIN,
  /// в остальных беседах — любой участник (зеркалит бэкендский _assertCanPin).
  bool _canPin(ConversationEntity? conv) {
    if (conv == null) return false;
    if (conv.type == 'CHANNEL' || conv.type == 'GROUP') {
      return conv.myRole == 'OWNER' || conv.myRole == 'ADMIN';
    }
    return true;
  }
```

- [ ] **Step 7: Прогнать анализатор и тесты**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib/features/messenger && flutter test test/features/messenger/pinned_banner_test.dart`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай. и PASS. (`pinned_messages_screen.dart` создаётся в Task 13 — если анализатор ругается на отсутствующий импорт, выполнить Task 13 и вернуться к этому шагу.)

- [ ] **Step 8: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/messenger/presentation test/features/messenger/pinned_banner_test.dart
git commit -m "feat(messenger): pinned banner in chat room"
```

---

### Task 13: Экран «Закреплённые»

**Files:**
- Create: `lib/features/messenger/presentation/screens/pinned_messages_screen.dart`

- [ ] **Step 1: Написать экран**

Создать `lib/features/messenger/presentation/screens/pinned_messages_screen.dart`:

```dart
import 'package:flutter/material.dart';

import '../../../../core/di/service_locator.dart';
import '../../../../core/theme/app_colors.dart';
import '../../../../l10n/app_localizations.dart';
import '../../domain/entities/message_entity.dart';
import '../../domain/repositories/i_messenger_repository.dart';

/// Список всех закреплённых сообщений беседы.
/// Возврат с `messageId` в Navigator.pop — чат прыгает к этому сообщению.
class PinnedMessagesScreen extends StatefulWidget {
  final String conversationId;
  final bool canUnpin;

  const PinnedMessagesScreen({
    super.key,
    required this.conversationId,
    required this.canUnpin,
  });

  @override
  State<PinnedMessagesScreen> createState() => _PinnedMessagesScreenState();
}

class _PinnedMessagesScreenState extends State<PinnedMessagesScreen> {
  List<MessageEntity> _pins = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final pins = await sl<IMessengerRepository>()
          .getPinnedMessages(widget.conversationId);
      if (mounted) setState(() { _pins = pins; _loading = false; });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _unpin(String messageId) async {
    await sl<IMessengerRepository>().unpinMessage(widget.conversationId, messageId);
    if (mounted) setState(() => _pins = _pins.where((m) => m.id != messageId).toList());
  }

  Future<void> _unpinAll() async {
    final l10n = AppLocalizations.of(context)!;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        content: Text(l10n.unpinAllConfirm),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(l10n.cancel)),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: Text(l10n.unpinAllAction)),
        ],
      ),
    );
    if (ok != true) return;
    await sl<IMessengerRepository>().unpinAll(widget.conversationId);
    if (mounted) setState(() => _pins = const []);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final colors = AppColors.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.pinnedMessagesTitle),
        actions: [
          if (widget.canUnpin && _pins.isNotEmpty)
            TextButton(onPressed: _unpinAll, child: Text(l10n.unpinAllAction)),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _pins.isEmpty
              ? Center(
                  child: Text(
                    l10n.noPinnedMessages,
                    style: TextStyle(color: colors.textSecondary),
                  ),
                )
              : ListView.separated(
                  itemCount: _pins.length,
                  separatorBuilder: (_, __) => Divider(height: 1, color: colors.divider),
                  itemBuilder: (_, i) {
                    final m = _pins[i];
                    return ListTile(
                      title: Text(
                        m.senderName ?? '',
                        style: TextStyle(color: colors.primary, fontSize: 13),
                      ),
                      subtitle: Text(
                        m.content.replaceAll('\n', ' ').trim(),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      trailing: widget.canUnpin
                          ? IconButton(
                              icon: const Icon(Icons.push_pin_outlined),
                              onPressed: () => _unpin(m.id),
                            )
                          : null,
                      onTap: () => Navigator.pop(context, m.id),
                    );
                  },
                ),
    );
  }
}
```

Если в `AppColors` нет `divider` — использовать `colors.textSecondary.withValues(alpha: 0.2)`. Ключ `l10n.cancel` в проекте уже есть; если имя другое — свериться с любым существующим `AlertDialog` в `lib/features/messenger`.

- [ ] **Step 2: Обработать возврат с экрана в чате**

В `chat_room_screen.dart`, в `onOpenList` (Task 12, Step 5) заменить `Navigator.of(context).push(...)` на вариант с обработкой результата:

```dart
                  onOpenList: () async {
                    final messageId = await Navigator.of(context).push<String>(
                      MaterialPageRoute(
                        builder: (_) => PinnedMessagesScreen(
                          conversationId: widget.conversationId,
                          canUnpin: _canPin(conv),
                        ),
                      ),
                    );
                    if (messageId == null || !mounted) return;
                    final msgs = _messengerBloc.state.messages[widget.conversationId] ?? [];
                    final idx = msgs.indexWhere((m) => m.id == messageId);
                    if (idx >= 0) {
                      setState(() {
                        _searchMatchChronIndices = [idx];
                        _searchCurrentMatchIdx = 0;
                      });
                      _scrollToChronIndex(idx);
                    }
                  },
```

- [ ] **Step 3: Анализатор**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib/features/messenger`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай.

- [ ] **Step 4: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/messenger/presentation/screens/pinned_messages_screen.dart lib/features/messenger/presentation/screens/chat_room_screen.dart
git commit -m "feat(messenger): pinned messages screen"
```

---

### Task 14: Пункт меню сообщения и рендер сервисной строки

**Files:**
- Modify: `lib/features/messenger/presentation/screens/chat_room_screen.dart`
- Modify: `lib/features/messenger/presentation/screens/conversations_screen.dart`

- [ ] **Step 1: Найти меню длинного тапа**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && grep -n "chatDelete\|chatEdit\|showModalBottomSheet" lib/features/messenger/presentation/screens/chat_room_screen.dart | head -20`
Expected: строки с пунктами контекстного меню сообщения (копировать / редактировать / удалить).

- [ ] **Step 2: Добавить пункт «Закрепить/Открепить»**

В найденное меню, рядом с пунктом удаления, добавить (подставив принятый в этом меню способ построения пункта — `ListTile` внутри bottom sheet):

```dart
              if (_canPin(_resolveConv(_messengerBloc.state.conversations)))
                ListTile(
                  leading: Icon(
                    msg.pinnedAt == null
                        ? Icons.push_pin_outlined
                        : Icons.push_pin_rounded,
                  ),
                  title: Text(
                    msg.pinnedAt == null ? l10n.pinAction : l10n.unpinAction,
                  ),
                  onTap: () {
                    Navigator.pop(context);
                    _messengerBloc.add(
                      msg.pinnedAt == null
                          ? PinMessage(widget.conversationId, msg.id)
                          : UnpinMessage(widget.conversationId, msg.id),
                    );
                    _pinsLoadedForCount = -1; // заставить плашку перечитать список
                  },
                ),
```

Имена локальных переменных (`msg`, `l10n`) взять те, что уже используются в этом меню.

- [ ] **Step 3: Отрисовать сервисное сообщение о закрепе**

В `chat_room_screen.dart` (~строка 3955), в `switch` по `action`, добавить рядом с `case 'member_added'`:

```dart
        case 'message_pinned': text = l10n.messagePinnedBy(actor); break;
```

В `conversations_screen.dart` (~строка 1565), в аналогичный `switch`:

```dart
        case 'message_pinned': return l10n.messagePinnedBy(actor);
```

- [ ] **Step 4: Анализатор и юнит-тесты**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib && flutter test`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай. и все тесты зелёные.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/messenger/presentation/screens
git commit -m "feat(messenger): pin action in message menu + service row"
```

---

### Task 15: Инструменты ассистента (правило Assistant-first)

**Files:**
- Modify: `lib/features/assistant/tools/assistant_tools_schema.dart`
- Modify: `lib/features/assistant/tools/assistant_tools_executor.dart`

- [ ] **Step 1: Добавить схемы инструментов**

В `lib/features/assistant/tools/assistant_tools_schema.dart`, рядом с описанием `send_message` (~строка 266), добавить три элемента в тот же список:

```dart
          {
            'type': 'function',
            'name': 'pin_message',
            'description': 'Pin a message in a conversation so it stays at the top for everyone.',
            'parameters': {
              'type': 'object',
              'properties': {
                'conversationId': {'type': 'string'},
                'messageId': {'type': 'string'},
              },
              'required': ['conversationId', 'messageId'],
            },
          },
          {
            'type': 'function',
            'name': 'unpin_message',
            'description': 'Unpin a previously pinned message in a conversation.',
            'parameters': {
              'type': 'object',
              'properties': {
                'conversationId': {'type': 'string'},
                'messageId': {'type': 'string'},
              },
              'required': ['conversationId', 'messageId'],
            },
          },
          {
            'type': 'function',
            'name': 'list_pinned',
            'description': 'List pinned messages of a conversation.',
            'parameters': {
              'type': 'object',
              'properties': {'conversationId': {'type': 'string'}},
              'required': ['conversationId'],
            },
          },
```

- [ ] **Step 2: Добавить исполнение**

В `lib/features/assistant/tools/assistant_tools_executor.dart`, рядом с веткой `} else if (name == 'send_message') {` (~строка 190), добавить:

```dart
      } else if (name == 'pin_message') {
        final convId = args['conversationId'] as String;
        final msgId = args['messageId'] as String;
        final res = await sl<IMessengerRepository>().pinMessage(convId, msgId);
        output = jsonEncode({'ok': true, 'pinnedCount': res['pinnedCount']});
      } else if (name == 'unpin_message') {
        final convId = args['conversationId'] as String;
        final msgId = args['messageId'] as String;
        final res = await sl<IMessengerRepository>().unpinMessage(convId, msgId);
        output = jsonEncode({'ok': true, 'pinnedCount': res['pinnedCount']});
      } else if (name == 'list_pinned') {
        final convId = args['conversationId'] as String;
        final pins = await sl<IMessengerRepository>().getPinnedMessages(convId);
        output = jsonEncode({
          'pinned': pins
              .map((m) => {'id': m.id, 'content': m.content, 'senderName': m.senderName})
              .toList(),
        });
```

Если `IMessengerRepository` в этом файле ещё не импортирован — добавить импорт по образцу импорта `MessengerRemoteDataSource`.

- [ ] **Step 3: Анализатор**

Run: `cd /Users/dmitry/Downloads/taler_id_mobile && flutter analyze lib/features/assistant`
Expected: **ни одного нового замечания, ссылающегося на твои файлы.** В репозитории ~341 замечание анализатора, существовавшее до этой работы (проверено на `dev` 2026-08-08) — «No issues found!» здесь недостижимо и требовать его нельзя. Сравнивай по именам своих файлов, а не по общему счётчику; чужой долг не трогай.

- [ ] **Step 4: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/assistant
git commit -m "feat(assistant): pin_message/unpin_message/list_pinned tools"
```

---

## Часть 4 — Выкатка

### Task 16: Мёрдж и деплой бэкенда на DEV

**Files:** —

- [ ] **Step 1: Влить ветку в `dev`**

```bash
cd /Users/dmitry/taler-id
git checkout dev && git pull --ff-only
git merge --no-ff feature/pinned-messages -m "feat(messenger): pinned messages"
git push origin dev
```

- [ ] **Step 2: Проверить статус миграций на DEV до деплоя**

Run: `ssh dvolkov@89.169.55.217 'cd ~/taler-id && npx prisma migrate status'`
Expected: список применённых миграций; новая `20260808000000_pinned_messages` числится как pending (`Following migration have not yet been applied`).

- [ ] **Step 3: Задеплоить с миграцией**

Run:
```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npx prisma migrate deploy && npx prisma generate && npm run build && pm2 restart taler-id-dev'
```
Expected: `All migrations have been successfully applied`, сборка ок, `pm2 restart` без ошибок.

- [ ] **Step 4: Убедиться, что бэкенд жив**

Run: `curl -s -o /dev/null -w "%{http_code}\n" https://staging.id.taler.tirol/health`
Expected: `200`

- [ ] **Step 5: Прогнать новый набор**

Run: `cd /Users/dmitry/Downloads/taler_id_tests && npm run test:pins`
Expected: `… passed, 0 failed`

- [ ] **Step 6: Прогнать обязательную батарею на DEV**

Run:
```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm test && npm run test:channels && npm run test:system-channel && npm run test:files && npm run test:sync
```
Expected: все наборы зелёные. Между наборами выдерживать паузу ~20с — на `/auth/login` в nginx стоит `limit_req`, иначе посыпятся 503, которые выглядят как регрессия.

---

### Task 17: Мобильный релиз

**Files:**
- Modify: `pubspec.yaml` (мобилка)
- Modify: `src/app-releases.ts` (бэкенд)
- Modify: `src/app.controller.ts` (бэкенд)

- [ ] **Step 1: Влить мобильную ветку в `dev` и поднять версию**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git checkout dev && git pull --ff-only
git merge --no-ff feature/pinned-messages -m "feat(messenger): pinned messages"
```

В `pubspec.yaml` поднять `version:` на следующий патч относительно текущего 1.1.24+225 → `1.1.25+226`, закоммитить и запушить `dev`.

- [ ] **Step 2: Прогнать тесты и интеграционный тест мобилки**

Run:
```bash
cd /Users/dmitry/Downloads/taler_id_mobile && flutter test
flutter emulators --launch Pixel_XL_API_33
# подождать ~15 секунд, затем:
flutter test integration_test/app_test.dart --flavor dev --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol -d emulator-5554
```
Expected: оба прогона зелёные.

- [ ] **Step 3: Добавить запись в `APP_RELEASES`**

В `/Users/dmitry/taler-id/src/app-releases.ts` первым элементом массива добавить:

```ts
  {
    version: '1.1.25',
    build: 226,
    date: '2026-08-08',
    flavor: 'both',
    notes_ru:
      'Закреплённые сообщения. В чатах, группах и каналах теперь можно закрепить сообщение — оно висит плашкой сверху. Несколько закреплённых переключаются тапом, есть отдельный экран со списком и «Открепить всё». Плашку можно скрыть у себя — она вернётся, когда закрепят что-то новое.',
    notes_en:
      'Pinned messages. Chats, groups and channels can now pin messages — they show as a bar at the top. Multiple pins cycle on tap, with a separate list screen and "Unpin all". You can hide the bar for yourself; it comes back when something new is pinned.',
  },
```

- [ ] **Step 4: Обновить `latest` в `app.controller.ts`**

В `src/app.controller.ts` заменить дефолты в `latest`:

```ts
      version: env.APP_LATEST_VERSION || '1.1.25',
      build: parseInt(env.APP_LATEST_BUILD || '226', 10),
```

⚠️ Этот шаг выполнять **только после того, как артефакты собраны и выложены** (Step 5) — иначе пользователям DEV/TEST прилетит баннер на несуществующий файл (обжигались 2026-07-30).

- [ ] **Step 5: Собрать и выложить артефакты**

Android DEV APK:
```bash
ssh dvolkov@138.124.61.221 'cd ~/taler_id_mobile && git fetch origin --quiet && git checkout dev && git reset --hard origin/dev && flutter build apk --flavor dev --release -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol && sudo cp build/app/outputs/flutter-apk/app-dev-release.apk /var/www/downloads/taler-id-dev.apk'
```

Остальные треки (TEST APK, PROD talerid APK, iOS×3, десктоп) — по пайплайну из CLAUDE.md, раздел «Desktop сборки — три трека» и «Мобильная сборка (Android) — build-дроплет». Каждую выкладку проверять `curl -sIL <url>` на 200 и свежий `Last-Modified`.

- [ ] **Step 6: Задеплоить бэкенд с новой версией на DEV и проверить**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
curl -s https://staging.id.taler.tirol/app/version | jq '{android:.android, first:.releases[0].version}'
```
Expected: `1.1.25` в обоих полях.

---

### Task 18: Деплой на TEST и PROD

**Files:** —

- [ ] **Step 1: Влить `dev` в `main` (бэкенд) и запушить**

```bash
cd /Users/dmitry/taler-id
git checkout main && git pull --ff-only
git merge --no-ff dev -m "release: pinned messages"
git push origin main
```

- [ ] **Step 2: Проверить миграции на TEST до деплоя**

Run: `ssh dvolkov@138.124.61.221 'cd ~/taler-id && npx prisma migrate status'`
Expected: `20260808000000_pinned_messages` в pending.

- [ ] **Step 3: Деплой TEST**

Run:
```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npx prisma migrate deploy && npx prisma generate && npm run build && pm2 restart taler-id'
curl -s -o /dev/null -w "%{http_code}\n" https://id.taler.tirol/health
```
Expected: миграция применена, `200`.

- [ ] **Step 4: Прогнать батарею на TEST**

Run:
```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:pins:prod && npm run test:prod && npm run test:channels:prod && npm run test:system-channel:prod
```
Expected: все зелёные (с паузами между наборами из-за rate-limit на `/auth/login`).

- [ ] **Step 5: Деплой PROD (DO), по одной ноде**

Run:
```bash
ssh dvolkov@77.73.131.137 "ssh do-app-1 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma migrate deploy && npx prisma generate && npm run build && sudo pm2 restart taler-id && sleep 5 && curl -s -o /dev/null -w \"health:%{http_code}\n\" http://localhost:3000/health'"
```
Expected: `health:200`. Полный `npm ci` обязателен — с `--omit=dev` сборка падает на `nest: not found`.

Дождаться `health:200`, затем повторить для `do-app-2` (миграция уже применена, `migrate deploy` отработает как no-op).

- [ ] **Step 6: Проверить PROD**

Run: `cd /Users/dmitry/Downloads/taler_id_tests && npm run test:talerid`
Expected: smoke зелёный.

---

### Task 19: Объявление на TEST и перенастройка баннера

**Files:** —

- [ ] **Step 1: Получить админский токен на TEST**

На TEST админский пользователь — `admin@taler.id` (проверено запросом к БД). Если пароль недоступен, временно выдать флаг своему аккаунту:

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && DB=$(grep -m1 ^DATABASE_URL .env | cut -d= -f2- | tr -d "\""); psql "$DB" -c "UPDATE \"User\" SET \"isAdmin\"=true WHERE email='"'"'integration_test@taler-test.com'"'"';"'
```

Затем залогиниться и забрать `accessToken`:

```bash
# ⚠️ Именно /admin/auth/login, а не /auth/login: AdminGuard требует в токене
# claim isAdmin, а обычный accessToken его не несёт. Возвращает {"token": ...},
# живёт 8 часов.
curl -s https://id.taler.tirol/admin/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' | jq -r .token
```

- [ ] **Step 2: Запостить объявление с закрепом**

```bash
TOKEN=<токен из шага 1>
curl -s https://id.taler.tirol/admin/system-channel/post \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "type": "news",
    "pin": true,
    "text_ru": "⚠️ Это тестовая версия Taler ID\n\nПриложение, которым вы пользуетесь, работает на тестовой среде (id.taler.tirol). Она нужна для проверки новых функций и может работать нестабильно.\n\nПожалуйста, перейдите на основную версию:\n• iOS (TestFlight): https://testflight.apple.com/join/UB3D5Dcd\n• Android (APK): https://talerid.io/download/talerid.apk\n\nПродакшн — отдельная среда: если аккаунт не найдётся, зарегистрируйтесь заново.",
    "text_en": "⚠️ This is the test version of Taler ID\n\nThe app you are using runs on the test environment (id.taler.tirol). It exists to try out new features and may be unstable.\n\nPlease switch to the production version:\n• iOS (TestFlight): https://testflight.apple.com/join/UB3D5Dcd\n• Android (APK): https://talerid.io/download/talerid.apk\n\nProduction is a separate environment: if your account is not found, please register again."
  }' | jq
```
Expected: `{ "messageId": "…", "pinned": true }`

- [ ] **Step 3: Снять временный флаг администратора**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && DB=$(grep -m1 ^DATABASE_URL .env | cut -d= -f2- | tr -d "\""); psql "$DB" -c "UPDATE \"User\" SET \"isAdmin\"=false WHERE email='"'"'integration_test@taler-test.com'"'"';"'
```

Шаг обязательный — тестовый аккаунт не должен остаться администратором.

- [ ] **Step 4: Проверить, что пин виден**

```bash
TOKEN=$(curl -s https://id.taler.tirol/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"integration_test_2@taler-test.com","password":"IntegrationTest123!"}' | jq -r .accessToken)
curl -s https://id.taler.tirol/messenger/conversations -H "Authorization: Bearer $TOKEN" \
  | jq '.[] | select(.isSystem == true) | {pinnedCount, topPinned: .topPinned.content[0:60]}'
```
Expected: `pinnedCount: 1`, в `topPinned` — начало объявления.

- [ ] **Step 5: Перенастроить update-баннер на TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && \
  printf "\nAPP_UPDATE_URL_ANDROID=https://talerid.io/download/talerid.apk\nAPP_UPDATE_URL_IOS=https://testflight.apple.com/join/UB3D5Dcd\nAPP_LATEST_VERSION=1.1.25\nAPP_LATEST_BUILD=226\n" >> .env && \
  pm2 restart taler-id --update-env'
```

Перед добавлением проверить, что этих ключей в `.env` ещё нет (`grep -n APP_UPDATE_URL ~/taler-id/.env`) — дубликаты в `.env` читаются непредсказуемо.

- [ ] **Step 6: Проверить баннер TEST**

Run: `curl -s https://id.taler.tirol/app/version | jq '{android:.android, updateUrl:.updateUrl}'`
Expected: `updateUrl.android` = `https://talerid.io/download/talerid.apk`, `updateUrl.ios` = TestFlight-ссылка.

- [ ] **Step 7: Починить iOS-ссылку на PROD**

На обеих DO app-нодах:

```bash
ssh dvolkov@77.73.131.137 "ssh do-app-1 'cd /opt/taler-id && grep -q APP_UPDATE_URL_IOS .env || echo \"APP_UPDATE_URL_IOS=https://testflight.apple.com/join/UB3D5Dcd\" >> .env && sudo pm2 restart taler-id --update-env'"
ssh dvolkov@77.73.131.137 "ssh do-app-2 'cd /opt/taler-id && grep -q APP_UPDATE_URL_IOS .env || echo \"APP_UPDATE_URL_IOS=https://testflight.apple.com/join/UB3D5Dcd\" >> .env && sudo pm2 restart taler-id --update-env'"
curl -s https://api.talerid.io/app/version | jq .updateUrl
```
Expected: `updateUrl.ios` = TestFlight `UB3D5Dcd` вместо aeza-листинга `id6741208498`.

- [ ] **Step 8: Обновить CLAUDE.md**

В `/Users/dmitry/talerid/CLAUDE.md`:
- в секцию обязательных тестов добавить пункт про `npm run test:pins` / `test:pins:prod`;
- в описание TEST отметить, что `/app/version` на TEST ведёт на PROD-артефакты, а не на TEST-сборки;
- в разделе про DO снять пометку «загрузка APNs-ключа / iOS updateUrl — известный пробел» в части `APP_UPDATE_URL_IOS`.

---

## Self-review плана

**Покрытие спеки:**

| Требование спеки | Задача |
|---|---|
| Поля `pinnedAt`/`pinnedById`, индекс, `pinsDismissedAt` | Task 1 |
| Права `_assertCanPin` по типам бесед | Task 2 |
| Идемпотентный повторный пин | Task 2 |
| `listPinned`, `unpinAll`, `dismissPins` | Task 3 |
| `pinnedCount`/`topPinned`/`pinsDismissedAt` в payload беседы | Task 4 |
| REST-эндпоинты + три socket-события | Task 5 |
| Сервисное сообщение + push через `deliverNewMessage` | Task 2 (ветка switch) + Task 5 (доставка) |
| Админский `pin: true` без сервисного сообщения, `pin`/`unpin` | Task 6 |
| e2e `test:pins` | Task 7 |
| Модели мобилки | Task 8 |
| Datasource/repository | Task 9 |
| BLoC | Task 10 |
| i18n ru/en | Task 11 |
| Плашка + прыжок к сообщению + dismiss | Task 12 |
| Экран «Закреплённые» + «Открепить всё» | Task 13 |
| Пункт меню + рендер сервисной строки | Task 14 |
| Инструменты ассистента | Task 15 |
| Выкатка DEV → TEST → PROD с миграциями | Tasks 16, 18 |
| Мобильный релиз, `APP_RELEASES`, порядок «сначала артефакты» | Task 17 |
| Объявление на TEST + баннер + починка PROD-iOS | Task 19 |

Пробелов нет.

**Согласованность имён:** `pinMessage` / `unpinMessage` / `listPinned` / `unpinAll` / `dismissPins` / `_assertCanPin` / `_pinnedCount` — одинаковы в сервисе, контроллере, тестах и мобильном репозитории. Socket-события `message_pinned` / `message_unpinned` / `pins_cleared` — одинаковы в контроллере, datasource и блоке. Поля payload `pinnedCount` / `topPinned` / `pinsDismissedAt` — одинаковы в бэкенде, e2e и сущностях мобилки.

**Известные места, где исполнителю нужно свериться с кодом** (в шагах помечены явно, это не заглушки): точные имена полей `AppColors`, форма `_http.delete` в datasource, имя приватного поля datasource в `messenger_repository_impl.dart`, форма построения пунктов контекстного меню сообщения.
