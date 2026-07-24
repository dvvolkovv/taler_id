# System News Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Официальный канал «Taler ID — Новости» (`Conversation.isSystem`) с принудительной подпиской всех юзеров, автопостом release notes из `APP_RELEASES` и critical-постами, чей push пробивает mute.

**Architecture:** Новый модуль `src/system-channel/` с идемпотентным seed'ом на `onApplicationBootstrap` (системный юзер + канал + backfill подписок + автопост релиза). Точечные правки: запрет отписки (`messenger.service`), critical-bypass mute (`messenger.gateway.fanOutToParticipants`), подписка при регистрации (`auth.service`), admin-эндпоинт ручных постов. `APP_RELEASES` извлекается из `app.controller.ts` в отдельный экспортируемый файл.

**Tech Stack:** NestJS, Prisma (PostgreSQL JSON-фильтры по `Message.metadata`), существующий канальный стек (`CHANNEL` conversations, `deliverNewMessage`).

**Spec:** `docs/superpowers/specs/2026-07-24-system-news-channel-design.md`
**Репо:** бэкенд `~/Downloads/taler_id` (все задачи кроме e2e); e2e — `~/Downloads/taler_id_tests`.

---

## File Structure

```
src/app-releases.ts                        # ИЗВЛЕЧЁННЫЙ export const APP_RELEASES + type AppRelease
src/system-channel/
├── system-channel.module.ts               # imports Prisma + Messenger (forwardRef при цикле)
├── system-channel.service.ts              # seed, backfill, subscribeUser, autopost, postNews
└── system-channel.service.spec.ts
```

Изменяемые: `prisma/schema.prisma` (Conversation.isSystem), `src/app.controller.ts` (импорт APP_RELEASES), `src/messenger/messenger.service.ts` (запрет отписки), `src/messenger/messenger.gateway.ts` (critical bypass), `src/auth/auth.service.ts` + `auth.module.ts` (подписка при регистрации), `src/admin/admin.controller.ts` + `admin.module.ts` (ручной пост), `src/app.module.ts`.

Константы (в `system-channel.service.ts`): `SYSTEM_USER_EMAIL = 'system@talerid.io'`, `SYSTEM_USERNAME = 'talerid'`, `SYSTEM_CHANNEL_NAME = 'Taler ID — Новости'`.

---

### Task 1: Prisma — `Conversation.isSystem`

**Files:**
- Modify: `prisma/schema.prisma` (model Conversation)

- [ ] **Step 1:** В `model Conversation` добавить поле (рядом с другими Boolean-полями модели):

```prisma
  isSystem Boolean @default(false)
```

- [ ] **Step 2:** `npx prisma migrate dev --name conversation_is_system`. Если локальная shadow-DB падает с P3006 (известная проблема, миграция `20260306_add_meeting_summary`) — создать каталог миграции вручную по образцу `prisma/migrations/20260724062858_mcp_oauth_client_flags/` с SQL:

```sql
-- AlterTable
ALTER TABLE "Conversation" ADD COLUMN     "isSystem" BOOLEAN NOT NULL DEFAULT false;
```

Затем `npx prisma generate` + `npx prisma validate` — оба зелёные.

- [ ] **Step 3: Commit**

```bash
git add prisma/schema.prisma prisma/migrations/
git commit -m "feat(system-channel): Conversation.isSystem flag"
```

---

### Task 2: Извлечь APP_RELEASES в `src/app-releases.ts`

**Files:**
- Create: `src/app-releases.ts`
- Modify: `src/app.controller.ts` (убрать локальный const, импортировать)

`APP_RELEASES` сейчас — неэкспортируемый `const` в `src/app.controller.ts:106`. SystemChannelService должен его читать; импорт из контроллера создал бы кривую зависимость — извлекаем в отдельный файл.

- [ ] **Step 1:** Создать `src/app-releases.ts`:

```typescript
export interface AppRelease {
  version: string;
  build: number;
  date: string;
  flavor: string;
  notes_ru: string;
  notes_en: string;
}

export const APP_RELEASES: AppRelease[] = [
  // <ПЕРЕНЕСТИ сюда БЕЗ ИЗМЕНЕНИЙ весь массив из src/app.controller.ts:106-...>
];
```

Перенос — copy-paste всего массива, содержимое не менять.

- [ ] **Step 2:** В `src/app.controller.ts`: удалить локальный `const APP_RELEASES = [...]`, добавить `import { APP_RELEASES } from './app-releases';`. Проверить, что больше никто не объявляет/не использует локально (grep по файлу).

- [ ] **Step 3:** `npm run build` — чисто; `npx jest src/app.controller.spec.ts --silent` — существующие тесты `/app/version` зелёные.

- [ ] **Step 4: Commit**

```bash
git add src/app-releases.ts src/app.controller.ts
git commit -m "refactor(system-channel): extract APP_RELEASES to importable module"
```

---

### Task 3: SystemChannelService — seed (юзер, канал, backfill)

**Files:**
- Create: `src/system-channel/system-channel.service.ts`
- Create: `src/system-channel/system-channel.module.ts`
- Test: `src/system-channel/system-channel.service.spec.ts`

ВАЖНО, проверить перед кодингом: (а) точное имя enum роли участника в `prisma/schema.prisma` (grep `OWNER` — вероятно `ParticipantRole` со значениями OWNER/ADMIN/SUBSCRIBER; использовать реальные); (б) обязательные поля `User` при create (email, passwordHash, username, profile) — см. `auth.service.ts:66-77`; (в) поля `Conversation` для CHANNEL — см. `messenger.service.ts:1288-1300` (`createChannel`).

- [ ] **Step 1: Падающий тест** `src/system-channel/system-channel.service.spec.ts`:

```typescript
import { SystemChannelService } from './system-channel.service';

function makePrisma() {
  return {
    user: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'sys-user' }),
      findMany: jest.fn().mockResolvedValue([{ id: 'u1' }, { id: 'u2' }]),
    },
    conversation: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'sys-chan' }),
    },
    conversationParticipant: {
      createMany: jest.fn().mockResolvedValue({ count: 2 }),
    },
    message: { findFirst: jest.fn().mockResolvedValue({ id: 'm', metadata: { version: '9.9.9' } }) },
  } as any;
}

describe('SystemChannelService seed', () => {
  it('creates system user and channel when missing, backfills subscriptions', async () => {
    const prisma = makePrisma();
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, { getMessageById: jest.fn() } as any);
    await svc.ensureSeeded();
    expect(prisma.user.create).toHaveBeenCalled();
    expect(prisma.conversation.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ isSystem: true, type: 'CHANNEL' }) }),
    );
    expect(prisma.conversationParticipant.createMany).toHaveBeenCalledWith(
      expect.objectContaining({ skipDuplicates: true }),
    );
  });

  it('is idempotent: existing user/channel are not recreated', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, { getMessageById: jest.fn() } as any);
    await svc.ensureSeeded();
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.conversation.create).not.toHaveBeenCalled();
    // backfill выполняется всегда (idempotent skipDuplicates)
    expect(prisma.conversationParticipant.createMany).toHaveBeenCalled();
  });
});
```

(Конструкторные зависимости: prisma, gateway, messengerService — точный набор смотри в Step 3; тест подгони под финальную сигнатуру.)

- [ ] **Step 2:** `npx jest src/system-channel --silent` → FAIL (модуль отсутствует).

- [ ] **Step 3: Реализация** `system-channel.service.ts` (каркас; поля User/Conversation подогнать под реальные):

```typescript
import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { MessengerService } from '../messenger/messenger.service';
import { APP_RELEASES } from '../app-releases';

export const SYSTEM_USER_EMAIL = 'system@talerid.io';
export const SYSTEM_USERNAME = 'talerid';
export const SYSTEM_CHANNEL_NAME = 'Taler ID — Новости';

@Injectable()
export class SystemChannelService implements OnApplicationBootstrap {
  private readonly logger = new Logger(SystemChannelService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly gateway: MessengerGateway,
    private readonly messenger: MessengerService,
  ) {}

  async onApplicationBootstrap() {
    try {
      await this.ensureSeeded();
      await this.autopostLatestRelease(); // Task 5
    } catch (e) {
      // seed не должен ронять приложение
      this.logger.error(`System channel seed failed: ${(e as Error).message}`);
    }
  }

  async ensureSeeded(): Promise<{ userId: string; channelId: string }> {
    // 1) системный юзер
    let sysUser = await this.prisma.user.findUnique({ where: { email: SYSTEM_USER_EMAIL } });
    if (!sysUser) {
      sysUser = await this.prisma.user.create({
        data: {
          email: SYSTEM_USER_EMAIL,
          username: SYSTEM_USERNAME,
          // случайный hex вместо bcrypt-хеша — bcrypt.compare с ним всегда false,
          // логин под системным юзером невозможен
          passwordHash: crypto.randomBytes(32).toString('hex'),
          profile: { create: { firstName: 'Taler ID', lastName: '' } },
          kycRecord: { create: {} },
        },
      });
    }
    // 2) канал
    let channel = await this.prisma.conversation.findFirst({ where: { isSystem: true } });
    if (!channel) {
      channel = await this.prisma.conversation.create({
        data: {
          type: 'CHANNEL',
          isSystem: true,
          name: SYSTEM_CHANNEL_NAME, // подогнать поле под createChannel (name/description/...)
          participants: { create: { userId: sysUser.id, role: 'OWNER' } },
        },
      });
    }
    // 3) backfill подписок — батчами, idempotent
    const BATCH = 500;
    let cursor: string | undefined;
    for (;;) {
      const users = await this.prisma.user.findMany({
        take: BATCH,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: { id: 'asc' },
        select: { id: true },
      });
      if (users.length === 0) break;
      await this.prisma.conversationParticipant.createMany({
        data: users.map((u) => ({ conversationId: channel!.id, userId: u.id, role: 'SUBSCRIBER' })),
        skipDuplicates: true,
      });
      cursor = users[users.length - 1].id;
      if (users.length < BATCH) break;
    }
    return { userId: sysUser.id, channelId: channel.id };
  }
}
```

⚠️ `conversationParticipant.createMany` + `skipDuplicates` требует unique-констрейнта `(conversationId, userId)` — проверить в schema.prisma (`@@unique`/`@@id` на ConversationParticipant); если его нет — использовать цикл upsert'ов и отразить в тесте.

`system-channel.module.ts`:

```typescript
import { Module, forwardRef } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { MessengerModule } from '../messenger/messenger.module';
import { SystemChannelService } from './system-channel.service';

@Module({
  imports: [PrismaModule, forwardRef(() => MessengerModule)],
  providers: [SystemChannelService],
  exports: [SystemChannelService],
})
export class SystemChannelModule {}
```

(forwardRef — превентивно; если цикла нет, можно обычный import. Проверить, что PrismaModule существует и экспортирует PrismaService — grep `src/prisma/`.)

- [ ] **Step 4:** `npx jest src/system-channel --silent` → PASS; `npm run build` чисто.

- [ ] **Step 5: Commit**

```bash
git add src/system-channel/
git commit -m "feat(system-channel): seed service — system user, channel, subscription backfill"
```

---

### Task 4: Запрет отписки + подписка при регистрации

**Files:**
- Modify: `src/messenger/messenger.service.ts` (`unsubscribeFromChannel`, строка ~1322)
- Modify: `src/auth/auth.service.ts` (`register`, после `prisma.user.create` ~строка 66) + `src/auth/auth.module.ts`
- Test: расширить `src/system-channel/system-channel.service.spec.ts` + новый блок в messenger-тестах

- [ ] **Step 1: Тест запрета отписки** — добавить в существующий подходящий spec messenger-сервиса (или создать `src/messenger/messenger.service.system.spec.ts` по паттерну `messenger.service.contacts.spec.ts` — `Object.create(MessengerService.prototype)` + подмена `(service as any).prisma`):

```typescript
import { ForbiddenException } from '@nestjs/common';
import { MessengerService } from './messenger.service';

describe('unsubscribeFromChannel — system channel', () => {
  it('refuses to unsubscribe from isSystem channel', async () => {
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = {
      conversation: {
        findUnique: jest.fn().mockResolvedValue({ id: 'c1', type: 'CHANNEL', isSystem: true }),
      },
    };
    await expect(service.unsubscribeFromChannel('c1', 'u1')).rejects.toThrow(ForbiddenException);
  });
});
```

(Прочитать реальное начало `unsubscribeFromChannel` — как он грузит conversation — и подстроить мок под фактический prisma-вызов.)

- [ ] **Step 2:** FAIL → **реализация**: в начале `unsubscribeFromChannel`, после загрузки conversation (или добавив загрузку `isSystem` в существующий select):

```typescript
    if ((conv as any).isSystem) {
      throw new ForbiddenException('Нельзя отписаться от системного канала');
    }
```

- [ ] **Step 3: Подписка при регистрации.** В `SystemChannelService` добавить метод:

```typescript
  async subscribeUser(userId: string): Promise<void> {
    const channels = await this.prisma.conversation.findMany({
      where: { isSystem: true },
      select: { id: true },
    });
    if (channels.length === 0) return;
    await this.prisma.conversationParticipant.createMany({
      data: channels.map((c) => ({ conversationId: c.id, userId, role: 'SUBSCRIBER' })),
      skipDuplicates: true,
    });
  }
```

Тест (в system-channel spec): `subscribeUser` вызывает createMany с ролью SUBSCRIBER; при отсутствии системных каналов — не вызывает createMany.

В `auth.service.ts` `register`: после `prisma.user.create` добавить

```typescript
    // системный канал: подписка нового юзера (не роняем регистрацию при сбое)
    try {
      await this.systemChannel.subscribeUser(user.id);
    } catch (e) {
      this.logger?.warn?.(`system-channel subscribe failed for ${user.id}: ${(e as Error).message}`);
    }
```

Инжект: конструктор AuthService += `private readonly systemChannel: SystemChannelService`; `AuthModule` imports += `SystemChannelModule`. ⚠️ Проверить цикл: если `MessengerModule` (импортируемый SystemChannelModule) прямо или транзитивно импортирует `AuthModule` — обернуть в `forwardRef(() => SystemChannelModule)` в auth.module и/или наоборот; если цикл неразрешим красиво — вынести `subscribeUser` в отдельный лёгкий `SystemChannelSubscriptionService` в том же каталоге, зависящий ТОЛЬКО от PrismaModule, и инжектить его (отразить в отчёте).

- [ ] **Step 4:** Все тесты: `npx jest src/system-channel src/messenger src/auth --silent` (auth-suite падает pre-existing — сравнить с baseline, новых падений нет); `npm run build` чисто.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/messenger.service.ts src/messenger/messenger.service.system.spec.ts src/system-channel/ src/auth/
git commit -m "feat(system-channel): forced subscription — register hook + unsubscribe ban"
```

---

### Task 5: Автопост релизов + critical сквозь mute

**Files:**
- Modify: `src/system-channel/system-channel.service.ts` (+ spec)
- Modify: `src/messenger/messenger.gateway.ts` (`fanOutToParticipants`, mute-проверка ~строка 477) + `src/messenger/messenger.gateway.deliver.spec.ts`

- [ ] **Step 1: Тест автопоста** (system-channel spec):

```typescript
describe('autopostLatestRelease', () => {
  it('posts when APP_RELEASES[0].version is newer than last release post', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    prisma.message.findFirst.mockResolvedValue(null); // release-постов ещё нет
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm1', content: 'x' }),
    };
    const gateway = { deliverNewMessage: jest.fn() };
    const svc = new SystemChannelService(prisma, gateway as any, messenger as any);
    await svc.autopostLatestRelease();
    expect(messenger.createMessage).toHaveBeenCalledWith(
      'sys-chan', 'sys-user', expect.stringContaining('Taler ID'),
      undefined, undefined, undefined,
      expect.objectContaining({ newsType: 'release' }),
    );
    expect(gateway.deliverNewMessage).toHaveBeenCalled();
  });

  it('skips when latest release already posted', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    const { APP_RELEASES } = require('../app-releases');
    prisma.message.findFirst.mockResolvedValue({ metadata: { version: APP_RELEASES[0].version } });
    const messenger = { createMessage: jest.fn(), getMessageById: jest.fn() };
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, messenger as any);
    await svc.autopostLatestRelease();
    expect(messenger.createMessage).not.toHaveBeenCalled();
  });
});
```

(`createMessage` позиционные аргументы — сверить с реальной сигнатурой `messenger.service.ts:727`: `(conversationId, senderId, content, fileData?, topicId?, isSystem?, metadata?, ...)` — metadata седьмым; подогнать expect.)

- [ ] **Step 2:** FAIL → **реализация** в SystemChannelService:

```typescript
  async autopostLatestRelease(): Promise<void> {
    const latest = APP_RELEASES[0];
    if (!latest) return;
    const channel = await this.prisma.conversation.findFirst({ where: { isSystem: true } });
    const sysUser = await this.prisma.user.findUnique({ where: { email: SYSTEM_USER_EMAIL } });
    if (!channel || !sysUser) return;
    const lastPost = await this.prisma.message.findFirst({
      where: {
        conversationId: channel.id,
        metadata: { path: ['newsType'], equals: 'release' },
      },
      orderBy: { createdAt: 'desc' },
    });
    if ((lastPost?.metadata as any)?.version === latest.version) return;
    const content =
      `🚀 Taler ID ${latest.version}\n\n${latest.notes_ru}\n\n— EN —\n\n${latest.notes_en}`;
    await this.post(channel.id, sysUser.id, content, { newsType: 'release', version: latest.version });
    this.logger.log(`Release ${latest.version} posted to system channel`);
  }

  /** общий постинг: createMessage + доставка (broadcast + FCM всем подписчикам) */
  private async post(
    channelId: string,
    senderId: string,
    content: string,
    metadata: Record<string, any>,
  ): Promise<{ messageId: string }> {
    const msg = await this.messenger.createMessage(
      channelId, senderId, content,
      undefined, undefined, undefined, metadata,
    );
    const full = await this.messenger.getMessageById(msg.id);
    if (full) {
      await this.gateway.deliverNewMessage(
        { ...full, senderName: 'Taler ID', reactions: [] },
        senderId, channelId, { senderName: 'Taler ID' },
      );
    }
    return { messageId: msg.id };
  }
```

(Форму opts `deliverNewMessage` сверить с реальной сигнатурой в gateway — `{ silent?, senderName? }`.)

- [ ] **Step 3: Тест critical-bypass** — в `src/messenger/messenger.gateway.deliver.spec.ts` (паттерн уже есть):

```typescript
  it('critical news push bypasses mute', async () => {
    // участник замьючен, но enrichedMsg.metadata.newsType === 'critical'
    service.isParticipantMuted.mockResolvedValue(true);
    service.getFcmTokens.mockResolvedValue(['tok1']);
    await gateway.fanOutToParticipants(
      { id: 'm1', content: 'Обновитесь!', metadata: { newsType: 'critical' } },
      'sys-user', 'sys-chan', { senderName: 'Taler ID' },
    );
    expect(fcmService.sendNewMessage).toHaveBeenCalled();
  });

  it('non-critical news still respects mute', async () => {
    service.isParticipantMuted.mockResolvedValue(true);
    await gateway.fanOutToParticipants(
      { id: 'm2', content: 'Новость', metadata: { newsType: 'news' } },
      'sys-user', 'sys-chan', { senderName: 'Taler ID' },
    );
    expect(fcmService.sendNewMessage).not.toHaveBeenCalled();
  });
```

(Скопировать setup моков из существующих тестов файла; имена моков подогнать.)

- [ ] **Step 4:** FAIL → **реализация** в `fanOutToParticipants` (мьют-ветка, ~строка 477):

```typescript
        const isCriticalNews = enrichedMsg?.metadata?.newsType === 'critical';
        const muted = isCriticalNews
          ? false // critical-новости системного канала пробивают mute
          : await this.service.isParticipantMuted(conversationId, p.userId);
```

- [ ] **Step 5:** `npx jest src/system-channel src/messenger --silent` зелёные; `npm run build`.

- [ ] **Step 6: Commit**

```bash
git add src/system-channel/ src/messenger/messenger.gateway.ts src/messenger/messenger.gateway.deliver.spec.ts
git commit -m "feat(system-channel): release autopost + critical push bypasses mute"
```

---

### Task 6: Admin-эндпоинт ручных постов

**Files:**
- Modify: `src/system-channel/system-channel.service.ts` (+ spec)
- Modify: `src/admin/admin.controller.ts`, `src/admin/admin.module.ts`

- [ ] **Step 1: Тест `postNews`** (system-channel spec): постит с metadata `{newsType:'news'}`; для critical — `{newsType:'critical', minVersion}`; RU+EN формат когда text_en передан; бросает NotFoundException если системного канала нет.

```typescript
describe('postNews', () => {
  it('posts manual news with metadata', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm1' }),
    };
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, messenger as any);
    await svc.postNews({ type: 'critical', text_ru: 'Обновитесь до 1.2.0', minVersion: '1.2.0' });
    expect(messenger.createMessage).toHaveBeenCalledWith(
      'sys-chan', 'sys-user', expect.stringContaining('Обновитесь'),
      undefined, undefined, undefined,
      expect.objectContaining({ newsType: 'critical', minVersion: '1.2.0' }),
    );
  });
});
```

- [ ] **Step 2:** FAIL → **реализация**:

```typescript
  async postNews(dto: {
    type: 'news' | 'critical';
    text_ru: string;
    text_en?: string;
    minVersion?: string;
  }): Promise<{ messageId: string }> {
    const channel = await this.prisma.conversation.findFirst({ where: { isSystem: true } });
    const sysUser = await this.prisma.user.findUnique({ where: { email: SYSTEM_USER_EMAIL } });
    if (!channel || !sysUser) throw new NotFoundException('System channel is not seeded');
    const content = dto.text_en
      ? `${dto.text_ru}\n\n— EN —\n\n${dto.text_en}`
      : dto.text_ru;
    return this.post(channel.id, sysUser.id, content, {
      newsType: dto.type,
      ...(dto.minVersion ? { minVersion: dto.minVersion } : {}),
    });
  }
```

- [ ] **Step 3: Эндпоинт.** Прочитать `src/admin/admin.controller.ts` (стиль, guard) и добавить:

```typescript
  @Post('system-channel/post')
  @UseGuards(AdminGuard)
  async postSystemNews(
    @Body() body: { type: 'news' | 'critical'; text_ru: string; text_en?: string; minVersion?: string },
  ) {
    if (!body?.text_ru || !['news', 'critical'].includes(body?.type)) {
      throw new BadRequestException('type (news|critical) and text_ru are required');
    }
    return this.systemChannel.postNews(body);
  }
```

`AdminModule` imports += `SystemChannelModule`; конструктор контроллера += `private readonly systemChannel: SystemChannelService`. (Если у admin-роутов префикс/иная структура — mirror существующих роутов.)

- [ ] **Step 4:** `npx jest src/system-channel src/admin --silent` зелёные (admin — если есть suite); `npm run build`.

- [ ] **Step 5: Commit**

```bash
git add src/system-channel/ src/admin/
git commit -m "feat(system-channel): admin endpoint for manual news/critical posts"
```

---

### Task 7: Wiring + полный прогон

**Files:**
- Modify: `src/app.module.ts`

- [ ] **Step 1:** `SystemChannelModule` в imports `AppModule`.

- [ ] **Step 2:** ⚠️ Урок MCP-фичи (boot-crash 2026-07-24): юнит-тесты НЕ ловят DI-проблемы. Проверить руками: все конструкторные типы в новых/изменённых сервисах — конкретные классы (НЕ `Pick<>`/интерфейсы); все инжектируемые провайдеры экспортируются своими модулями; циклы обёрнуты forwardRef.

- [ ] **Step 3:** `npm run build` чисто; `npx jest --silent` — итог сравнить с baseline (pre-existing падения: profile, tenant, auth, billing/metering — 121 тест; новых нет).

- [ ] **Step 4: Commit**

```bash
git add src/app.module.ts
git commit -m "feat(system-channel): wire SystemChannelModule into app"
```

---

### Task 8: E2E `test:system-channel` (репо taler_id_tests)

**Files (репо `~/Downloads/taler_id_tests`):**
- Create: `system_channel_test.ts`
- Modify: `package.json`

- [ ] **Step 1:** Изучить `channels_test.ts` (логин-хелпер, counters, стиль) и `mcp_test.ts` (свежий пример). Написать `system_channel_test.ts`:

1. Логин `integration_test` + `integration_test_2`.
2. `GET /messenger/conversations` обоих → найти канал с `name` = «Taler ID — Новости» (или `isSystem: true`, если поле отдаётся в `_formatConversation` — проверить бэкенд; если не отдаётся, матчить по имени) → у ОБОИХ канал в списке.
3. `GET /messenger/conversations/<id>/messages` → есть сообщение с `metadata.newsType === 'release'` и `metadata.version` === `version` из `GET /app/version` (`ios.version` prod-flavor).
4. Отписка: `DELETE`/`POST` unsubscribe-роут канала (посмотреть точный метод в `messenger.controller.ts:1144` — `unsubscribe`) → HTTP 403.
5. Mute: существующий mute-роут → 200 (и unmute обратно).
6. (cleanup не нужен — ничего не создавали.)

- [ ] **Step 2:** package.json:

```json
"test:system-channel": "BASE_URL=https://staging.id.taler.tirol npx ts-node system_channel_test.ts",
"test:system-channel:prod": "BASE_URL=https://id.taler.tirol npx ts-node system_channel_test.ts"
```

- [ ] **Step 3:** Компиляционный smoke: `npx tsc --noEmit system_channel_test.ts --esModuleInterop --target es2022 --module commonjs --moduleResolution node --lib es2022 --strict` → чисто. (Живой прогон — после деплоя DEV, Task 9.)

- [ ] **Step 4: Commit** (только свои 2 файла):

```bash
git add system_channel_test.ts package.json
git commit -m "test: system news channel e2e (forced subscription, release autopost, unsubscribe ban)"
```

---

### Task 9: Деплой DEV + живая верификация + CLAUDE.md

- [ ] **Step 1:** Бэкенд: `npm run build && npx jest --silent` локально — baseline не ухудшен → `git push origin dev`.

- [ ] **Step 2:** Деплой DEV:

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm ci && npx prisma migrate deploy && npm run build && pm2 restart taler-id-dev && sleep 8 && curl -s -o /dev/null -w "health:%{http_code}\n" http://localhost:3000/health'
```

Ожидаемо `health:200`. В логах (`pm2 logs taler-id-dev --lines 50 --nostream`) — строки seed'а: канал создан / релиз запощен, без ошибок SystemChannelService.

- [ ] **Step 3:** `cd ~/Downloads/taler_id_tests && npm run test:system-channel` → все проверки зелёные (итерировать при падениях). Затем регрессия каналов: `npm run test:channels` → 23/23.

- [ ] **Step 4:** CLAUDE.md (`/Users/dmitry/talerid/CLAUDE.md`): добавить тест №14 после теста 13 (MCP):

```markdown
### 14. Тест системного канала новостей (DEV)
E2E: канал «Taler ID — Новости» есть у обоих тест-юзеров → release-пост совпадает с /app/version → отписка запрещена (403) → mute работает.
```bash
cd ~/Downloads/taler_id_tests && npm run test:system-channel
```
```

И добавить `npm run test:system-channel:prod` в строку «После деплоя на TEST».

- [ ] **Step 5:** Отчёт пользователю. Деплой TEST/PROD — только по явной команде.

---

## Self-Review Notes

- **Spec coverage:** isSystem-миграция (T1), APP_RELEASES экспорт (T2), seed юзер/канал/backfill (T3), подписка при регистрации + запрет отписки (T4), автопост + critical-bypass (T5), admin ручные посты (T6), wiring + DI-проверка (T7), e2e (T8), деплой DEV + CLAUDE.md (T9). Фаза 2 спека (minSupportedVersion, локализация, бейдж) — вне плана, соответствует спеку.
- **Точки подгонки** (⚠️ в задачах): enum роли участника, обязательные поля User/Conversation при create, unique-констрейнт ConversationParticipant, позиционные аргументы `createMessage`, точная форма mute-ветки fan-out, отдаётся ли `isSystem` в `_formatConversation` (для e2e-матчинга; если нет — матчить по имени канала).
- **Type consistency:** `SystemChannelService(prisma, gateway, messenger)` — единый порядок конструктора в T3/T5/T6 тестах; `post(channelId, senderId, content, metadata)` private-хелпер используется автопостом (T5) и postNews (T6); `subscribeUser(userId)` (T4) вызывается из auth.
