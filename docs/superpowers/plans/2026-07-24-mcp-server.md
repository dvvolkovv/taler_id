# TalerID MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Единый MCP endpoint `POST /mcp` (Streamable HTTP, stateless) с tools для календаря, заметок и сообщений, авторизуемый access-токенами существующего OIDC-провайдера; DCR для личных AI-ассистентов + ручной verified-partner для B2B.

**Architecture:** Новый NestJS-модуль `src/mcp/` внутри существующего бэкенда. Tools вызывают существующие сервисы (CalendarService, NotesService, MessengerService) in-process. Auth: Bearer access-token → `provider.AccessToken.find()` → userId+scopes; tools фильтруются по scopes при сборке server-инстанса per-request (stateless — работает на 2 DO-нодах за LB). DCR включается в `oidc-provider` конфигом за env-флагом; динамические клиенты хранятся в `OAuthClient` (новые поля).

**Tech Stack:** NestJS, `@modelcontextprotocol/sdk` (Streamable HTTP transport), `zod`, `oidc-provider@9`, Prisma, Redis.

**Spec:** `docs/superpowers/specs/2026-07-24-mcp-server-design.md`

**Репо:** задачи 1–11 — бэкенд `taler_id` (локально `~/Downloads/taler_id`, ветка `dev`); задача 12 — `~/Downloads/taler_id_tests`; задача 13 — CLAUDE.md в `~/talerid`.

---

## File Structure

```
src/mcp/
├── mcp.module.ts                  # DI-wiring, imports Calendar/Notes/Messenger/Oidc modules
├── mcp.controller.ts              # POST/GET/DELETE /mcp + /.well-known/oauth-protected-resource
├── mcp-auth.guard.ts              # Bearer → OIDC AccessToken → req.mcpAuth {userId, scopes, clientId}
├── mcp-server.factory.ts          # buildServer(userId, scopes) → McpServer со scope-фильтрованными tools
└── tools/
    ├── calendar.tools.ts          # 5 tools → CalendarService
    ├── notes.tools.ts             # 4 tools → NotesService
    └── messenger.tools.ts         # 5 tools → MessengerService (+gateway broadcast для send)
```

Изменяемые существующие файлы:
- `prisma/schema.prisma` — поля OAuthClient
- `src/oidc/adapters/prisma-client-adapter.ts` — DCR upsert/destroy/find
- `src/oidc/oidc-provider.factory.ts` — mcp-scopes, `features.registration`, `clientAuthMethods`
- `src/main.ts` — rate-limit на `/oauth/reg`
- `src/messenger/messenger.service.ts` — новый метод `listContacts`
- `src/app.module.ts` — подключение McpModule

---

### Task 1: Prisma-миграция — поля DCR/partner в OAuthClient

**Files:**
- Modify: `prisma/schema.prisma` (model OAuthClient, строки ~158-173)

- [ ] **Step 1: Добавить поля в модель**

В `model OAuthClient` после `logoUri String?` добавить:

```prisma
  verifiedPartner Boolean  @default(false)
  isDynamic       Boolean  @default(false)
  dcrMetadata     Json?
```

- [ ] **Step 2: Создать миграцию**

Run: `cd ~/Downloads/taler_id && npx prisma migrate dev --name mcp_oauth_client_flags`
Expected: миграция создана, `npx prisma generate` прошёл.

- [ ] **Step 3: Commit**

```bash
git add prisma/schema.prisma prisma/migrations/
git commit -m "feat(mcp): add verifiedPartner/isDynamic/dcrMetadata to OAuthClient"
```

---

### Task 2: PrismaClientAdapter — поддержка DCR-клиентов

**Files:**
- Modify: `src/oidc/adapters/prisma-client-adapter.ts`
- Test: `src/oidc/adapters/prisma-client-adapter.spec.ts` (создать)

- [ ] **Step 1: Прочитать текущий `find()`** (строки 9-56) — понять существующий маппинг статических клиентов DB→metadata. Его НЕ менять.

- [ ] **Step 2: Написать падающий тест**

```typescript
import { PrismaClientAdapter } from './prisma-client-adapter';

describe('PrismaClientAdapter DCR', () => {
  const prisma: any = {
    oAuthClient: {
      findUnique: jest.fn(),
      upsert: jest.fn(),
      deleteMany: jest.fn(),
    },
  };
  const adapter = new PrismaClientAdapter(prisma, 'walletx-secret');

  beforeEach(() => jest.clearAllMocks());

  it('upsert stores dynamic client and strips offline_access from scope', async () => {
    await adapter.upsert('dyn-client-1', {
      client_name: 'Claude',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      token_endpoint_auth_method: 'none',
      scope: 'openid mcp:calendar offline_access',
    }, 0);
    const call = prisma.oAuthClient.upsert.mock.calls[0][0];
    expect(call.where).toEqual({ clientId: 'dyn-client-1' });
    expect(call.create.isDynamic).toBe(true);
    expect(call.create.dcrMetadata.scope).toBe('openid mcp:calendar');
  });

  it('find returns dcrMetadata for dynamic client', async () => {
    prisma.oAuthClient.findUnique.mockResolvedValue({
      clientId: 'dyn-client-1',
      isDynamic: true,
      dcrMetadata: { client_id: 'dyn-client-1', client_name: 'Claude' },
    });
    const result = await adapter.find('dyn-client-1');
    expect(result).toEqual({ client_id: 'dyn-client-1', client_name: 'Claude' });
  });

  it('destroy deletes only dynamic clients', async () => {
    await adapter.destroy('dyn-client-1');
    expect(prisma.oAuthClient.deleteMany).toHaveBeenCalledWith({
      where: { clientId: 'dyn-client-1', isDynamic: true },
    });
  });
});
```

- [ ] **Step 3: Run test — verify FAIL**

Run: `npx jest src/oidc/adapters/prisma-client-adapter.spec.ts`
Expected: FAIL (upsert — заглушка, find не знает про dcrMetadata).

- [ ] **Step 4: Реализация**

В `find()` — первой проверкой (до существующей логики):

```typescript
const row = await this.prisma.oAuthClient.findUnique({ where: { clientId: id } });
if (row?.isDynamic) return row.dcrMetadata as Record<string, any>;
// далее — существующая логика для статических клиентов (использовать уже загруженный row)
```

Заменить заглушку `upsert`:

```typescript
async upsert(id: string, payload: any, _expiresIn: number): Promise<void> {
  const scope = String(payload.scope ?? '')
    .split(' ')
    .filter((s) => s && s !== 'offline_access') // offline_access только для verified partners (ставится вручную)
    .join(' ');
  const metadata = { ...payload, scope };
  await this.prisma.oAuthClient.upsert({
    where: { clientId: id },
    create: {
      clientId: id,
      clientSecret: payload.client_secret ?? '',
      name: payload.client_name ?? id,
      redirectUris: payload.redirect_uris ?? [],
      allowedScopes: scope.split(' ').filter(Boolean),
      isDynamic: true,
      dcrMetadata: metadata,
    },
    update: { dcrMetadata: metadata, redirectUris: payload.redirect_uris ?? [] },
  });
}
```

Заменить заглушку `destroy`:

```typescript
async destroy(id: string): Promise<void> {
  await this.prisma.oAuthClient.deleteMany({ where: { clientId: id, isDynamic: true } });
}
```

- [ ] **Step 5: Run test — verify PASS**

Run: `npx jest src/oidc/adapters/prisma-client-adapter.spec.ts`
Expected: 3 passed. Если существующий `find()` использовал другой prisma-вызов (не `findUnique` по clientId) — адаптировать мок под фактический вызов, не наоборот.

- [ ] **Step 6: Commit**

```bash
git add src/oidc/adapters/prisma-client-adapter.ts src/oidc/adapters/prisma-client-adapter.spec.ts
git commit -m "feat(mcp): DCR client storage in PrismaClientAdapter"
```

---

### Task 3: OIDC-фабрика — mcp-scopes + DCR за env-флагом

**Files:**
- Modify: `src/oidc/oidc-provider.factory.ts` (конфиг Provider, строки ~60-80)

- [ ] **Step 1: Расширить scopes**

В массив `scopes` добавить:

```typescript
      'mcp:calendar',
      'mcp:notes',
      'mcp:messages.read',
      'mcp:messages.send',
```

- [ ] **Step 2: Включить registration и client auth 'none'**

В `features` добавить:

```typescript
      registration: {
        enabled: process.env.OIDC_DCR_ENABLED === 'true',
      },
```

На верхнем уровне конфига Provider (рядом с `responseTypes`) добавить:

```typescript
    clientAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
```

(MCP-клиенты типа Claude — public clients с `token_endpoint_auth_method: 'none'` + PKCE; PKCE уже required.)

- [ ] **Step 3: Build + существующие тесты**

Run: `npm run build && npx jest src/oidc`
Expected: сборка ок, тесты зелёные.

- [ ] **Step 4: Добавить env на DEV** (не деплой — просто фиксация): в задаче 14 при деплое добавить `OIDC_DCR_ENABLED=true` в `~/taler-id/.env` на DEV. В коде дефолт — выключено (kill-switch).

- [ ] **Step 5: Commit**

```bash
git add src/oidc/oidc-provider.factory.ts
git commit -m "feat(mcp): mcp scopes + env-gated dynamic client registration"
```

---

### Task 4: Rate-limit на POST /oauth/reg

**Files:**
- Modify: `src/main.ts` (перед `expressApp.use('/oauth', ...)`, строки ~555-575)

- [ ] **Step 1: Добавить middleware**

Перед строкой `expressApp.use('/oauth', ...)` вставить (Redis-клиент уже доступен — найти в main.ts, как его получает oidc-фабрика, и переиспользовать тот же инстанс/фабрику):

```typescript
  // DCR registration rate-limit: 10/min per IP (защита от мусорной регистрации клиентов)
  expressApp.use('/oauth/reg', async (req: any, res: any, next: any) => {
    if (req.method !== 'POST') return next();
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const key = `dcr_rl:${ip}`;
    const count = await redisClient.incr(key);
    if (count === 1) await redisClient.expire(key, 60);
    if (count > 10) {
      return res.status(429).json({ error: 'too_many_requests' });
    }
    return next();
  });
```

- [ ] **Step 2: Build**

Run: `npm run build`
Expected: ок. (Функционально проверится в e2e задачи 12 — негативный rate-limit-тест в suite не делаем, чтобы не флапать; достаточно ручного `for i in $(seq 12); do curl -s -o /dev/null -w '%{http_code}\n' -X POST https://staging.id.taler.tirol/oauth/reg -H 'content-type: application/json' -d '{}'; done` после деплоя DEV — последние два должны быть 429.)

- [ ] **Step 3: Commit**

```bash
git add src/main.ts
git commit -m "feat(mcp): rate-limit DCR registration endpoint"
```

---

### Task 5: SDK + McpAuthGuard

**Files:**
- Modify: `package.json` (deps)
- Create: `src/mcp/mcp-auth.guard.ts`
- Test: `src/mcp/mcp-auth.guard.spec.ts`

- [ ] **Step 1: Установить зависимости**

Run: `npm i @modelcontextprotocol/sdk zod`
Expected: установлено без peer-конфликтов (если zod уже есть в deps — оставить существующую версию).

- [ ] **Step 2: Написать падающий тест**

```typescript
import { UnauthorizedException } from '@nestjs/common';
import { McpAuthGuard } from './mcp-auth.guard';

function ctx(authHeader?: string) {
  const res = { setHeader: jest.fn() };
  return {
    switchToHttp: () => ({
      getRequest: () => ({ headers: { authorization: authHeader } }),
      getResponse: () => res,
    }),
  } as any;
}

describe('McpAuthGuard', () => {
  const provider: any = { AccessToken: { find: jest.fn() } };
  const guard = new McpAuthGuard(provider);

  beforeEach(() => jest.clearAllMocks());

  it('rejects missing bearer with WWW-Authenticate header', async () => {
    await expect(guard.canActivate(ctx(undefined))).rejects.toThrow(UnauthorizedException);
  });

  it('rejects unknown/expired token', async () => {
    provider.AccessToken.find.mockResolvedValue(undefined);
    await expect(guard.canActivate(ctx('Bearer nope'))).rejects.toThrow(UnauthorizedException);
  });

  it('attaches mcpAuth on valid token', async () => {
    provider.AccessToken.find.mockResolvedValue({
      accountId: 'user-1',
      clientId: 'client-1',
      scope: 'openid mcp:calendar mcp:messages.read',
    });
    const c = ctx('Bearer good');
    const req = c.switchToHttp().getRequest();
    await expect(guard.canActivate(c)).resolves.toBe(true);
    expect(req.mcpAuth).toEqual({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid', 'mcp:calendar', 'mcp:messages.read'],
    });
  });
});
```

⚠️ Тест использует один и тот же request-объект — в guard'e писать в `getRequest()` результат. Если тест-хелпер выше отдаёт новый объект на каждый вызов — вынести req в переменную хелпера (поправить хелпер, чтобы `getRequest` возвращал один инстанс).

- [ ] **Step 3: Run — verify FAIL**

Run: `npx jest src/mcp/mcp-auth.guard.spec.ts`
Expected: FAIL — модуль не существует.

- [ ] **Step 4: Реализация**

`src/mcp/mcp-auth.guard.ts`:

```typescript
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { OIDC_PROVIDER } from '../oidc/oidc.service';

export interface McpAuthContext {
  userId: string;
  clientId: string;
  scopes: string[];
}

@Injectable()
export class McpAuthGuard implements CanActivate {
  constructor(@Inject(OIDC_PROVIDER) private readonly provider: any) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();
    const issuer = process.env.OIDC_ISSUER_URL || 'https://staging.id.taler.tirol/oauth';
    const resourceBase = issuer.replace(/\/oauth$/, '');
    res.setHeader(
      'WWW-Authenticate',
      `Bearer resource_metadata="${resourceBase}/.well-known/oauth-protected-resource"`,
    );

    const auth: string = req.headers?.authorization ?? '';
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer' || !token) {
      throw new UnauthorizedException('Missing bearer token');
    }
    const at = await this.provider.AccessToken.find(token).catch(() => undefined);
    if (!at?.accountId) {
      throw new UnauthorizedException('Invalid or expired token');
    }
    req.mcpAuth = {
      userId: at.accountId,
      clientId: at.clientId,
      scopes: String(at.scope ?? '').split(' ').filter(Boolean),
    } satisfies McpAuthContext;
    return true;
  }
}
```

⚠️ Перед кодингом проверить в `src/main.ts` (район строки 535), из какой env-переменной строится issuer, и использовать её вместо `OIDC_ISSUER_URL`, если имя другое.

- [ ] **Step 5: Run — verify PASS**

Run: `npx jest src/mcp/mcp-auth.guard.spec.ts`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json src/mcp/mcp-auth.guard.ts src/mcp/mcp-auth.guard.spec.ts
git commit -m "feat(mcp): MCP SDK dependency + bearer auth guard over OIDC access tokens"
```

---

### Task 6: MessengerService.listContacts

**Files:**
- Modify: `src/messenger/messenger.service.ts` (рядом с `hasContactWith`, строка ~1916)
- Test: `src/messenger/messenger.service.contacts.spec.ts` (создать)

- [ ] **Step 1: Падающий тест**

```typescript
import { MessengerService } from './messenger.service';

describe('MessengerService.listContacts', () => {
  it('returns profile info for accepted contacts in both directions', async () => {
    const prisma: any = {
      contactRequest: {
        findMany: jest.fn().mockResolvedValue([
          { senderId: 'me', receiverId: 'u2' },
          { senderId: 'u3', receiverId: 'me' },
        ]),
      },
      user: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'u2', username: 'ivan', profile: { firstName: 'Ivan', lastName: 'P' } },
          { id: 'u3', username: 'anna', profile: { firstName: 'Anna', lastName: 'K' } },
        ]),
      },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;

    const contacts = await service.listContacts('me');
    expect(prisma.user.findMany.mock.calls[0][0].where.id.in).toEqual(['u2', 'u3']);
    expect(contacts).toHaveLength(2);
    expect(contacts[0]).toMatchObject({ id: 'u2', username: 'ivan' });
  });
});
```

- [ ] **Step 2: Run — verify FAIL**

Run: `npx jest src/messenger/messenger.service.contacts.spec.ts`
Expected: FAIL — `listContacts is not a function`.

- [ ] **Step 3: Реализация** — после `hasContactWith`:

```typescript
  async listContacts(userId: string) {
    const requests = await this.prisma.contactRequest.findMany({
      where: {
        status: 'ACCEPTED',
        OR: [{ senderId: userId }, { receiverId: userId }],
      },
      select: { senderId: true, receiverId: true },
    });
    const ids = requests.map((r) =>
      r.senderId === userId ? r.receiverId : r.senderId,
    );
    if (ids.length === 0) return [];
    return this.prisma.user.findMany({
      where: { id: { in: ids } },
      select: {
        id: true,
        username: true,
        profile: { select: { firstName: true, lastName: true } },
      },
    });
  }
```

- [ ] **Step 4: Run — verify PASS**

Run: `npx jest src/messenger/messenger.service.contacts.spec.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/messenger.service.ts src/messenger/messenger.service.contacts.spec.ts
git commit -m "feat(mcp): MessengerService.listContacts"
```

---

### Task 7: Calendar tools

**Files:**
- Create: `src/mcp/tools/calendar.tools.ts`
- Test: `src/mcp/tools/calendar.tools.spec.ts`

Используемые сигнатуры CalendarService (`src/calendar/calendar.service.ts`): `findByRange(userId, from?, to?)`, `findOne(userId, id)`, `create(...)` (строка 154 — прочитать точную сигнатуру перед кодингом и подогнать маппинг create-tool), `update(userId, id, data)`, `remove(userId, id)`.

- [ ] **Step 1: Падающий тест**

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerCalendarTools } from './calendar.tools';

describe('calendar tools', () => {
  const calendar: any = {
    findByRange: jest.fn().mockResolvedValue([{ id: 'e1', title: 'Standup' }]),
    findOne: jest.fn().mockResolvedValue({ id: 'e1', title: 'Standup' }),
    create: jest.fn().mockResolvedValue({ id: 'e2' }),
    update: jest.fn().mockResolvedValue({ id: 'e1' }),
    remove: jest.fn().mockResolvedValue({ ok: true }),
  };

  function build() {
    const server = new McpServer({ name: 't', version: '1' });
    registerCalendarTools(server, calendar, 'user-1');
    return server;
  }

  it('registers all five tools', () => {
    const server = build();
    const names = Object.keys((server as any)._registeredTools);
    expect(names.sort()).toEqual([
      'create_calendar_event',
      'delete_calendar_event',
      'get_calendar_event',
      'list_calendar_events',
      'update_calendar_event',
    ]);
  });

  it('list passes userId and range', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['list_calendar_events'];
    const result = await tool.callback({ from: '2026-07-01', to: '2026-07-31' }, {} as any);
    expect(calendar.findByRange).toHaveBeenCalledWith('user-1', '2026-07-01', '2026-07-31');
    expect(JSON.parse(result.content[0].text)).toHaveLength(1);
  });
});
```

ℹ️ Если внутреннее поле SDK называется не `_registeredTools` — посмотреть в `node_modules/@modelcontextprotocol/sdk/dist/cjs/server/mcp.js` и адаптировать тест (интересует только «tool зарегистрирован и его callback дергает сервис»).

- [ ] **Step 2: Run — verify FAIL**

Run: `npx jest src/mcp/tools/calendar.tools.spec.ts`
Expected: FAIL — модуль не существует.

- [ ] **Step 3: Реализация**

```typescript
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CalendarService } from '../../calendar/calendar.service';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

function err(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}

export function registerCalendarTools(
  server: McpServer,
  calendar: CalendarService,
  userId: string,
) {
  server.registerTool(
    'list_calendar_events',
    {
      description:
        'Список событий календаря пользователя за период. from/to — ISO даты.',
      inputSchema: { from: z.string().optional(), to: z.string().optional() },
    },
    async ({ from, to }) => json(await calendar.findByRange(userId, from, to)),
  );

  server.registerTool(
    'get_calendar_event',
    {
      description: 'Детали события календаря по id.',
      inputSchema: { id: z.string() },
    },
    async ({ id }) => {
      try {
        return json(await calendar.findOne(userId, id));
      } catch {
        return err(`Событие ${id} не найдено`);
      }
    },
  );

  server.registerTool(
    'create_calendar_event',
    {
      description:
        'Создать событие календаря. start/end — ISO datetime. reminder_minutes_before — за сколько минут напомнить (опционально).',
      inputSchema: {
        title: z.string(),
        start: z.string(),
        end: z.string().optional(),
        description: z.string().optional(),
        reminder_minutes_before: z.number().int().positive().optional(),
      },
    },
    async (args) => {
      const reminderAt = args.reminder_minutes_before
        ? new Date(
            new Date(args.start).getTime() -
              args.reminder_minutes_before * 60_000,
          ).toISOString()
        : undefined;
      // ⚠️ подогнать под фактическую сигнатуру CalendarService.create (строка 154)
      const event = await calendar.create(userId, {
        title: args.title,
        startAt: args.start,
        endAt: args.end,
        description: args.description,
        reminderAt,
      } as any);
      return json(event);
    },
  );

  server.registerTool(
    'update_calendar_event',
    {
      description: 'Обновить событие календаря (частичное обновление).',
      inputSchema: {
        id: z.string(),
        title: z.string().optional(),
        start: z.string().optional(),
        end: z.string().optional(),
        description: z.string().optional(),
        reminder_minutes_before: z.number().int().positive().optional(),
      },
    },
    async ({ id, ...rest }) => {
      try {
        return json(await calendar.update(userId, id, rest as any));
      } catch {
        return err(`Событие ${id} не найдено или нет прав`);
      }
    },
  );

  server.registerTool(
    'delete_calendar_event',
    {
      description: 'Удалить событие календаря по id.',
      inputSchema: { id: z.string() },
    },
    async ({ id }) => {
      try {
        await calendar.remove(userId, id);
        return json({ deleted: id });
      } catch {
        return err(`Событие ${id} не найдено или нет прав`);
      }
    },
  );
}
```

⚠️ Обязательный под-шаг: прочитать `src/calendar/calendar.service.ts:154-260` (`create`, `update`) и привести имена полей (`startAt`/`start`/`startsAt`, где живёт `reminderAt`) к фактическим. Тест из Step 1 дополнить проверкой маппинга create.

- [ ] **Step 4: Run — verify PASS**

Run: `npx jest src/mcp/tools/calendar.tools.spec.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/tools/calendar.tools.ts src/mcp/tools/calendar.tools.spec.ts
git commit -m "feat(mcp): calendar tools"
```

---

### Task 8: Notes tools

**Files:**
- Create: `src/mcp/tools/notes.tools.ts`
- Test: `src/mcp/tools/notes.tools.spec.ts`

Сигнатуры NotesService: `findAll(userId, limit=50, offset=0)`, `findOne(userId, id)`, `create(...)` (строка 29 — прочитать), `update(...)` (строка 53), `remove(userId, id)`.

- [ ] **Step 1: Падающий тест** (тот же паттерн, что calendar):

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerNotesTools } from './notes.tools';

describe('notes tools', () => {
  const notes: any = {
    findAll: jest.fn().mockResolvedValue([{ id: 'n1', title: 'todo' }]),
    create: jest.fn().mockResolvedValue({ id: 'n2' }),
    update: jest.fn().mockResolvedValue({ id: 'n1' }),
    remove: jest.fn().mockResolvedValue({ ok: true }),
  };

  it('registers four tools and list calls service with userId', async () => {
    const server = new McpServer({ name: 't', version: '1' });
    registerNotesTools(server, notes, 'user-1');
    const tools = (server as any)._registeredTools;
    expect(Object.keys(tools).sort()).toEqual([
      'create_note',
      'delete_note',
      'list_notes',
      'update_note',
    ]);
    await tools['list_notes'].callback({}, {} as any);
    expect(notes.findAll).toHaveBeenCalledWith('user-1', 50, 0);
  });
});
```

- [ ] **Step 2: Run — verify FAIL** — `npx jest src/mcp/tools/notes.tools.spec.ts`

- [ ] **Step 3: Реализация**

```typescript
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { NotesService } from '../../notes/notes.service';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

export function registerNotesTools(
  server: McpServer,
  notes: NotesService,
  userId: string,
) {
  server.registerTool(
    'list_notes',
    {
      description: 'Список заметок пользователя.',
      inputSchema: {
        limit: z.number().int().positive().max(100).optional(),
        offset: z.number().int().nonnegative().optional(),
      },
    },
    async ({ limit, offset }) =>
      json(await notes.findAll(userId, limit ?? 50, offset ?? 0)),
  );

  server.registerTool(
    'create_note',
    {
      description: 'Создать заметку.',
      // ⚠️ подогнать поля под фактическую сигнатуру NotesService.create (строка 29)
      inputSchema: { title: z.string().optional(), content: z.string() },
    },
    async (args) => json(await notes.create(userId, args as any)),
  );

  server.registerTool(
    'update_note',
    {
      description: 'Обновить заметку по id.',
      inputSchema: {
        id: z.string(),
        title: z.string().optional(),
        content: z.string().optional(),
      },
    },
    async ({ id, ...rest }) => json(await notes.update(userId, id, rest as any)),
  );

  server.registerTool(
    'delete_note',
    {
      description: 'Удалить заметку по id.',
      inputSchema: { id: z.string() },
    },
    async ({ id }) => {
      await notes.remove(userId, id);
      return json({ deleted: id });
    },
  );
}
```

- [ ] **Step 4: Run — verify PASS**, поправив маппинг create/update под фактические сигнатуры.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/tools/notes.tools.ts src/mcp/tools/notes.tools.spec.ts
git commit -m "feat(mcp): notes tools"
```

---

### Task 9: Messenger tools

**Files:**
- Create: `src/mcp/tools/messenger.tools.ts`
- Test: `src/mcp/tools/messenger.tools.spec.ts`

Используемые методы MessengerService: `listContacts(userId)` (Task 6), `getConversations(userId)`, `getMessages(conversationId, userId, cursor?, limit=30)`, `searchMessages(q, userId)`, `hasContactWith(a, b)`, `getOrCreateDirectConversation(a, b)`, `createMessage(conversationId, senderId, content)`, `getMessageById(id)`, `getUserDisplayName(id)`. Broadcast — `MessengerGateway.server.to(conversationId).emit('new_message', ...)` (паттерн из `messenger.controller.ts:1119`).

**Scope-гранулярность:** read-tools (`list_contacts`, `list_conversations`, `get_messages`, `search_messages`) — под `mcp:messages.read`; `send_message` — под `mcp:messages.send`. Фильтрация происходит в factory (Task 10) — здесь два отдельных регистратора.

- [ ] **Step 1: Падающий тест**

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  registerMessengerReadTools,
  registerMessengerSendTool,
} from './messenger.tools';

describe('messenger tools', () => {
  const svc: any = {
    listContacts: jest.fn().mockResolvedValue([{ id: 'u2', username: 'ivan' }]),
    getConversations: jest.fn().mockResolvedValue([]),
    getMessages: jest.fn().mockResolvedValue([]),
    searchMessages: jest.fn().mockResolvedValue([]),
    hasContactWith: jest.fn(),
    getOrCreateDirectConversation: jest.fn().mockResolvedValue({ id: 'conv-1' }),
    createMessage: jest.fn().mockResolvedValue({ id: 'm1', deduped: false }),
    getMessageById: jest.fn().mockResolvedValue({ id: 'm1', content: 'hi' }),
    getUserDisplayName: jest.fn().mockResolvedValue('Me'),
  };
  const gateway: any = {
    server: { to: jest.fn().mockReturnValue({ emit: jest.fn() }) },
  };

  it('read registrar registers 4 tools, send registrar 1', () => {
    const server = new McpServer({ name: 't', version: '1' });
    registerMessengerReadTools(server, svc, 'me');
    registerMessengerSendTool(server, svc, gateway, 'me');
    expect(Object.keys((server as any)._registeredTools).sort()).toEqual([
      'get_messages',
      'list_contacts',
      'list_conversations',
      'search_messages',
      'send_message',
    ]);
  });

  it('send_message refuses non-contact', async () => {
    svc.hasContactWith.mockResolvedValue(false);
    const server = new McpServer({ name: 't', version: '1' });
    registerMessengerSendTool(server, svc, gateway, 'me');
    const result = await (server as any)._registeredTools['send_message'].callback(
      { contact_id: 'stranger', text: 'hi' },
      {} as any,
    );
    expect(result.isError).toBe(true);
    expect(svc.createMessage).not.toHaveBeenCalled();
  });

  it('send_message to contact creates message and broadcasts', async () => {
    svc.hasContactWith.mockResolvedValue(true);
    const server = new McpServer({ name: 't', version: '1' });
    registerMessengerSendTool(server, svc, gateway, 'me');
    const result = await (server as any)._registeredTools['send_message'].callback(
      { contact_id: 'u2', text: 'привет' },
      {} as any,
    );
    expect(svc.createMessage).toHaveBeenCalledWith('conv-1', 'me', 'привет');
    expect(gateway.server.to).toHaveBeenCalledWith('conv-1');
    expect(result.isError).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run — verify FAIL** — `npx jest src/mcp/tools/messenger.tools.spec.ts`

- [ ] **Step 3: Реализация**

```typescript
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { MessengerService } from '../../messenger/messenger.service';
import type { MessengerGateway } from '../../messenger/messenger.gateway';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

function err(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}

export function registerMessengerReadTools(
  server: McpServer,
  svc: MessengerService,
  userId: string,
) {
  server.registerTool(
    'list_contacts',
    {
      description:
        'Контакты пользователя (id, username, имя). Писать сообщения можно только этим людям.',
      inputSchema: {},
    },
    async () => json(await svc.listContacts(userId)),
  );

  server.registerTool(
    'list_conversations',
    {
      description: 'Диалоги пользователя с превью последнего сообщения.',
      inputSchema: {},
    },
    async () => json(await svc.getConversations(userId)),
  );

  server.registerTool(
    'get_messages',
    {
      description:
        'История сообщений диалога. cursor — id сообщения для пагинации назад.',
      inputSchema: {
        conversation_id: z.string(),
        cursor: z.string().optional(),
        limit: z.number().int().positive().max(100).optional(),
      },
    },
    async ({ conversation_id, cursor, limit }) => {
      try {
        return json(
          await svc.getMessages(conversation_id, userId, cursor, limit ?? 30),
        );
      } catch {
        return err('Диалог не найден или вы не участник');
      }
    },
  );

  server.registerTool(
    'search_messages',
    {
      description: 'Поиск по тексту сообщений во всех диалогах пользователя.',
      inputSchema: { query: z.string().min(2) },
    },
    async ({ query }) => json(await svc.searchMessages(query, userId)),
  );
}

export function registerMessengerSendTool(
  server: McpServer,
  svc: MessengerService,
  gateway: MessengerGateway,
  userId: string,
) {
  server.registerTool(
    'send_message',
    {
      description:
        'Отправить текстовое сообщение контакту. contact_id — id пользователя из list_contacts.',
      inputSchema: { contact_id: z.string(), text: z.string().min(1) },
    },
    async ({ contact_id, text }) => {
      const isContact = await svc.hasContactWith(userId, contact_id);
      if (!isContact) {
        return err(
          'Пользователь не в контактах — отправка запрещена. Используйте list_contacts.',
        );
      }
      const conv = await svc.getOrCreateDirectConversation(userId, contact_id);
      const message = await svc.createMessage(conv.id, userId, text);
      if (!(message as any).deduped) {
        const full = await svc.getMessageById(message.id);
        if (full) {
          gateway.server.to(conv.id).emit('new_message', {
            ...full,
            senderName: await svc.getUserDisplayName(userId),
            reactions: [],
          });
        }
      }
      return json({ message_id: message.id, conversation_id: conv.id });
    },
  );
}
```

⚠️ Проверить перед PASS: имя метода `getMessageById` в MessengerService (используется в `messenger.controller.ts:1117`) и форму возврата `getOrCreateDirectConversation` (поле `id`). Подогнать при расхождении.

- [ ] **Step 4: Run — verify PASS** — `npx jest src/mcp/tools/messenger.tools.spec.ts`

- [ ] **Step 5: Commit**

```bash
git add src/mcp/tools/messenger.tools.ts src/mcp/tools/messenger.tools.spec.ts
git commit -m "feat(mcp): messenger tools with contact-gated send"
```

---

### Task 10: McpServerFactory + McpController + module wiring

**Files:**
- Create: `src/mcp/mcp-server.factory.ts`
- Create: `src/mcp/mcp.controller.ts`
- Create: `src/mcp/mcp.module.ts`
- Modify: `src/app.module.ts` (imports)
- Test: `src/mcp/mcp-server.factory.spec.ts`

- [ ] **Step 1: Падающий тест factory (scope-фильтрация)**

```typescript
import { McpServerFactory } from './mcp-server.factory';

describe('McpServerFactory scope filtering', () => {
  const factory = new McpServerFactory(
    { findByRange: jest.fn() } as any, // CalendarService
    { findAll: jest.fn() } as any, // NotesService
    { listContacts: jest.fn() } as any, // MessengerService
    { server: { to: jest.fn() } } as any, // MessengerGateway
  );

  function toolNames(scopes: string[]) {
    const server = factory.buildServer('user-1', scopes);
    return Object.keys((server as any)._registeredTools).sort();
  }

  it('calendar scope → only calendar tools', () => {
    expect(toolNames(['mcp:calendar'])).toEqual([
      'create_calendar_event',
      'delete_calendar_event',
      'get_calendar_event',
      'list_calendar_events',
      'update_calendar_event',
    ]);
  });

  it('messages.read without send → no send_message', () => {
    expect(toolNames(['mcp:messages.read'])).not.toContain('send_message');
    expect(toolNames(['mcp:messages.read'])).toContain('get_messages');
  });

  it('all scopes → 14 tools', () => {
    expect(
      toolNames([
        'mcp:calendar',
        'mcp:notes',
        'mcp:messages.read',
        'mcp:messages.send',
      ]),
    ).toHaveLength(14);
  });
});
```

- [ ] **Step 2: Run — verify FAIL** — `npx jest src/mcp/mcp-server.factory.spec.ts`

- [ ] **Step 3: Реализация factory**

`src/mcp/mcp-server.factory.ts`:

```typescript
import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { CalendarService } from '../calendar/calendar.service';
import { NotesService } from '../notes/notes.service';
import { MessengerService } from '../messenger/messenger.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { registerCalendarTools } from './tools/calendar.tools';
import { registerNotesTools } from './tools/notes.tools';
import {
  registerMessengerReadTools,
  registerMessengerSendTool,
} from './tools/messenger.tools';

@Injectable()
export class McpServerFactory {
  constructor(
    private readonly calendar: CalendarService,
    private readonly notes: NotesService,
    private readonly messenger: MessengerService,
    private readonly gateway: MessengerGateway,
  ) {}

  buildServer(userId: string, scopes: string[]): McpServer {
    const server = new McpServer({ name: 'talerid', version: '1.0.0' });
    if (scopes.includes('mcp:calendar')) {
      registerCalendarTools(server, this.calendar, userId);
    }
    if (scopes.includes('mcp:notes')) {
      registerNotesTools(server, this.notes, userId);
    }
    if (scopes.includes('mcp:messages.read')) {
      registerMessengerReadTools(server, this.messenger, userId);
    }
    if (scopes.includes('mcp:messages.send')) {
      registerMessengerSendTool(server, this.messenger, this.gateway, userId);
    }
    return server;
  }
}
```

- [ ] **Step 4: Run — verify PASS** — `npx jest src/mcp/mcp-server.factory.spec.ts`

- [ ] **Step 5: Controller + well-known**

`src/mcp/mcp.controller.ts`:

```typescript
import {
  All,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { McpAuthGuard } from './mcp-auth.guard';
import { McpServerFactory } from './mcp-server.factory';

const MCP_SCOPES = [
  'mcp:calendar',
  'mcp:notes',
  'mcp:messages.read',
  'mcp:messages.send',
];

@Controller()
export class McpController {
  constructor(private readonly factory: McpServerFactory) {}

  @Post('mcp')
  @UseGuards(McpAuthGuard)
  async handle(@Req() req: Request, @Res() res: Response) {
    const { userId, scopes } = (req as any).mcpAuth;
    const server = this.factory.buildServer(userId, scopes);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless: multi-node за LB без sticky
      enableJsonResponse: true,
    });
    res.on('close', () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, (req as any).body);
  }

  @All('mcp')
  methodNotAllowed(@Res() res: Response) {
    res.status(405).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed. Use POST.' },
      id: null,
    });
  }

  @Get('.well-known/oauth-protected-resource')
  protectedResourceMetadata() {
    const issuer =
      process.env.OIDC_ISSUER_URL || 'https://staging.id.taler.tirol/oauth';
    const base = issuer.replace(/\/oauth$/, '');
    return {
      resource: `${base}/mcp`,
      authorization_servers: [issuer],
      scopes_supported: MCP_SCOPES,
      bearer_methods_supported: ['header'],
    };
  }
}
```

⚠️ Тот же env-var caveat, что в Task 5 — сверить имя с main.ts. NestJS route-order: `@Post('mcp')` должен стоять ДО `@All('mcp')` (как в коде выше), иначе POST перехватится.

`src/mcp/mcp.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { CalendarModule } from '../calendar/calendar.module';
import { NotesModule } from '../notes/notes.module';
import { MessengerModule } from '../messenger/messenger.module';
import { OidcModule } from '../oidc/oidc.module';
import { McpController } from './mcp.controller';
import { McpServerFactory } from './mcp-server.factory';
import { McpAuthGuard } from './mcp-auth.guard';

@Module({
  imports: [CalendarModule, NotesModule, MessengerModule, OidcModule],
  controllers: [McpController],
  providers: [McpServerFactory, McpAuthGuard],
})
export class McpModule {}
```

⚠️ Проверить, что Calendar/Notes/Messenger/Oidc модули **экспортируют** нужные сервисы (`exports: [...]` в их `*.module.ts`); если нет — добавить export (это не ломает существующих потребителей).

- [ ] **Step 6: Подключить в AppModule**

В `src/app.module.ts` добавить `McpModule` в imports.

- [ ] **Step 7: Build + полный прогон юнитов**

Run: `npm run build && npx jest src/mcp src/oidc src/messenger/messenger.service.contacts.spec.ts`
Expected: сборка ок, все зелёные.

- [ ] **Step 8: Commit**

```bash
git add src/mcp/ src/app.module.ts
git commit -m "feat(mcp): /mcp streamable-http endpoint with scope-filtered tools"
```

---

### Task 11: scopeDescriptions в grant-info (consent ru/en)

**Files:**
- Modify: `src/oauth-mobile/oauth-mobile.service.ts`

- [ ] **Step 1: Прочитать `getGrantInfo`** в `src/oauth-mobile/oauth-mobile.service.ts` — найти, где формируется ответ.

- [ ] **Step 2: Добавить статичную карту и включить в ответ**

```typescript
const SCOPE_DESCRIPTIONS: Record<string, { ru: string; en: string }> = {
  'mcp:calendar': {
    ru: 'Просмотр и управление календарём и напоминаниями',
    en: 'View and manage your calendar and reminders',
  },
  'mcp:notes': {
    ru: 'Просмотр и управление заметками',
    en: 'View and manage your notes',
  },
  'mcp:messages.read': {
    ru: 'Чтение ваших сообщений и списка контактов',
    en: 'Read your messages and contact list',
  },
  'mcp:messages.send': {
    ru: 'Отправка сообщений вашим контактам от вашего имени',
    en: 'Send messages to your contacts on your behalf',
  },
};
```

В возвращаемый объект `getGrantInfo` добавить поле:

```typescript
scopeDescriptions: Object.fromEntries(
  requestedScopes
    .filter((s) => SCOPE_DESCRIPTIONS[s])
    .map((s) => [s, SCOPE_DESCRIPTIONS[s]]),
),
```

(`requestedScopes` — как называется список запрошенных scopes в этом методе; подогнать по факту.)

- [ ] **Step 3: Build** — `npm run build`. Expected: ок.

- [ ] **Step 4: Commit**

```bash
git add src/oauth-mobile/oauth-mobile.service.ts
git commit -m "feat(mcp): human-readable scope descriptions in grant-info"
```

---

### Task 12: E2E `test:mcp` в taler_id_tests

**Files (репо `~/Downloads/taler_id_tests`):**
- Create: `mcp_test.ts`
- Modify: `package.json` (scripts)

- [ ] **Step 1: Изучить паттерн** — открыть `channels_test.ts`: как делается login (`integration_test@taler-test.com` / `IntegrationTest123!`), какой HTTP-хелпер, как считаются PASS/FAIL. Скопировать каркас (shebang, BASE_URL из env, counters).

- [ ] **Step 2: Изучить approve-флоу** — открыть в бэкенд-репо `src/oauth-mobile/oauth-mobile.service.ts` и `src/oauth-mobile/dto/*.ts`: точные query-параметры `grant-info` и body `approve`, форма ответа approve (redirect URL с `code`). Ниже — каркас, поля подогнать по факту.

- [ ] **Step 3: Написать `mcp_test.ts`**

Проверки (каркас; JSON-RPC-хелпер обязателен):

```typescript
// Хелперы
import crypto from 'crypto';

const BASE = process.env.BASE_URL || 'https://staging.id.taler.tirol';

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

async function mcpCall(accessToken: string, body: any) {
  const res = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

async function callTool(token: string, name: string, args: any, id: number) {
  return mcpCall(token, {
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name, arguments: args },
  });
}
```

Последовательность тестов:

1. **login** user1 + user2 (REST `/auth/login`) → JWT обоих.
2. **DCR**: `POST /oauth/reg` body `{ client_name: 'e2e-mcp', redirect_uris: ['http://localhost:19999/cb'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code'], response_types: ['code'] }` → assert 201 + `client_id` в ответе.
3. **Code flow**: pkce() → `GET /oauth/mobile/grant-info` (JWT user1, scope `openid mcp:calendar mcp:notes mcp:messages.read mcp:messages.send`) → `POST /oauth/mobile/approve` → извлечь `code` из redirect-URL → `POST /oauth/token` (`grant_type=authorization_code`, `code_verifier`) → assert `access_token`.
4. **MCP initialize**: `mcpCall(token, { jsonrpc:'2.0', id:1, method:'initialize', params:{ protocolVersion:'2025-03-26', capabilities:{}, clientInfo:{ name:'e2e', version:'1' } } })` → assert 200 + `result.serverInfo.name === 'talerid'`.
5. **tools/list** → assert 14 tools, включая `send_message`.
6. **Scope-фильтрация**: второй DCR-клиент, code flow только со scope `openid mcp:calendar` → tools/list → assert 5 tools, `send_message` отсутствует; `tools/call send_message` → error.
7. **Calendar CRUD**: `create_calendar_event` (start = завтра, reminder_minutes_before 30) → извлечь id из `result.content[0].text` → `get_calendar_event` → `update_calendar_event` (title) → `list_calendar_events` содержит → `delete_calendar_event` → `get_calendar_event` → isError.
8. **Notes CRUD**: create → list содержит → update → delete.
9. **send_message**: user1 → user2 (`contact_id` = userId user2; контакт между ними уже есть на DEV) → assert `message_id`; затем REST-ом от user2 `GET /messenger/conversations/91f97844-307b-4a20-ad62-c1d2820e627f/messages` → assert текст доставлен.
10. **search_messages** по отправленному тексту (уникальный маркер `mcp-e2e-<timestamp>`) → найден.
11. **Негатив**: `send_message` с `contact_id` = случайный UUID → `isError: true`; `mcpCall` без Authorization → 401 + заголовок `WWW-Authenticate` содержит `oauth-protected-resource`.

- [ ] **Step 4: Добавить scripts в package.json**

```json
"test:mcp": "BASE_URL=https://staging.id.taler.tirol npx ts-node mcp_test.ts",
"test:mcp:prod": "BASE_URL=https://id.taler.tirol npx ts-node mcp_test.ts"
```

- [ ] **Step 5: Прогнать против DEV** (после деплоя Task 14): `npm run test:mcp` — все проверки зелёные.

- [ ] **Step 6: Commit** (репо taler_id_tests)

```bash
git add mcp_test.ts package.json
git commit -m "test: MCP server e2e suite (DCR, code flow, scope filtering, tools)"
```

---

### Task 13: CLAUDE.md — обязательный тест перед деплоем

**Files:**
- Modify: `/Users/dmitry/talerid/CLAUDE.md` (секция «🧪 ОБЯЗАТЕЛЬНЫЕ ТЕСТЫ»)

- [ ] **Step 1: Добавить пункт после теста 12 (translator):**

```markdown
### 13. Тест MCP-сервера (DEV)
E2E: DCR-регистрация клиента → OAuth code flow (PKCE) → MCP initialize → tools/list со scope-фильтрацией → calendar/notes CRUD → send_message контакту + доставка → негативы (не-контакт, без токена).
```bash
cd ~/Downloads/taler_id_tests && npm run test:mcp
```
- Использует integration_test + integration_test_2. Требует `OIDC_DCR_ENABLED=true` в env бэкенда.
```

Также добавить `npm run test:mcp:prod` в список «После деплоя на TEST».

- [ ] **Step 2: Commit не нужен** (`~/talerid` — не git-репо), просто сохранить файл.

---

### Task 14: Деплой DEV + верификация

- [ ] **Step 1: Прогнать все юниты бэкенда локально**

Run: `cd ~/Downloads/taler_id && npm run build && npx jest`
Expected: все зелёные.

- [ ] **Step 2: Push ветки dev**

```bash
git push origin dev
```

- [ ] **Step 3: Деплой DEV + env-флаг**

```bash
ssh dvolkov@89.169.55.217 'grep -q OIDC_DCR_ENABLED ~/taler-id/.env || echo "OIDC_DCR_ENABLED=true" >> ~/taler-id/.env'
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm ci && npx prisma migrate deploy && npm run build && pm2 restart taler-id-dev'
```

- [ ] **Step 4: Smoke**

```bash
curl -s https://staging.id.taler.tirol/.well-known/oauth-protected-resource | jq
# → resource=.../mcp, authorization_servers=[.../oauth], 4 mcp-scope
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://staging.id.taler.tirol/mcp -H 'content-type: application/json' -d '{}'
# → 401
```

- [ ] **Step 5: E2E** — `cd ~/Downloads/taler_id_tests && npm run test:mcp` → все зелёные.

- [ ] **Step 6: Полный пред-деплойный набор** (CLAUDE.md тесты 4–12) — убедиться, что MCP-изменения ничего не сломали: `npm test && npm run test:voice && npm run test:assistant && npm run test:files && npm run test:channels && npm run test:billing && npm run test:voice-session && npm run test:translator`.

- [ ] **Step 7: Ручная проверка сценария A** — подключить `https://staging.id.taler.tirol/mcp` как custom connector в claude.ai / Claude Desktop: DCR + consent + «покажи мой календарь» / «отправь сообщение …». Зафиксировать результат для пользователя.

> Деплой на TEST и PROD — только по явной команде пользователя, стандартным пайплайном (перед PROD добавить `OIDC_DCR_ENABLED` в env DO app-нод + `npx prisma migrate deploy`).

---

## Self-Review Notes

- **Spec coverage:** endpoint+транспорт (T10), auth+DCR+verified-partner-скоупы (T2,T3,T5), rate-limit (T4), consent-описания (T11), calendar tools (T7), notes tools (T8), messenger tools + contact-gate (T6,T9), well-known (T10), e2e (T12), CLAUDE.md (T13), деплой DEV (T14). Verified-partner admin-UI и webhooks — фаза 2 (вне плана, соответствует спеку).
- **Известные точки подгонки** (помечены ⚠️ в задачах): сигнатура `CalendarService.create/update`, `NotesService.create/update`, имя env-переменной issuer в main.ts, внутреннее поле `_registeredTools` SDK, форма ответа `oauth-mobile approve`. Каждая закрыта явным шагом «прочитать и подогнать» с указанием файла и строки.
- **Type consistency:** `registerCalendarTools/registerNotesTools(server, svc, userId)`, `registerMessengerReadTools(server, svc, userId)`, `registerMessengerSendTool(server, svc, gateway, userId)` — сигнатуры совпадают между задачами 7-10; `McpServerFactory.buildServer(userId, scopes)` совпадает с использованием в контроллере.
