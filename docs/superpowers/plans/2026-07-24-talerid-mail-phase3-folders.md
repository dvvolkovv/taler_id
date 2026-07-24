# Mail Phase 3 — Folders, Sent/Drafts/Trash, Unread Badge — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Полноценные папки почты (Входящие/Отправленные/Черновики/Спам/Корзина + пользовательские), копия отправленных в Sent, черновики, удаление в Корзину и бейдж непрочитанных на планете Mail.

**Architecture:** Бэкенд расширяет существующий `MailBridgeService` (imapflow поверх Mailcow): папки через IMAP LIST/STATUS (Dovecot автосоздаёт special-use Sent/Drafts/Junk/Trash), Sent-копия через IMAP APPEND raw-сообщения, собранного MailComposer (тот же raw уходит в SMTP). Flutter добавляет выбор папки в существующий MailBloc (поле `folder` в state) и счётчик непрочитанных в бейдж орбиты.

**Tech Stack:** NestJS + imapflow + nodemailer (MailComposer), Flutter BLoC, тесты ts-node (mail_test.ts) + jest + bloc_test.

**Репо/ветки:** `~/Downloads/taler_id` (dev), `~/Downloads/taler_id_mobile/.worktrees/dev-merge` (dev), тесты `~/Downloads/taler_id_tests/mail_test.ts`.

**Якоря в текущем коде:**
- `src/mail/mail-bridge.service.ts` — `withImap()` (строка ~40), `listMessages(userId, folder='INBOX', beforeUid?, limit=30)` уже принимает folder; `getMessage`/`getAttachment`/`setSeen`/`deleteMessage` жёстко `'INBOX'` (строки 140, 175, 221, 233); `sendMessage` шлёт через nodemailer SMTP-транспорт (строка 242), raw не сохраняется.
- `src/mail/mail.controller.ts` — `GET /mail/messages` уже прокидывает `?folder=`; остальные message-роуты без folder.
- Flutter: `lib/features/mail/data/datasources/mail_remote_datasource.dart` (методы см. ниже), `mail_bloc.dart`/`mail_state.dart` (state: `items`, `nextCursor`, `isLoading`, `isLoadingMore`, `noAccount`, `error`), `mail_inbox_screen.dart` (ListView.builder, Dismissible per item, FAB compose).
- Бейджи орбиты: `lib/features/assistant/presentation/screens/assistant_screen.dart:1468-1512` — `_NavCircle(badge: ...)`, Mail сейчас `badge: 0`.

---

## Задача 1: Backend — папки (LIST/STATUS, создание/удаление)

**Files:**
- Modify: `src/mail/mail-bridge.service.ts`
- Modify: `src/mail/mail.controller.ts`
- Test: `src/mail/mail-bridge.folders.spec.ts` (create)

- [ ] **Step 1: Юнит-тест на маппинг папок**

`src/mail/mail-bridge.folders.spec.ts`:
```typescript
import { mapFolderEntry, SPECIAL_ORDER } from './mail-folders.util';

describe('mapFolderEntry', () => {
  it('maps special-use to stable role names', () => {
    expect(mapFolderEntry({ path: 'INBOX', specialUse: undefined, flags: new Set() }).role).toBe('inbox');
    expect(mapFolderEntry({ path: 'Sent', specialUse: '\\Sent', flags: new Set() }).role).toBe('sent');
    expect(mapFolderEntry({ path: 'Drafts', specialUse: '\\Drafts', flags: new Set() }).role).toBe('drafts');
    expect(mapFolderEntry({ path: 'Junk', specialUse: '\\Junk', flags: new Set() }).role).toBe('junk');
    expect(mapFolderEntry({ path: 'Trash', specialUse: '\\Trash', flags: new Set() }).role).toBe('trash');
    expect(mapFolderEntry({ path: 'My/Custom', specialUse: undefined, flags: new Set() }).role).toBe('custom');
  });
  it('orders special folders before custom', () => {
    expect(SPECIAL_ORDER.inbox).toBeLessThan(SPECIAL_ORDER.sent);
    expect(SPECIAL_ORDER.trash).toBeLessThan(SPECIAL_ORDER.custom);
  });
});
```

- [ ] **Step 2: Запустить — FAIL (модуль не существует)**

Run: `cd ~/Downloads/taler_id && npx jest src/mail/mail-bridge.folders.spec.ts`
Expected: FAIL "Cannot find module './mail-folders.util'"

- [ ] **Step 3: Создать `src/mail/mail-folders.util.ts`**

```typescript
export type FolderRole = 'inbox' | 'sent' | 'drafts' | 'junk' | 'trash' | 'custom';

export const SPECIAL_ORDER: Record<FolderRole, number> = {
  inbox: 0, sent: 1, drafts: 2, junk: 3, trash: 4, custom: 5,
};

export function mapFolderEntry(e: { path: string; specialUse?: string; flags: Set<string> }): {
  path: string; role: FolderRole;
} {
  if (e.path.toUpperCase() === 'INBOX') return { path: e.path, role: 'inbox' };
  switch (e.specialUse) {
    case '\\Sent': return { path: e.path, role: 'sent' };
    case '\\Drafts': return { path: e.path, role: 'drafts' };
    case '\\Junk': return { path: e.path, role: 'junk' };
    case '\\Trash': return { path: e.path, role: 'trash' };
    default: return { path: e.path, role: 'custom' };
  }
}
```

- [ ] **Step 4: Тест зелёный** — `npx jest src/mail/mail-bridge.folders.spec.ts` → PASS

- [ ] **Step 5: `listFolders` в MailBridgeService**

В `mail-bridge.service.ts` добавить import `{ mapFolderEntry, SPECIAL_ORDER }` и метод:
```typescript
async listFolders(userId: string) {
  return this.withImap(userId, async (client) => {
    const boxes = await client.list({ statusQuery: { messages: true, unseen: true } });
    const folders = boxes
      .filter((b) => !b.flags?.has('\\Noselect'))
      .map((b) => {
        const { path, role } = mapFolderEntry({ path: b.path, specialUse: b.specialUse, flags: b.flags ?? new Set() });
        return {
          path,
          role,
          name: b.name,
          total: b.status?.messages ?? 0,
          unseen: b.status?.unseen ?? 0,
        };
      });
    folders.sort((a, b) => SPECIAL_ORDER[a.role] - SPECIAL_ORDER[b.role] || a.path.localeCompare(b.path));
    return { folders };
  });
}

async createFolder(userId: string, name: string): Promise<void> {
  const safe = (name ?? '').trim();
  if (!safe || safe.length > 64 || /[\/%*"\\]/.test(safe)) throw new BadRequestException('folder_name_invalid');
  await this.withImap(userId, async (client) => {
    await client.mailboxCreate(safe).catch((e) => {
      if (String(e?.message).includes('ALREADYEXISTS')) throw new BadRequestException('folder_exists');
      throw e;
    });
  });
}

async deleteFolder(userId: string, path: string): Promise<void> {
  await this.withImap(userId, async (client) => {
    const boxes = await client.list();
    const box = boxes.find((b) => b.path === path);
    if (!box) throw new NotFoundException('folder_not_found');
    const { role } = mapFolderEntry({ path: box.path, specialUse: box.specialUse, flags: box.flags ?? new Set() });
    if (role !== 'custom') throw new BadRequestException('folder_protected');
    await client.mailboxDelete(path);
  });
}
```

- [ ] **Step 6: Роуты в mail.controller.ts**

После блока app-passwords добавить:
```typescript
@Get('folders')
listFolders(@CurrentUser() user: any) {
  return this.bridge.listFolders(user.sub);
}

@Post('folders')
async createFolder(@CurrentUser() user: any, @Body() dto: { name: string }) {
  await this.bridge.createFolder(user.sub, dto.name);
  return { ok: true };
}

@Delete('folders/:path')
async deleteFolder(@CurrentUser() user: any, @Param('path') path: string) {
  await this.bridge.deleteFolder(user.sub, decodeURIComponent(path));
  return { ok: true };
}
```

- [ ] **Step 7: `npm run build` → 0 ошибок; commit**

```bash
git add src/mail && git commit -m "feat(mail): folders — LIST/STATUS with roles, create/delete custom"
```

## Задача 2: Backend — folder-параметр во всех message-операциях + move

**Files:**
- Modify: `src/mail/mail-bridge.service.ts:135-240` (getMessage, getAttachment, setSeen, deleteMessage)
- Modify: `src/mail/mail.controller.ts:68-119`

- [ ] **Step 1: Прокинуть `folder` (default `'INBOX'`) в сигнатуры**

`getMessage(userId, uid, folder = 'INBOX')`, `getAttachment(userId, uid, index, folder = 'INBOX')`, `setSeen(userId, uid, seen, folder = 'INBOX')` — заменить жёсткие `getMailboxLock('INBOX')` на `getMailboxLock(folder)` (обёртка try/catch → `folder_not_found` уже есть в getMessage/getAttachment; в setSeen добавить такую же).

- [ ] **Step 2: deleteMessage → перемещение в Корзину**

```typescript
async deleteMessage(userId: string, uid: number, folder = 'INBOX'): Promise<void> {
  await this.withImap(userId, async (client) => {
    const boxes = await client.list();
    const trash = boxes.find((b) => b.specialUse === '\\Trash');
    const inTrash = trash && folder === trash.path;
    const lock = await client.getMailboxLock(folder);
    try {
      if (trash && !inTrash) {
        await client.messageMove(String(uid), trash.path, { uid: true });
      } else {
        await client.messageDelete(String(uid), { uid: true });
      }
    } finally {
      lock.release();
    }
  });
}

async moveMessage(userId: string, uid: number, fromFolder: string, toFolder: string): Promise<void> {
  await this.withImap(userId, async (client) => {
    let lock: Awaited<ReturnType<typeof client.getMailboxLock>>;
    try {
      lock = await client.getMailboxLock(fromFolder);
    } catch {
      throw new NotFoundException('folder_not_found');
    }
    try {
      await client.messageMove(String(uid), toFolder, { uid: true });
    } finally {
      lock.release();
    }
  });
}
```

- [ ] **Step 3: Контроллер — `?folder=` на getMessage/attachment/read/unread/delete + POST move**

```typescript
@Get('messages/:uid')
getMessage(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number, @Query('folder') folder?: string) {
  return this.bridge.getMessage(user.sub, uid, folder || 'INBOX');
}
// аналогично добавить @Query('folder') в getAttachment/markRead/markUnread/deleteMessage

@Post('messages/:uid/move')
async moveMessage(
  @CurrentUser() user: any,
  @Param('uid', ParseIntPipe) uid: number,
  @Body() dto: { fromFolder?: string; toFolder: string },
) {
  await this.bridge.moveMessage(user.sub, uid, dto.fromFolder || 'INBOX', dto.toFolder);
  return { ok: true };
}
```

- [ ] **Step 4: build + commit** `feat(mail): folder param on message ops, delete→Trash, move endpoint`

## Задача 3: Backend — Sent-копия при отправке + черновики

**Files:**
- Modify: `src/mail/mail-bridge.service.ts:242-283` (sendMessage)
- Modify: `src/mail/mail.controller.ts`

- [ ] **Step 1: sendMessage — собрать raw через MailComposer, отправить, APPEND в Sent**

```typescript
import MailComposer from 'nodemailer/lib/mail-composer';

// в sendMessage вместо transport.sendMail({...}):
const mail = new MailComposer({
  from: address,
  to: input.to,
  subject: input.subject,
  text: input.text,
  inReplyTo: inReplyToHeader,
  references: inReplyToHeader,
  attachments: (input.attachments ?? []).map((a) => ({
    filename: a.filename,
    content: Buffer.from(a.contentBase64, 'base64'),
  })),
});
const raw: Buffer = await mail.compile().build();
await transport.sendMail({ envelope: { from: address, to: [input.to] }, raw });
// Копия в Отправленные — best-effort: сбой APPEND не должен ронять отправку
try {
  await this.withImap(userId, async (client) => {
    const boxes = await client.list();
    const sent = boxes.find((b) => b.specialUse === '\\Sent');
    if (sent) await client.append(sent.path, raw, ['\\Seen']);
  });
} catch (e) {
  this.logger.warn(`sent-copy append failed for ${address}: ${(e as Error).message}`);
}
```

- [ ] **Step 2: Черновики — save/update/delete**

```typescript
async saveDraft(
  userId: string,
  input: { to?: string; subject?: string; text?: string; replaceUid?: number },
): Promise<{ uid: number | null }> {
  const account = await this.accounts.requireActiveAccount(userId);
  const address = this.accounts.address(account);
  const mail = new MailComposer({
    from: address,
    to: input.to || undefined,
    subject: input.subject ?? '',
    text: input.text ?? '',
  });
  const raw: Buffer = await mail.compile().build();
  return this.withImap(userId, async (client) => {
    const boxes = await client.list();
    const drafts = boxes.find((b) => b.specialUse === '\\Drafts');
    if (!drafts) throw new NotFoundException('folder_not_found');
    if (input.replaceUid) {
      const lock = await client.getMailboxLock(drafts.path);
      try {
        await client.messageDelete(String(input.replaceUid), { uid: true });
      } finally {
        lock.release();
      }
    }
    const res = await client.append(drafts.path, raw, ['\\Draft', '\\Seen']);
    return { uid: res?.uid ?? null };
  });
}
```

Роут: `@Post('drafts')` → `saveDraft(user.sub, dto)`; удаление/чтение черновиков идёт через обычные `messages`-роуты с `?folder=<Drafts path>` (уже работает после Задачи 2).

- [ ] **Step 3: Unread-счётчик для бейджа**

```typescript
async unreadCount(userId: string): Promise<{ unseen: number }> {
  return this.withImap(userId, async (client) => {
    const st = await client.status('INBOX', { unseen: true });
    return { unseen: st.unseen ?? 0 };
  });
}
```
Роут `@Get('unread-count')`. В контроллере обернуть: если аккаунта нет (`requireActiveAccount` кидает 404) — вернуть `{ unseen: 0 }`, чтобы орбита не сыпала 404 у юзеров без ящика.

- [ ] **Step 4: build + jest src/mail + commit** `feat(mail): sent copy on send, drafts, unread-count`

## Задача 4: E2E-тест (taler_id_tests/mail_test.ts)

**Files:** Modify: `~/Downloads/taler_id_tests/mail_test.ts` (после блока 5, перед блоком 6)

- [ ] **Step 1: Добавить проверки 7.x**

```typescript
// 7. Папки: спец-набор, Sent-копия, черновики, корзина, move, unread
const folders = await http.get('/mail/folders', auth(t1));
const roles = (folders.data.folders as any[]).map((f) => f.role);
check('7. GET /mail/folders: inbox+sent+drafts+junk+trash', ['inbox','sent','drafts','junk','trash'].every((r) => roles.includes(r)), roles);
const sentPath = (folders.data.folders as any[]).find((f) => f.role === 'sent').path;
const draftsPath = (folders.data.folders as any[]).find((f) => f.role === 'drafts').path;
const trashPath = (folders.data.folders as any[]).find((f) => f.role === 'trash').path;

const sentMarker = `sentcopy-${Date.now()}`;
await http.post('/mail/messages', { to: acc2.address, subject: sentMarker, text: 'body' }, auth(t1));
let sentSeen = false;
for (let i = 0; i < 10 && !sentSeen; i++) {
  await new Promise((r) => setTimeout(r, 2000));
  const s = await http.get(`/mail/messages?folder=${encodeURIComponent(sentPath)}`, auth(t1));
  sentSeen = (s.data.items as any[])?.some((m) => m.subject === sentMarker);
}
check('7b. копия письма появляется в Sent (≤20с)', sentSeen);

const draft = await http.post('/mail/drafts', { to: acc2.address, subject: `draft-${Date.now()}`, text: 'draft body' }, auth(t1));
check('7c. POST /mail/drafts → uid', draft.status < 300 && draft.data.uid, draft.data);
const dList = await http.get(`/mail/messages?folder=${encodeURIComponent(draftsPath)}`, auth(t1));
check('7d. черновик в Drafts', (dList.data.items as any[])?.some((m) => m.uid === draft.data.uid));
check('7e. удаление черновика', (await http.delete(`/mail/messages/${draft.data.uid}?folder=${encodeURIComponent(draftsPath)}`, auth(t1))).status < 300);

const cf = await http.post('/mail/folders', { name: `e2e-${Date.now() % 100000}` }, auth(t1));
check('7f. создание своей папки', cf.status < 300);
const cfPath = `e2e-${'' /* взять из повторного GET /mail/folders */}`;
const foldersAfter = await http.get('/mail/folders', auth(t1));
const custom = (foldersAfter.data.folders as any[]).find((f) => f.role === 'custom' && f.path.startsWith('e2e-'));
check('7g. своя папка в списке', !!custom);
// move: возьмём последнее письмо INBOX user1 (доставленное в 4c ещё живо у user2 — здесь шлём себе)
const selfMarker = `self-${Date.now()}`;
await http.post('/mail/messages', { to: acc1.address, subject: selfMarker, text: 'x' }, auth(t1));
let selfUid: number | null = null;
for (let i = 0; i < 10 && !selfUid; i++) {
  await new Promise((r) => setTimeout(r, 2000));
  const inb = await http.get('/mail/messages', auth(t1));
  selfUid = (inb.data.items as any[])?.find((m) => m.subject === selfMarker)?.uid ?? null;
}
check('7h. self-письмо доставлено', selfUid !== null);
if (selfUid && custom) {
  check('7i. move в свою папку', (await http.post(`/mail/messages/${selfUid}/move`, { toFolder: custom.path }, auth(t1))).status < 300);
  const inCustom = await http.get(`/mail/messages?folder=${encodeURIComponent(custom.path)}`, auth(t1));
  const movedUid = (inCustom.data.items as any[])?.find((m) => m.subject === selfMarker)?.uid;
  check('7j. письмо в своей папке', !!movedUid);
  check('7k. delete → уходит в Trash', (await http.delete(`/mail/messages/${movedUid}?folder=${encodeURIComponent(custom.path)}`, auth(t1))).status < 300);
  const inTrash = await http.get(`/mail/messages?folder=${encodeURIComponent(trashPath)}`, auth(t1));
  check('7l. письмо в Корзине', (inTrash.data.items as any[])?.some((m) => m.subject === selfMarker));
}
check('7m. удаление своей папки', custom ? (await http.delete(`/mail/folders/${encodeURIComponent(custom.path)}`, auth(t1))).status < 300 : false);
const uc = await http.get('/mail/unread-count', auth(t1));
check('7n. unread-count отвечает числом', uc.status === 200 && typeof uc.data.unseen === 'number', uc.data);
```

- [ ] **Step 2: Задеплоить backend на DEV** (`git push origin dev`; на DEV: `git pull && npm run build && pm2 restart taler-id-dev`) и прогнать `npm run test:mail` — все (23 старых + ~14 новых) зелёные.

- [ ] **Step 3: Commit тестов**

## Задача 5: Flutter — datasource/repository/bloc с папками

**Files:**
- Modify: `lib/features/mail/data/datasources/mail_remote_datasource.dart`
- Modify: `lib/features/mail/domain/repositories/i_mail_repository.dart` + data/repositories impl
- Create: `lib/features/mail/domain/entities/mail_folder_entity.dart`
- Modify: `lib/features/mail/presentation/bloc/{mail_bloc,mail_event,mail_state}.dart`
- Test: `test/mail/mail_bloc_test.dart` (расширить)

- [ ] **Step 1: Entity**

```dart
class MailFolderEntity extends Equatable {
  final String path;
  final String role; // inbox|sent|drafts|junk|trash|custom
  final String name;
  final int total;
  final int unseen;
  const MailFolderEntity({required this.path, required this.role, required this.name, required this.total, required this.unseen});
  factory MailFolderEntity.fromJson(Map<String, dynamic> j) => MailFolderEntity(
    path: j['path'] as String, role: j['role'] as String, name: j['name'] as String,
    total: (j['total'] ?? 0) as int, unseen: (j['unseen'] ?? 0) as int);
  @override
  List<Object?> get props => [path, role, name, total, unseen];
}
```

- [ ] **Step 2: Datasource — новые методы + folder-параметры**

`getFolders()`, `createFolder(name)`, `deleteFolder(path)`, `moveMessage(uid, {fromFolder, toFolder})`, `saveDraft({to, subject, text, replaceUid})`, `getUnreadCount()`; в `getMessages/getMessage/downloadAttachment/setSeen/deleteMessage` добавить необязательный `String folder = 'INBOX'` → query-параметр. Прокинуть через IMailRepository и impl (1:1).

- [ ] **Step 3: Bloc — события/стейт**

В `MailState` добавить: `List<MailFolderEntity> folders`, `String currentFolder` (default `'INBOX'`), `int unread`. События: `MailFoldersRequested`, `MailFolderSelected(path)` (сбрасывает items+cursor, грузит страницу выбранной папки), `MailMessageMoved(uid, toFolder)`, `MailFolderCreated(name)`, `MailFolderDeleted(path)`. `MailInboxRequested` дополнительно дергает `getFolders()` и кладёт `unread` (inbox.unseen). bloc_test: выбор папки меняет `currentFolder` и перезагружает items; move убирает письмо из списка.

- [ ] **Step 4: `flutter test test/mail` зелёный; commit**

## Задача 6: Flutter — UI папок, черновики, бейдж

**Files:**
- Modify: `lib/features/mail/presentation/screens/mail_inbox_screen.dart` (папки: горизонтальный chip-selector под AppBar ИЛИ Drawer — выбрать chip-selector, он проще и виден сразу; кнопка «+» в конце списка chips → диалог создания папки; long-press на custom-chip → удалить)
- Modify: `lib/features/mail/presentation/screens/mail_detail_screen.dart` (иконка «переместить в папку» в AppBar → bottom sheet со списком папок; передавать `folder` во все вызовы)
- Modify: `lib/features/mail/presentation/screens/mail_compose_screen.dart` (при закрытии с непустым телом — диалог «Сохранить черновик?» → `saveDraft`; открытие из Drafts: prefill + `replaceUid`)
- Modify: `lib/features/assistant/presentation/screens/assistant_screen.dart:1506-1512` (`badge: mailUnread` — значение из лёгкого запроса `GET /mail/unread-count` при построении орбиты, кэш 60с в MailRepository, 0 при 404/ошибке)
- Modify: `lib/l10n/app_en.arb` + `app_ru.arb`: `mailFolders`, `mailFolderInbox` («Входящие»), `mailFolderSent` («Отправленные»), `mailFolderDrafts` («Черновики»), `mailFolderJunk` («Спам»), `mailFolderTrash` («Корзина»), `mailNewFolder`, `mailDeleteFolder`, `mailMoveTo`, `mailSaveDraft`, `mailDraftSaved` (en+ru)

- [ ] **Step 1: chip-selector папок** (role → локализованное имя, custom → path; badge unseen на chip)
- [ ] **Step 2: move из detail-экрана** (bottom sheet, исключить текущую папку)
- [ ] **Step 3: черновики в compose** (диалог при pop, prefill при открытии из Drafts)
- [ ] **Step 4: бейдж на планете Mail**
- [ ] **Step 5: `flutter analyze lib/features/mail` + `flutter test` зелёные; commit**

## Задача 7: Гейт и раскатка

- [ ] **Step 1:** Backend DEV задеплоен (Задача 4), `npm run test:mail` 37+ зелёных
- [ ] **Step 2:** Локальная сборка dev-APK, ручная проверка на эмуляторе: папки видны, Sent пополняется, черновик сохраняется/открывается, delete → Корзина, бейдж на орбите
- [ ] **Step 3:** Версия 1.1.20+219: bump pubspec, `src/app-releases.ts` + `app.controller.ts` defaults, merge dev→main обоих репо
- [ ] **Step 4:** Конвейер как в 1.1.19: TEST backend (только build+restart — env уже есть) → TEST APK → test:mail:prod (`MAIL_LP_PREFIX=inttest-t`) → PROD rolling → talerid APK на do-build → обе ноды + env-bump → iOS оба флейвора + TestFlight notes (без эмодзи!) → `/app/version` на всех трёх

---

## Self-Review

- Spec coverage: папки ✓ (З.1), Входящие/Отправленные/Спам/Черновики/Корзина ✓ (роли LIST/STATUS), свои папки ✓ (create/delete), Sent-копия ✓ (З.3), черновики ✓ (З.3+З.6), перемещение ✓ (З.2), удаление в Корзину ✓ (З.2), бейдж непрочитанных ✓ (З.3+З.6), e2e ✓ (З.4).
- Типы согласованы: `role` строки едины backend↔Flutter; `folder` query-параметр везде опционален с default INBOX.
- Известный риск: `client.append` в imapflow возвращает `{uid}` только при UIDPLUS (Dovecot поддерживает) — фолбэк `uid: null` обработан в saveDraft.
