# Чат комнаты: картинки — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** В чат комнаты можно прислать картинку — из веб-комнаты, из приложения и ручкой снаружи (Linkeon), — и она видна всем участникам прямо в переписке.

**Architecture:** В пакете `chat_message` появляется поле `image: {url, thumbUrl, width, height}` рядом с `text`; старые клиенты покажут подпись и проигнорируют картинку. Файл всегда наш: ручка `POST /voice/rooms/:roomName/chat/image` принимает либо `multipart` с файлом, либо `{"url"}` — тогда сервер скачивает картинку сам через SSRF-намордник и кладёт в S3. Превью и загрузку переиспользуем из мессенджера (`ThumbnailService`, `FileStorageService`, `isInlineSafeMime`).

**Tech Stack:** NestJS + multer + sharp + axios (бэкенд), ванильный JS (`public/room.html`), Flutter (`image_picker`, `cached_network_image` — оба уже в `pubspec.yaml`).

**Спека:** `docs/superpowers/specs/2026-09-07-room-chat-links-images-read-api-design.md`, раздел «Картинки».

**Порядок относительно других планов:** только **после** `2026-09-07-room-chat-server-transport.md` — этот план опирается на `RoomChatBufferService`, `roomActor` в guard'е и на то, что клиенты уже шлют чат через бэкенд.

---

## Структура файлов

**Бэкенд (`taler_id`):**
- Создать `src/common/safe-remote-fetch.ts` — намордник от SSRF: проверка адреса и скачивание с потолком размера. Отдельный модуль, потому что это единственное место, где сервер ходит наружу по чужому URL, и правило должно быть проверяемо само по себе.
- Создать `src/common/safe-remote-fetch.spec.ts`.
- Создать `src/voice/room-chat-image.service.ts` — превращение файла или URL в `{url, thumbUrl, width, height}`.
- Создать `src/voice/room-chat-image.service.spec.ts`.
- Изменить `src/voice/room-chat-buffer.service.ts` — необязательное поле `image` в записи.
- Изменить `src/voice/voice.service.ts` — общая публикация для текста и картинки.
- Изменить `src/voice/voice.controller.ts` — ручка загрузки.
- Изменить `src/voice/voice.module.ts` — провайдеры.
- Изменить `public/room.html` — отрисовка картинки, скрепка, вставка из буфера.

**Мобилка/десктоп (`taler_id_mobile`):**
- Изменить `lib/features/voice/presentation/controllers/room_chat_controller.dart` — картинка в сообщении.
- Изменить `lib/features/voice/domain/room_chat_history.dart` — картинка в истории.
- Изменить `lib/features/voice/data/room_chat_api.dart` — отправка файла.
- Изменить `lib/features/voice/presentation/widgets/room_chat_panel.dart` — превью в пузыре, кнопка выбора файла, просмотр во весь экран.

**Тесты (`taler_id_tests`):**
- Изменить `room_chat_test.ts` — загрузка картинки и её появление в ленте.

---

## Task 1: Намордник от SSRF

**Files:**
- Create: `src/common/safe-remote-fetch.ts`
- Test: `src/common/safe-remote-fetch.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/common/safe-remote-fetch.spec.ts`:

```ts
import { isPrivateAddress, fetchRemoteImage } from './safe-remote-fetch';

describe('isPrivateAddress', () => {
  it.each([
    '127.0.0.1',
    '10.0.0.1',
    '172.16.5.4',
    '192.168.1.1',
    '169.254.169.254', // облачные метаданные — главная цель SSRF
    '0.0.0.0',
    '100.64.0.1', // CGNAT
    '::1',
    'fd00::1',
    'fe80::1',
  ])('%s — приватный', (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '161.35.199.107', '2606:4700::1111'])(
    '%s — публичный',
    (ip) => {
      expect(isPrivateAddress(ip)).toBe(false);
    },
  );
});

describe('fetchRemoteImage', () => {
  const publicLookup = jest.fn(async () => [{ address: '8.8.8.8' }] as any);

  it('отказывает на не-http схеме, никуда не ходя', async () => {
    const request = jest.fn();
    await expect(
      fetchRemoteImage('file:///etc/passwd', { request, lookup: publicLookup }),
    ).rejects.toThrow(/scheme/i);
    expect(request).not.toHaveBeenCalled();
  });

  it('отказывает, если имя резолвится в приватный адрес', async () => {
    const request = jest.fn();
    const lookup = jest.fn(async () => [{ address: '169.254.169.254' }] as any);
    await expect(
      fetchRemoteImage('http://metadata.example/img.png', { request, lookup }),
    ).rejects.toThrow(/private/i);
    expect(request).not.toHaveBeenCalled();
  });

  it('отказывает, если хотя бы один из адресов приватный', async () => {
    const request = jest.fn();
    const lookup = jest.fn(async () => [
      { address: '8.8.8.8' },
      { address: '127.0.0.1' },
    ] as any);
    await expect(
      fetchRemoteImage('http://mixed.example/img.png', { request, lookup }),
    ).rejects.toThrow(/private/i);
    expect(request).not.toHaveBeenCalled();
  });

  it('скачивает картинку и отдаёт буфер с типом', async () => {
    const request = jest.fn(async () => ({
      status: 200,
      headers: { 'content-type': 'image/png' },
      data: Buffer.from([1, 2, 3]),
    }));
    const res = await fetchRemoteImage('https://cdn.example/img.png', {
      request,
      lookup: publicLookup,
    });
    expect(res.mime).toBe('image/png');
    expect(res.buffer).toHaveLength(3);
  });

  it('идёт по редиректу, проверяя новый адрес тем же правилом', async () => {
    const lookup = jest
      .fn()
      .mockResolvedValueOnce([{ address: '8.8.8.8' }])
      .mockResolvedValueOnce([{ address: '127.0.0.1' }]);
    const request = jest.fn(async () => ({
      status: 302,
      headers: { location: 'http://localhost/img.png' },
      data: Buffer.alloc(0),
    }));
    await expect(
      fetchRemoteImage('https://cdn.example/img.png', { request, lookup }),
    ).rejects.toThrow(/private/i);
  });

  it('сдаётся после трёх редиректов', async () => {
    const request = jest.fn(async () => ({
      status: 302,
      headers: { location: 'https://cdn.example/next' },
      data: Buffer.alloc(0),
    }));
    await expect(
      fetchRemoteImage('https://cdn.example/img.png', {
        request,
        lookup: publicLookup,
      }),
    ).rejects.toThrow(/redirect/i);
  });

  it('отказывает на не-картинке', async () => {
    const request = jest.fn(async () => ({
      status: 200,
      headers: { 'content-type': 'text/html' },
      data: Buffer.from('<html>'),
    }));
    await expect(
      fetchRemoteImage('https://cdn.example/page', {
        request,
        lookup: publicLookup,
      }),
    ).rejects.toThrow(/not an image/i);
  });

  it('отказывает, если ответ больше потолка', async () => {
    const request = jest.fn(async () => ({
      status: 200,
      headers: { 'content-type': 'image/png' },
      data: Buffer.alloc(11 * 1024 * 1024),
    }));
    await expect(
      fetchRemoteImage('https://cdn.example/big.png', {
        request,
        lookup: publicLookup,
      }),
    ).rejects.toThrow(/too large/i);
  });

  it('отказывает на статусе ошибки', async () => {
    const request = jest.fn(async () => ({
      status: 404,
      headers: {},
      data: Buffer.alloc(0),
    }));
    await expect(
      fetchRemoteImage('https://cdn.example/gone.png', {
        request,
        lookup: publicLookup,
      }),
    ).rejects.toThrow(/404/);
  });
});
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/common/safe-remote-fetch.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Написать модуль**

Создать `src/common/safe-remote-fetch.ts`:

```ts
import axios from 'axios';
import * as dns from 'dns';
import { BadRequestException } from '@nestjs/common';

/** Потолок скачиваемого — тот же, что у загрузки файлом. */
export const MAX_REMOTE_IMAGE_BYTES = 10 * 1024 * 1024;
const MAX_REDIRECTS = 3;

/**
 * Адреса, на которые серверу ходить нельзя: свои интерфейсы, внутренняя сеть
 * и облачные метаданные (`169.254.169.254` — обычная цель SSRF: оттуда
 * достают ключи инстанса).
 */
export function isPrivateAddress(ip: string): boolean {
  const addr = ip.toLowerCase();

  if (addr.includes(':')) {
    if (addr === '::' || addr === '::1') return true;
    // Уникальные локальные (fc00::/7) и link-local (fe80::/10).
    if (addr.startsWith('fc') || addr.startsWith('fd')) return true;
    if (addr.startsWith('fe8') || addr.startsWith('fe9')) return true;
    if (addr.startsWith('fea') || addr.startsWith('feb')) return true;
    // IPv4, завёрнутый в IPv6.
    const mapped = addr.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateAddress(mapped[1]);
    return false;
  }

  const octets = addr.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o))) return true;
  const [a, b] = octets;

  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast и выше
  return false;
}

export interface RemoteFetchDeps {
  request?: (url: string) => Promise<{
    status: number;
    headers: Record<string, any>;
    data: Buffer;
  }>;
  lookup?: (hostname: string) => Promise<{ address: string }[]>;
}

const defaultLookup = async (hostname: string) =>
  dns.promises.lookup(hostname, { all: true });

const defaultRequest = async (url: string) => {
  const res = await axios.get(url, {
    responseType: 'arraybuffer',
    // Редиректы разбираем сами: иначе проверка адреса обходится первым же
    // Location на localhost.
    maxRedirects: 0,
    validateStatus: () => true,
    timeout: 10000,
    maxContentLength: MAX_REMOTE_IMAGE_BYTES,
  });
  return {
    status: res.status,
    headers: res.headers as Record<string, any>,
    data: Buffer.from(res.data),
  };
};

/**
 * Скачивает картинку по чужому URL.
 *
 * Единственное место, где бэкенд ходит наружу по адресу, который назвал
 * клиент, поэтому проверки здесь не «на всякий случай»: без них ручка
 * загрузки превращается в сканер внутренней сети и читалку облачных
 * метаданных.
 */
export async function fetchRemoteImage(
  rawUrl: string,
  deps: RemoteFetchDeps = {},
): Promise<{ buffer: Buffer; mime: string }> {
  const request = deps.request ?? defaultRequest;
  const lookup = deps.lookup ?? defaultLookup;

  let url = rawUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new BadRequestException('image url is malformed');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new BadRequestException('image url scheme must be http or https');
    }

    const addresses = await lookup(parsed.hostname);
    if (!addresses.length || addresses.some((a) => isPrivateAddress(a.address))) {
      throw new BadRequestException('image url resolves to a private address');
    }

    const res = await request(url);

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers['location'];
      if (typeof location !== 'string' || !location) {
        throw new BadRequestException(`image url returned ${res.status}`);
      }
      if (hop === MAX_REDIRECTS) {
        throw new BadRequestException('image url has too many redirects');
      }
      url = new URL(location, url).toString();
      continue;
    }

    if (res.status !== 200) {
      throw new BadRequestException(`image url returned ${res.status}`);
    }

    const mime = String(res.headers['content-type'] ?? '')
      .split(';')[0]
      .trim()
      .toLowerCase();
    if (!mime.startsWith('image/')) {
      throw new BadRequestException('image url is not an image');
    }
    if (res.data.length > MAX_REMOTE_IMAGE_BYTES) {
      throw new BadRequestException('image is too large');
    }
    return { buffer: res.data, mime };
  }

  throw new BadRequestException('image url has too many redirects');
}
```

- [ ] **Step 4: Запустить тест и убедиться, что он проходит**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/common/safe-remote-fetch.spec.ts`
Expected: PASS, 23 проверки (`it.each` разворачивается в отдельные).

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/common/safe-remote-fetch.ts src/common/safe-remote-fetch.spec.ts
git commit -m "feat(common): намордник от SSRF для скачивания по чужому URL"
```

---

## Task 2: Картинка в S3

**Files:**
- Create: `src/voice/room-chat-image.service.ts`
- Test: `src/voice/room-chat-image.service.spec.ts`
- Modify: `src/voice/voice.module.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/voice/room-chat-image.service.spec.ts`:

```ts
import { BadRequestException } from '@nestjs/common';
import * as sharp from 'sharp';
import { RoomChatImageService } from './room-chat-image.service';

/** Настоящий PNG 4×2 — sharp должен уметь прочитать из него размеры. */
const png = async () =>
  sharp({
    create: {
      width: 4,
      height: 2,
      channels: 3,
      background: { r: 0, g: 0, b: 0 },
    },
  })
    .png()
    .toBuffer();

describe('RoomChatImageService', () => {
  let storage: { upload: jest.Mock; getPublicUrl: jest.Mock };
  let thumbs: { generateImageThumbnails: jest.Mock };
  let service: RoomChatImageService;

  beforeEach(() => {
    storage = {
      upload: jest.fn().mockResolvedValue(undefined),
      getPublicUrl: jest.fn((key: string) => `https://s3.example/${key}`),
    };
    thumbs = {
      generateImageThumbnails: jest
        .fn()
        .mockResolvedValue({ medium: Buffer.from([9, 9]) }),
    };
    service = new RoomChatImageService(storage as any, thumbs as any);
  });

  it('кладёт оригинал и превью, отдаёт ссылки и размеры', async () => {
    const res = await service.store(await png(), 'image/png');

    expect(res.width).toBe(4);
    expect(res.height).toBe(2);
    expect(res.url).toMatch(/^https:\/\/s3\.example\/files\//);
    expect(res.thumbUrl).toMatch(/^https:\/\/s3\.example\/thumbs\//);
    expect(storage.upload).toHaveBeenCalledTimes(2);
  });

  it('без превью отдаёт ссылку на оригинал вместо thumbUrl', async () => {
    thumbs.generateImageThumbnails.mockResolvedValue({});
    const res = await service.store(await png(), 'image/png');
    expect(res.thumbUrl).toBe(res.url);
  });

  it('отказывает на svg — он умеет исполнять скрипт', async () => {
    await expect(
      service.store(Buffer.from('<svg/>'), 'image/svg+xml'),
    ).rejects.toThrow(BadRequestException);
    expect(storage.upload).not.toHaveBeenCalled();
  });

  it('отказывает на не-картинке', async () => {
    await expect(
      service.store(Buffer.from('%PDF-1.4'), 'application/pdf'),
    ).rejects.toThrow(BadRequestException);
  });

  it('отказывает, если содержимое не открывается как картинка', async () => {
    // Тип обещает png, а внутри мусор — доверять заголовку нельзя.
    await expect(
      service.store(Buffer.from('не картинка'), 'image/png'),
    ).rejects.toThrow(BadRequestException);
    expect(storage.upload).not.toHaveBeenCalled();
  });

  it('отказывает на файле больше потолка', async () => {
    await expect(
      service.store(Buffer.alloc(11 * 1024 * 1024), 'image/png'),
    ).rejects.toThrow(BadRequestException);
  });
});
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/room-chat-image.service.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Написать сервис**

Создать `src/voice/room-chat-image.service.ts`:

```ts
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import sharp = require('sharp');
import { v4 as uuidv4 } from 'uuid';
import { FileStorageService } from '../common/file-storage.service';
import { ThumbnailService } from '../common/thumbnail.service';
import { isInlineSafeMime } from '../common/safe-mime';

/** Картинка так, как она уезжает в пакете чата. */
export interface RoomChatImage {
  url: string;
  thumbUrl: string;
  width: number;
  height: number;
}

export const MAX_ROOM_CHAT_IMAGE_BYTES = 10 * 1024 * 1024;

/**
 * Приводит присланную картинку к виду, пригодному для чата комнаты: проверяет,
 * кладёт в S3 и делает превью.
 *
 * Ключи те же, что у мессенджера (`files/`, `thumbs/`), — не ради красоты:
 * `isAllowedDownloadKey` пускает на выдачу только известные префиксы, и новый
 * префикс пришлось бы заводить и там.
 */
@Injectable()
export class RoomChatImageService {
  private readonly log = new Logger(RoomChatImageService.name);

  constructor(
    private readonly storage: FileStorageService,
    private readonly thumbnails: ThumbnailService,
  ) {}

  async store(buffer: Buffer, mime: string): Promise<RoomChatImage> {
    if (buffer.length > MAX_ROOM_CHAT_IMAGE_BYTES) {
      throw new BadRequestException('image is too large');
    }
    const type = String(mime ?? '').split(';')[0].trim().toLowerCase();
    // isInlineSafeMime заодно отсекает image/svg+xml: он умеет исполнять
    // скрипт в браузере, а картинка из чата показывается всем в комнате.
    if (!type.startsWith('image/') || !isInlineSafeMime(type)) {
      throw new BadRequestException('unsupported image type');
    }

    let width = 0;
    let height = 0;
    try {
      const meta = await sharp(buffer).metadata();
      width = meta.width ?? 0;
      height = meta.height ?? 0;
    } catch {
      // Заголовку верить нельзя: тип может обещать png, а внутри что угодно.
      throw new BadRequestException('image could not be read');
    }
    if (!width || !height) {
      throw new BadRequestException('image could not be read');
    }

    const ext = type === 'image/jpeg' ? '.jpg' : `.${type.slice('image/'.length)}`;
    const key = `files/${uuidv4()}${ext}`;
    await this.storage.upload(key, buffer, type);
    const url = this.storage.getPublicUrl(key);

    let thumbUrl = url;
    try {
      const thumbs = await this.thumbnails.generateImageThumbnails(buffer);
      if (thumbs.medium) {
        const thumbKey = `thumbs/${uuidv4()}_m.webp`;
        await this.storage.upload(thumbKey, thumbs.medium, 'image/webp');
        thumbUrl = this.storage.getPublicUrl(thumbKey);
      }
    } catch (e) {
      // Без превью картинка всё равно показывается — просто тяжелее.
      this.log.warn(`не удалось сделать превью для ${key}: ${e}`);
    }

    return { url, thumbUrl, width, height };
  }
}
```

- [ ] **Step 4: Запустить тест и убедиться, что он проходит**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/room-chat-image.service.spec.ts`
Expected: PASS, 6 тестов.

- [ ] **Step 5: Зарегистрировать провайдеры**

В `src/voice/voice.module.ts`:

```ts
import { ThumbnailService } from '../common/thumbnail.service';
import { RoomChatImageService } from './room-chat-image.service';

// в providers:
  providers: [
    VoiceService,
    FileStorageService,
    RoomChatBufferService,
    ThumbnailService,
    RoomChatImageService,
  ],
```

- [ ] **Step 6: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/room-chat-image.service.ts src/voice/room-chat-image.service.spec.ts src/voice/voice.module.ts
git commit -m "feat(voice): картинка чата комнаты в S3 с превью"
```

---

## Task 3: Картинка в пакете и в ленте

**Files:**
- Modify: `src/voice/room-chat-buffer.service.ts`
- Modify: `src/voice/voice.service.ts`
- Test: `src/voice/voice.service.chat.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Дописать в `src/voice/voice.service.chat.spec.ts`:

```ts
  const image = {
    url: 'https://s3.example/files/a.png',
    thumbUrl: 'https://s3.example/thumbs/a_m.webp',
    width: 4,
    height: 2,
  };

  it('картинка уезжает в пакете рядом с подписью', async () => {
    await service.sendRoomChatImage('call-42', image, 'вот схема', 'Linkeon');

    const packet = decode(euSendData);
    expect(packet.type).toBe('chat_message');
    expect(packet.image).toEqual(image);
    expect(packet.text).toBe('вот схема');
  });

  it('картинка без подписи допустима', async () => {
    await service.sendRoomChatImage('call-42', image, '', 'Linkeon');
    expect(decode(euSendData).text).toBe('');
    expect(decode(euSendData).image).toEqual(image);
  });

  it('картинка тоже попадает в ленту', async () => {
    await service.sendRoomChatImage('call-42', image, '', 'Linkeon');
    expect(buffer.append.mock.calls[0][1].image).toEqual(image);
  });

  it('подпись к картинке длиннее 500 символов не принимается', async () => {
    await expect(
      service.sendRoomChatImage('call-42', image, 'x'.repeat(501), 'Linkeon'),
    ).rejects.toThrow(BadRequestException);
    expect(euSendData).not.toHaveBeenCalled();
  });
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice/voice.service.chat.spec.ts`
Expected: FAIL — `service.sendRoomChatImage is not a function`.

- [ ] **Step 3: Реализовать**

В `src/voice/room-chat-buffer.service.ts` дополнить запись:

```ts
import { RoomChatImage } from './room-chat-image.service';

export interface RoomChatEntry {
  msgId: string;
  text: string;
  name: string;
  ts: number;
  seq: number;
  /** Есть, если сообщение — картинка. Тогда `text` может быть пустым. */
  image?: RoomChatImage;
}
```

В `src/voice/voice.service.ts` вынести общий путь публикации и добавить второй вход. Заменить тело `sendRoomChatMessage` на вызов общего метода и дописать рядом:

```ts
  async sendRoomChatMessage(
    roomName: string,
    text: string,
    name: string,
    actor?: string,
  ): Promise<{ ts: number; seq: number; msgId: string }> {
    const trimmed = typeof text === 'string' ? text.trim() : '';
    if (!trimmed) throw new BadRequestException('text is empty');
    return this.publishRoomChat(roomName, trimmed, name, undefined, actor);
  }

  /** Картинка с необязательной подписью. Пустой текст здесь допустим:
   *  непустым должно быть либо одно, либо другое. */
  async sendRoomChatImage(
    roomName: string,
    image: RoomChatImage,
    text: string,
    name: string,
    actor?: string,
  ): Promise<{ ts: number; seq: number; msgId: string }> {
    const caption = typeof text === 'string' ? text.trim() : '';
    return this.publishRoomChat(roomName, caption, name, image, actor);
  }

  private async publishRoomChat(
    roomName: string,
    text: string,
    name: string,
    image: RoomChatImage | undefined,
    actor?: string,
  ): Promise<{ ts: number; seq: number; msgId: string }> {
    if (text.length > 500) {
      throw new BadRequestException('text is longer than 500 characters');
    }
    const who =
      (typeof name === 'string' ? name.trim() : '').slice(0, 64) || 'Taler ID';

    if (actor && (await this.chatBuffer.hitRateLimit(roomName, actor))) {
      throw new HttpException(
        'too many chat messages, slow down',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const stored = await this.chatBuffer.append(roomName, {
      msgId: `server_${uuidv4()}`,
      text,
      name: who,
      ts: Date.now(),
      ...(image ? { image } : {}),
    });

    const packet = { type: 'chat_message', ...stored };

    try {
      await this.sfuFor(roomName).client.sendData(
        roomName,
        new TextEncoder().encode(JSON.stringify(packet)),
        DataPacket_Kind.RELIABLE,
        {},
      );
    } catch (e) {
      await this.chatBuffer.remove(roomName, stored);
      console.error(`Failed to send chat message to room ${roomName}:`, e);
      throw e;
    }

    return { ts: stored.ts, seq: stored.seq, msgId: stored.msgId };
  }
```

Дописать импорт `RoomChatImage` из `./room-chat-image.service`.

- [ ] **Step 4: Запустить тесты и убедиться, что они проходят**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npx jest src/voice`
Expected: PASS — прежние проверки текста и четыре новые про картинку.

- [ ] **Step 5: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/room-chat-buffer.service.ts src/voice/voice.service.ts src/voice/voice.service.chat.spec.ts
git commit -m "feat(voice): картинка в пакете и ленте чата комнаты"
```

---

## Task 4: Ручка загрузки

**Files:**
- Modify: `src/voice/voice.controller.ts`

- [ ] **Step 1: Дописать ручку**

Добавить рядом с `readRoomChat`:

```ts
  // Картинка в чат: файлом из UI или ссылкой от внешнего ассистента. Файл в
  // любом случае кладётся к нам — клиенты не должны ходить на чужой хост.
  @Post('rooms/:roomName/chat/image')
  @UseGuards(RoomAccessGuard)
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: MAX_ROOM_CHAT_IMAGE_BYTES },
    }),
  )
  async sendRoomChatImage(
    @Param('roomName') roomName: string,
    @UploadedFile() file: Express.Multer.File | undefined,
    @Body() body: { url?: string; text?: string; name?: string },
    @Req() req: any,
  ) {
    let buffer: Buffer;
    let mime: string;

    if (file) {
      buffer = file.buffer;
      mime = file.mimetype;
    } else if (typeof body?.url === 'string' && body.url.trim()) {
      const fetched = await fetchRemoteImage(body.url.trim());
      buffer = fetched.buffer;
      mime = fetched.mime;
    } else {
      throw new BadRequestException('either file or url is required');
    }

    const image = await this.chatImages.store(buffer, mime);
    return this.service.sendRoomChatImage(
      roomName,
      image,
      body?.text ?? '',
      body?.name ?? '',
      req.roomActor,
    );
  }
```

Дописать в шапку файла импорты и инъекцию (проверив, чего уже нет):

```ts
import { UploadedFile, UseInterceptors, BadRequestException } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import {
  RoomChatImageService,
  MAX_ROOM_CHAT_IMAGE_BYTES,
} from './room-chat-image.service';
import { fetchRemoteImage } from '../common/safe-remote-fetch';
```

и в конструктор контроллера — `private readonly chatImages: RoomChatImageService,`.

- [ ] **Step 2: Собрать**

Run: `cd ~/Downloads/taler_id/.worktrees/room-chat-api && npm run build && npx jest src/voice`
Expected: сборка проходит, тесты зелёные.

- [ ] **Step 3: Проверить на живом DEV**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
```

Затем, взяв `$LK` и `$RN` из проверки в плане транспорта:

```bash
B=https://staging.id.taler.tirol
# файлом
curl -s -X POST "$B/voice/rooms/$RN/chat/image" -H "Authorization: Bearer $LK" \
  -F file=@/Users/dmitry/Downloads/1.jpeg -F 'text=вот схема'
# ссылкой
curl -s -X POST "$B/voice/rooms/$RN/chat/image" -H "Authorization: Bearer $LK" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://talerid.io/favicon.png","text":"по ссылке"}'
# намордник
curl -s -X POST "$B/voice/rooms/$RN/chat/image" -H "Authorization: Bearer $LK" \
  -H 'Content-Type: application/json' -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
curl -s "$B/voice/rooms/$RN/chat" -H "Authorization: Bearer $LK"
```

Expected: первые два — `{"ts":…,"seq":…,"msgId":…}`; третий — 400 `private address`; лента содержит оба сообщения с полем `image`.

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add src/voice/voice.controller.ts
git commit -m "feat(voice): POST /voice/rooms/:roomName/chat/image"
```

---

## Task 5: Картинка в веб-комнате

**Files:**
- Modify: `public/room.html`

- [ ] **Step 1: Показывать картинку в пузыре**

В обработчике `chat_message` (строка ~1243) передать картинку дальше:

```js
            if (msg.type === 'chat_message') {
              // Участника может не быть: сервер публикует через
              // RoomServiceClient.sendData от своего имени, без отправителя.
              const who = participant ? getDisplayName(participant) : '';
              appendChatMessage(msg.name || who || 'Taler ID', msg.text, msg.ts || Date.now(), false, false, msg.image);
            }
```

В `appendChatMessage` добавить шестой параметр и отрисовку:

```js
    function appendChatMessage(name, text, ts, own, silent, image) {
```

и перед вставкой текста:

```js
      if (image && image.url) {
        const img = document.createElement('img');
        img.src = image.thumbUrl || image.url;
        img.alt = '';
        img.loading = 'lazy';
        img.style.maxWidth = '100%';
        img.style.borderRadius = '10px';
        img.style.cursor = 'pointer';
        img.style.display = 'block';
        // Пропорции известны заранее — резервируем место, чтобы лента не
        // прыгала, пока картинка грузится.
        if (image.width && image.height) img.style.aspectRatio = `${image.width} / ${image.height}`;
        img.onclick = () => window.open(image.url, '_blank', 'noopener,noreferrer');
        div.appendChild(img);
      }
      if (text) {
        div.appendChild(roomChatTextNode(text));
      }
```

(если план про ссылки ещё не выполнен, вместо `roomChatTextNode(text)` оставить прежние две строки с `textContent`).

В `loadChatHistory` передать картинку так же: `appendChatMessage(m.name, m.text, m.ts, false, true, m.image)`.

- [ ] **Step 2: Добавить отправку файлом**

Рядом с полем ввода чата (там же, где кнопка отправки) добавить кнопку и скрытый `input`:

```html
        <input type="file" id="chat-file" accept="image/*" style="display:none">
        <button class="chat-attach" onclick="document.getElementById('chat-file').click()" title="Картинка">📎</button>
```

и рядом с `sendChatMessage` — обработчики:

```js
    /** Отправка картинки: файлом из диалога или вставкой из буфера обмена. */
    async function sendChatImage(file) {
      if (!room || !file) return;
      const form = new FormData();
      form.append('file', file);
      form.append('name', getDisplayName(room.localParticipant));
      const caption = document.getElementById('chat-input').value.trim();
      if (caption) form.append('text', caption);
      try {
        const res = await fetch(`${API_BASE}/voice/rooms/${room.name}/chat/image`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${lkToken}` },
          body: form,
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        document.getElementById('chat-input').value = '';
        // Своё эхо не рисуем: пакет от сервера придёт всем, включая нас, и
        // нарисует картинку сам — размеры и ссылку знает только он.
      } catch (e) {
        showNotification('Картинка не отправлена', 'error');
      }
    }

    document.getElementById('chat-file').addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      e.target.value = '';
      if (file) sendChatImage(file);
    });

    document.getElementById('chat-input').addEventListener('paste', (e) => {
      const item = Array.from(e.clipboardData?.items || [])
        .find((i) => i.type.startsWith('image/'));
      if (!item) return;
      e.preventDefault();
      sendChatImage(item.getAsFile());
    });
```

⚠️ Обработчики вешаются на элементы по `id` — код должен исполняться после того, как разметка чата попала в документ. Если скрипт идёт до неё, перенести навешивание в ту же функцию инициализации, где настраивается кнопка отправки.

- [ ] **Step 3: Проверить руками**

Открыть комнату в двух вкладках: отправить картинку кнопкой из первой, вставить скриншот из буфера во второй.
Expected: обе картинки появляются в обеих вкладках по одному разу, нажатие открывает полный размер в новой вкладке, подпись из поля ввода уезжает вместе с картинкой.

- [ ] **Step 4: Коммит**

```bash
cd ~/Downloads/taler_id/.worktrees/room-chat-api
git add public/room.html
git commit -m "feat(room): картинки в чате веб-комнаты"
```

---

## Task 6: Картинка в приложении

**Files:**
- Modify: `lib/features/voice/presentation/controllers/room_chat_controller.dart`
- Modify: `lib/features/voice/domain/room_chat_history.dart`
- Modify: `lib/features/voice/data/room_chat_api.dart`
- Modify: `lib/features/voice/presentation/widgets/room_chat_panel.dart`
- Test: `test/voice/room_chat_controller_test.dart`

- [ ] **Step 1: Написать падающий тест**

Дописать в `test/voice/room_chat_controller_test.dart`:

```dart
    test('пакет с картинкой разбирается', () {
      final c = RoomChatController();
      final ok = c.handlePacket({
        'type': 'chat_message',
        'text': 'вот схема',
        'name': 'Linkeon',
        'ts': 1000,
        'image': {
          'url': 'https://s3.example/files/a.png',
          'thumbUrl': 'https://s3.example/thumbs/a_m.webp',
          'width': 4,
          'height': 2,
        },
      }, fallbackName: '—');

      expect(ok, isTrue);
      final m = c.messages.single;
      expect(m.image?.url, 'https://s3.example/files/a.png');
      expect(m.image?.thumbUrl, 'https://s3.example/thumbs/a_m.webp');
      expect(m.image?.aspectRatio, 2.0);
    });

    test('картинка без подписи принимается, хотя текст пуст', () {
      final c = RoomChatController();
      final ok = c.handlePacket({
        'type': 'chat_message',
        'text': '',
        'name': 'Linkeon',
        'ts': 1000,
        'image': {'url': 'https://s3.example/files/a.png'},
      }, fallbackName: '—');

      expect(ok, isTrue);
      expect(c.messages.single.text, '');
    });

    test('пустое сообщение без картинки по-прежнему отбрасывается', () {
      final c = RoomChatController();
      expect(
        c.handlePacket({
          'type': 'chat_message',
          'text': '  ',
          'name': 'Linkeon',
          'ts': 1000,
        }, fallbackName: '—'),
        isFalse,
      );
    });

    test('битое поле image не роняет разбор — сообщение остаётся текстовым', () {
      final c = RoomChatController();
      final ok = c.handlePacket({
        'type': 'chat_message',
        'text': 'текст',
        'name': 'Linkeon',
        'ts': 1000,
        'image': 'не объект',
      }, fallbackName: '—');

      expect(ok, isTrue);
      expect(c.messages.single.image, isNull);
    });
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/voice/room_chat_controller_test.dart`
Expected: FAIL — у `RoomChatMessage` нет поля `image`.

- [ ] **Step 3: Реализовать модель и разбор**

В `room_chat_controller.dart` добавить перед `RoomChatMessage`:

```dart
/// Картинка в сообщении чата комнаты.
@immutable
class RoomChatImage {
  final String url;
  final String thumbUrl;
  final int width;
  final int height;

  const RoomChatImage({
    required this.url,
    required this.thumbUrl,
    required this.width,
    required this.height,
  });

  /// Отношение сторон для места под картинку. `null`, если сервер размеров не
  /// прислал — тогда лента слегка дёрнется при загрузке, но не сломается.
  double? get aspectRatio =>
      (width > 0 && height > 0) ? width / height : null;

  /// Разбор устойчив к типам по той же причине, что и весь пакет: данные
  /// приходят из `jsonDecode`, и любое поле может оказаться не той природы.
  static RoomChatImage? tryParse(Object? raw) {
    if (raw is! Map) return null;
    final url = raw['url'];
    if (url is! String || url.isEmpty) return null;
    final thumb = raw['thumbUrl'];
    return RoomChatImage(
      url: url,
      thumbUrl: thumb is String && thumb.isNotEmpty ? thumb : url,
      width: raw['width'] is int ? raw['width'] as int : 0,
      height: raw['height'] is int ? raw['height'] as int : 0,
    );
  }
}
```

Добавить поле в `RoomChatMessage`:

```dart
  final RoomChatImage? image;
```

и в его конструктор — `this.image,` (необязательный именованный).

Заменить проверку пустоты в `handlePacket`:

```dart
    final rawText = msg['text'];
    final text = rawText is String ? rawText.trim() : '';
    final image = RoomChatImage.tryParse(msg['image']);
    // Сообщение имеет смысл, если есть хоть что-то одно: подпись к картинке
    // может быть пустой.
    if (text.isEmpty && image == null) return false;
```

и передать `image: image` в создаваемый `RoomChatMessage`.

В `addOwn` ничего не меняем: своя картинка эхом не рисуется — её нарисует пакет от сервера, только он знает ссылку и размеры.

В `room_chat_history.dart` в разборе истории заменить проверку и добавить картинку:

```dart
      final text = item['text'] is String ? (item['text'] as String).trim() : '';
      final image = RoomChatImage.tryParse(item['image']);
      if (text.isEmpty && image == null) continue;
```

и `image: image` в создаваемое сообщение.

- [ ] **Step 4: Запустить тесты и убедиться, что они проходят**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test test/voice/ test/features/voice/`
Expected: PASS.

- [ ] **Step 5: Дописать отправку в клиент ручек**

В `room_chat_api.dart` добавить метод:

```dart
  /// Отправка картинки файлом. Ответ тот же, что у текста; эхо не рисуем —
  /// пакет от сервера придёт всем, включая нас, и принесёт ссылку и размеры.
  Future<RoomChatSendResult> sendImage({
    required String roomName,
    required String lkToken,
    required String filePath,
    required String name,
    String? text,
  }) async {
    final form = FormData.fromMap({
      'file': await MultipartFile.fromFile(filePath),
      'name': name,
      if (text != null && text.isNotEmpty) 'text': text,
    });
    final res = await _dio.post<dynamic>(
      '/voice/rooms/$roomName/chat/image',
      data: form,
      options: _auth(lkToken),
    );
    final data = Map<String, dynamic>.from(res.data as Map);
    return RoomChatSendResult(
      msgId: data['msgId'] is String ? data['msgId'] as String : '',
      seq: data['seq'] is int ? data['seq'] as int : 0,
      ts: data['ts'] is int
          ? data['ts'] as int
          : DateTime.now().millisecondsSinceEpoch,
    );
  }
```

- [ ] **Step 6: Показать картинку в пузыре**

В `room_chat_panel.dart` дописать импорты:

```dart
import 'package:cached_network_image/cached_network_image.dart';
```

и в `_bubble` перед телом сообщения:

```dart
            if (m.image != null) _imagePreview(context, m.image!),
```

Добавить в класс:

```dart
  /// Превью картинки. Тянем `thumbUrl` — оригинал открывается только по
  /// нажатию, иначе лента звонка вытянет мегабайты на мобильном интернете.
  Widget _imagePreview(BuildContext context, RoomChatImage image) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: GestureDetector(
        onTap: () => showDialog<void>(
          context: context,
          builder: (_) => Dialog(
            backgroundColor: Colors.black,
            insetPadding: EdgeInsets.zero,
            child: Stack(
              children: [
                InteractiveViewer(
                  child: Center(
                    child: CachedNetworkImage(imageUrl: image.url),
                  ),
                ),
                Positioned(
                  top: 8,
                  right: 8,
                  child: IconButton(
                    icon: const Icon(Icons.close, color: Colors.white),
                    onPressed: () => Navigator.of(context).pop(),
                  ),
                ),
              ],
            ),
          ),
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(10),
          child: AspectRatio(
            aspectRatio: image.aspectRatio ?? 4 / 3,
            child: CachedNetworkImage(
              imageUrl: image.thumbUrl,
              fit: BoxFit.cover,
              // Картинка может не открыться (файл убрали, сеть отвалилась) —
              // показываем заглушку, а не пустоту непонятного назначения.
              errorWidget: (_, __, ___) =>
                  const Icon(Icons.broken_image_outlined, size: 32),
            ),
          ),
        ),
      ),
    );
  }
```

Пустую подпись не рисовать — обернуть тело сообщения:

```dart
            if (m.text.isNotEmpty) _messageText(m.text, textColor, palette),
```

(если план про ссылки не выполнен — тем же условием обернуть прежний `Text`).

- [ ] **Step 7: Добавить кнопку выбора картинки**

В строку ввода панели, слева от поля, добавить:

```dart
                IconButton(
                  tooltip: l10n.voiceChatAttachImage,
                  icon: const Icon(Icons.image_outlined),
                  onPressed: widget.onSendImage == null ? null : _pickImage,
                ),
```

Завести в панели необязательный колбэк `final Future<void> Function(String path, String? caption)? onSendImage;` и метод:

```dart
  Future<void> _pickImage() async {
    final picked = await ImagePicker().pickImage(
      source: ImageSource.gallery,
      // Крупные снимки с камеры упираются в потолок ручки в 10 МБ, а в чате
      // звонка всё равно смотрят с телефона.
      maxWidth: 2048,
      maxHeight: 2048,
    );
    if (picked == null) return;
    // Текст из поля уезжает подписью к картинке — так же, как в вебе.
    final caption = _input.text.trim();
    _input.clear();
    await widget.onSendImage!(picked.path, caption.isEmpty ? null : caption);
  }
```

`_input` — существующий `TextEditingController` поля ввода панели. Импорт: `package:image_picker/image_picker.dart`.

Строку `voiceChatAttachImage` добавить в `lib/l10n/app_ru.arb` («Картинка») и `app_en.arb` («Image»), затем `flutter gen-l10n`.

- [ ] **Step 8: Подключить на экране звонка**

В `voice_call_screen.dart` в месте создания `RoomChatPanel` добавить:

```dart
                    onSendImage: (path, caption) async {
                      final token = _lkToken;
                      final roomName = _roomName;
                      if (token == null || roomName == null) return;
                      final me = _room?.localParticipant;
                      final myName = (me?.name.isNotEmpty ?? false)
                          ? me!.name
                          : ((me?.identity.isNotEmpty ?? false)
                              ? me!.identity
                              : AppLocalizations.of(context)!.voiceParticipant);
                      try {
                        await sl<RoomChatApi>().sendImage(
                          roomName: roomName,
                          lkToken: token,
                          filePath: path,
                          name: myName,
                          text: caption,
                        );
                      } catch (e) {
                        debugPrint('[VoiceCall] room chat image failed: $e');
                      }
                    },
```

- [ ] **Step 9: Прогнать тесты и анализатор**

Run: `cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api && flutter test && flutter analyze lib/features/voice/`
Expected: PASS; новых замечаний по тронутым файлам нет.

- [ ] **Step 10: Коммит**

```bash
cd ~/Downloads/taler_id_mobile/.worktrees/room-chat-api
git add lib/features/voice/ lib/l10n/ test/voice/
git commit -m "feat(voice): картинки в чате комнаты на телефоне и десктопе"
```

---

## Task 7: E2E на картинки

**Files:**
- Modify: `~/Downloads/taler_id_tests/room_chat_test.ts`

- [ ] **Step 1: Дописать проверки**

Перед блоком `finally` добавить:

```ts
    // 1×1 PNG — минимальная настоящая картинка.
    const pngBytes = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
      'base64',
    );
    const form = new FormData();
    form.append('file', new Blob([pngBytes], { type: 'image/png' }), 'dot.png');
    form.append('text', 'вот схема');
    form.append('name', 'Linkeon');

    const uploaded = await http.post(`/voice/rooms/${roomName}/chat/image`, form, auth(lkToken));
    check('13. загрузка картинки файлом → 200/201',
      uploaded.status === 200 || uploaded.status === 201, uploaded.data);

    const withImage = await http.get(`/voice/rooms/${roomName}/chat`, auth(lkToken));
    const last = withImage.data?.messages?.[withImage.data.messages.length - 1];
    check('13b. картинка попала в ленту с подписью и размерами',
      typeof last?.image?.url === 'string' &&
      typeof last?.image?.thumbUrl === 'string' &&
      last?.image?.width === 1 &&
      last?.image?.height === 1 &&
      last?.text === 'вот схема', last);

    const imageRes = await axios.get(last.image.url, { responseType: 'arraybuffer', validateStatus: () => true });
    check('13c. картинка доступна по отданной ссылке', imageRes.status === 200, imageRes.status);

    const metadata = await http.post(`/voice/rooms/${roomName}/chat/image`,
      { url: 'http://169.254.169.254/latest/meta-data/' }, auth(lkToken));
    check('14. ссылка на приватный адрес → 400', metadata.status === 400, metadata.data);

    const notImage = await http.post(`/voice/rooms/${roomName}/chat/image`,
      { url: 'https://talerid.io/' }, auth(lkToken));
    check('15. ссылка не на картинку → 400', notImage.status === 400, notImage.data);

    const nothing = await http.post(`/voice/rooms/${roomName}/chat/image`, {}, auth(lkToken));
    check('16. ни файла, ни ссылки → 400', nothing.status === 400, nothing.data);
```

- [ ] **Step 2: Прогнать**

Run: `cd ~/Downloads/taler_id_tests && npm run test:room-chat`
Expected: все проверки зелёные, включая новые 13–16.

- [ ] **Step 3: Коммит**

```bash
cd ~/Downloads/taler_id_tests
git add room_chat_test.ts
git commit -m "test: картинки в чате комнаты — загрузка, лента, намордник"
```

⚠️ В этом репозитории лежат чужие правки — `git add -A` не делать.

---

## Task 8: Раскатка

**Files:** нет — деплой и проверка.

- [ ] **Step 1: Проверить связку руками**

Веб + телефон в одной комнате: картинка из веба видна на телефоне и наоборот; нажатие открывает полный размер; вошедший позже видит картинку в истории.

- [ ] **Step 2: Отдать Linkeon описание ручек**

Передать: `POST /voice/rooms/:roomName/chat` (текст), `POST /voice/rooms/:roomName/chat/image` (файл или `{"url"}`), `GET /voice/rooms/:roomName/chat?since=` (чтение), авторизация room-scoped LiveKit-токеном из `POST /voice/rooms/public/:code/join`, потолки: 500 символов текста, 10 МБ картинки, 10 сообщений за 10 секунд.

- [ ] **Step 3: Выкатить на TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id'
cd ~/Downloads/taler_id_tests && npm run test:room-chat:prod
```

- [ ] **Step 4: PROD — только по явной команде**

```bash
ssh do-app-1 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id && sleep 5 && curl -s -o /dev/null -w "health:%{http_code}\n" http://localhost:3000/health'
# дождаться health:200, затем то же на do-app-2
cd ~/Downloads/taler_id_tests && npm run test:room-chat:talerid
```
