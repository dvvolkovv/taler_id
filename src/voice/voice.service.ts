import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  HttpException,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import {
  AccessToken,
  RoomServiceClient,
  DataPacket_Kind,
} from 'livekit-server-sdk';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { makeParticipantIdentity } from '../common/participant-identity';
import { PrismaService } from '../prisma/prisma.service';

import { FileStorageService } from '../common/file-storage.service';
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';
import { LedgerService } from '../billing/services/ledger.service';
import { PricingService } from '../billing/services/pricing.service';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';
import {
  RoomChatBufferService,
  RoomChatEntry,
  RoomChatPage,
} from './room-chat-buffer.service';

const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';
import { LK_API_KEY, LK_API_SECRET } from '../common/livekit-credentials';
const LK_WS_URL = process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
// Region-routed second SFU: CIS calls run on the Selectel SFU (box1), EU calls
// on the DO media SFU. Both share the LiveKit API key, so a token is valid on
// either — only the connect (ws) URL differs. Defaults fall back to the EU SFU.
const LK_HOST_RU = process.env.LIVEKIT_HOST_RU || LK_HOST;
const LK_WS_URL_RU = process.env.LIVEKIT_WS_URL_RU || LK_WS_URL;
const AI_AGENT_URL = process.env.AI_AGENT_URL || 'http://localhost:3100';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://id.taler.tirol';

/** Формат допустимого клиентского id сообщения чата: непустая строка не
 *  длиннее 64 символов из латиницы/цифр/подчёркивания/дефиса. */
const CLIENT_MSG_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * true, если `clientMsgId` проходит формат — единственная проверка формата
 * в одном месте, чтобы `buildChatMsgId` (пространство имён msgId) и пакет
 * data-канала (эхо `clientMsgId`, см. `sendRoomChatMessage`) не могли молча
 * разойтись в том, что считают «годным». `actor` сюда не входит: у него
 * своя проверка на стороне каждого вызывающего (пространство имён строить
 * не из чего без actor, а вот сама строка годна или нет — от actor не
 * зависит).
 */
function isValidClientMsgId(clientMsgId: unknown): clientMsgId is string {
  return (
    typeof clientMsgId === 'string' && CLIENT_MSG_ID_PATTERN.test(clientMsgId)
  );
}

/**
 * Строит итоговый `msgId` сообщения чата комнаты — устойчивый к подделке
 * пространства имён, не более того.
 *
 * Если у отправителя (`actor`) есть валидный `clientMsgId`, итоговый id
 * строится в пространстве имён, производном от самого отправителя:
 * `c_<8 hex символов sha256(actor)>_<clientMsgId>`. Два разных отправителя
 * физически не могут произвести одинаковый итоговый id, даже сговорившись
 * на одном `clientMsgId`: подделать чужое пространство имён значило бы
 * найти прообраз sha256 чужого `actor`, что бессмысленно. Это защита от
 * коллизий/подделки, а не подпись и не секрет — `actor` в проде не тайна
 * (виден другим участникам комнаты через сам чат), и не нужно, чтобы был.
 *
 * ВАЖНО: этот `msgId` клиент предсказать не может — хеш от `actor` считает
 * сервер, и заранее (до ответа) клиенту взять его неоткуда. Поэтому для
 * распознавания собственного echo (разорвать гонку «эхо из data-канала
 * приходит раньше HTTP-ответа») используется НЕ этот `msgId`, а отдельное
 * поле `clientMsgId` в пакете data-канала — оно уходит эхом ровно тем
 * значением, что прислал клиент, без всякого пространства имён (см.
 * докстринг `sendRoomChatMessage`). Раньше здесь было написано, что клиент
 * узнаёт `msgId` заранее по этой самой namespaced-схеме — неверно: клиент
 * не обязан (и не должен) воспроизводить sha256(actor) на своей стороне
 * ради дедупликации.
 *
 * Негодный `clientMsgId` — не строка, пустая строка, длиннее 64 символов
 * или с символами вне `[A-Za-z0-9_-]` — не отклоняет запрос: он молча
 * заменяется серверным `server_<uuid>`, как если бы поля не было вовсе.
 * Клиент с кривым id должен получить работающий чат, а не 400.
 *
 * Без `actor` (`sendRoomChatMessage` вызывается и без него — например от
 * лица ассистента, см. её докстринг) `clientMsgId` игнорируется целиком:
 * пространство имён строить не из чего, а взять клиентский id как есть
 * означало бы открыть ту самую дыру с подделкой, которую всё это призвано
 * закрыть.
 *
 * Экспортирована (а не приватный метод класса) по тому же соображению, что
 * и `roomActorFactory` в `room-actor.decorator.ts`: логика с двумя разными
 * последствиями отказа (тихий фолбэк vs пространство имён) должна быть
 * проверяема тестом напрямую, без поднятия всего VoiceService.
 */
export function buildChatMsgId(
  actor: string | undefined,
  clientMsgId?: unknown,
): string {
  if (actor && isValidClientMsgId(clientMsgId)) {
    const namespace = crypto
      .createHash('sha256')
      .update(actor)
      .digest('hex')
      .slice(0, 8);
    return `c_${namespace}_${clientMsgId}`;
  }
  return `server_${uuidv4()}`;
}

@Injectable()
export class VoiceService {
  private readonly log = new Logger(VoiceService.name);
  private rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);
  private ruRooms = new RoomServiceClient(
    LK_HOST_RU,
    LK_API_KEY,
    LK_API_SECRET,
  );
  // I2 (Task 4b review): a separate pair of clients, used only by the
  // meeting-boundary check in clearChatIfNewMeeting. `livekit-server-sdk`'s
  // TwirpRpc defaults `requestTimeout` to 60s (`AbortSignal.timeout(timeout
  // * 1000)`) — fine for `rooms`/`ruRooms` above, which back `sendData` and
  // recording uploads, nothing a human is blocked waiting on. It is NOT
  // fine for a call sitting on the room-join critical path: a fast refusal
  // degrades gracefully (the `catch` in clearChatIfNewMeeting logs and
  // moves on in milliseconds), but a blackholed connection — packets going
  // nowhere, no RST — would hang every join for up to a minute, two for the
  // public-room paths where a similarly-unbounded `createRoom` runs first.
  // A 2s cap turns that into "briefly slow", not "looks hung". Deliberately
  // NOT applied to the shared `rooms`/`ruRooms` above — lowering their
  // timeout would make `sendData` and recording uploads fail under load or
  // latency that 2s was never meant to police.
  private participantsCheckRooms = new RoomServiceClient(
    LK_HOST,
    LK_API_KEY,
    LK_API_SECRET,
    { requestTimeout: 2 },
  );
  private participantsCheckRuRooms = new RoomServiceClient(
    LK_HOST_RU,
    LK_API_KEY,
    LK_API_SECRET,
    { requestTimeout: 2 },
  );

  /** Pick the SFU for a room by its name prefix. CIS rooms are named
   * `call-ru-…` and live on the Selectel SFU; everything else on the EU/DO SFU. */
  private sfuFor(roomName: string) {
    return roomName.startsWith('call-ru-')
      ? { client: this.ruRooms, wsUrl: LK_WS_URL_RU }
      : { client: this.rooms, wsUrl: LK_WS_URL };
  }

  /** Same room→SFU split as `sfuFor`, but for the short-timeout client pair
   * used only by the meeting-boundary check — see the fields' comment. */
  private participantsCheckClient(roomName: string) {
    return roomName.startsWith('call-ru-')
      ? this.participantsCheckRuRooms
      : this.participantsCheckRooms;
  }

  constructor(
    private readonly prisma: PrismaService,
    private readonly fileStorage: FileStorageService,
    private readonly gating: GatingService,
    private readonly metering: MeteringService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
    private readonly chatBuffer: RoomChatBufferService,
  ) {}

  async createRoom(
    initiatorId: string,
    withAi = false,
    userToken?: string,
    conversationId?: string,
    sessionId?: string,
    region?: string,
  ) {
    // CIS-развилка отключена 2026-07-25: RU-SFU нестабилен, DTLS-таймауты и
    // TURN-обходы всё равно не спасали Android-клиентов. Единый маршрут =
    // основной SFU (DO); CIS-клиенты должны пользоваться VPN.
    void region;
    const roomName = 'call-' + uuidv4();
    const sfu = this.sfuFor(roomName);
    await sfu.client.createRoom({
      name: roomName,
      emptyTimeout: 300,
      departureTimeout: 60,
      maxParticipants: 10,
    });
    const token = await this.makeToken(roomName, initiatorId, sessionId);
    try {
      await this.prisma.callLog.create({
        data: {
          roomName,
          initiatorId,
          participantIds: [initiatorId],
          withAi,
          conversationId,
        },
      });
    } catch (_) {}
    // NOTE: the old livekit-ai-agent (gpt-realtime-mini) no longer auto-joins
    // person-to-person calls. It's still available for explicit scenarios
    // via its HTTP endpoint, but nothing in the clients currently asks for it
    // — and letting it auto-join collides with the new ai-twin-agent fallback.
    console.log(
      `[createRoom] room=${roomName} initiator=${initiatorId} withAi=${withAi} sfu=${sfu.wsUrl} — auto-join suppressed`,
    );
    return { roomName, token, livekitWsUrl: sfu.wsUrl };
  }

  async joinRoom(roomName: string, userId: string, sessionId?: string) {
    // This used to add the caller to participantIds and hand out a token to
    // whoever asked, so any authenticated user who learned a room name could
    // walk into someone else's call — and writing themselves into the log made
    // them look like a legitimate participant afterwards.
    //
    // The invite flow is the source of truth instead: handleCallInvite() adds
    // each callee to participantIds only after the block and contact checks
    // pass, so membership there means "was invited". Public, temporary and
    // guest entry go through the /rooms/public/:code/join* routes, not here.
    const log = await this.prisma.callLog.findUnique({ where: { roomName } });
    const isPersonalRoomOwner = roomName.startsWith(
      `personal-${userId.substring(0, 8)}`,
    );
    if (!isPersonalRoomOwner && !log?.participantIds.includes(userId)) {
      throw new ForbiddenException('Not invited to this room');
    }

    await this.clearChatIfNewMeeting(roomName);
    return {
      token: await this.makeToken(roomName, userId, sessionId),
      livekitWsUrl: this.sfuFor(roomName).wsUrl,
    };
  }

  /**
   * Issues a LiveKit access token for a group voice call. Group calls live in
   * rooms named `group-${groupCallId}` so the LiveKit webhook handler (Task 15)
   * can route room events to GroupCallService by prefix. Mirrors the 1-on-1
   * `makeToken` shape (roomJoin + canPublish/canSubscribe) and adds
   * canPublishData for in-room signaling. Returns the WS URL alongside the
   * token so callers don't need to know the LiveKit endpoint.
   */
  async generateGroupCallToken(
    groupCallId: string,
    userId: string,
    sessionId?: string,
  ): Promise<{ token: string; livekitWsUrl: string }> {
    const roomName = `group-${groupCallId}`;
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: makeParticipantIdentity(userId, sessionId),
      ttl: 60 * 60 * 4, // 4 hours
    });
    at.addGrant({
      room: roomName,
      roomJoin: true,
      canPublish: true,
      canSubscribe: true,
      canPublishData: true,
    });
    const token = await at.toJwt();
    return {
      token,
      livekitWsUrl: LK_WS_URL,
    };
  }

  /**
   * Forcefully delete a LiveKit room (any active participants are evicted).
   * Used by group-call lifecycle (Task 7+) when ending a call so the room
   * doesn't sit around until LiveKit's `emptyTimeout` reaps it. Idempotent
   * from the caller's perspective: LiveKit returns success even if the room
   * is already gone, so callers don't need to check existence first.
   */
  async deleteRoom(roomName: string): Promise<void> {
    await this.sfuFor(roomName).client.deleteRoom(roomName);
  }

  /**
   * Force-disconnect a participant from a LiveKit room.
   *
   * Used by group-call host actions (Task 9 `kick`) to forcibly remove an
   * invitee. Mirrors `deleteRoom`: thin pass-through to the LiveKit
   * RoomServiceClient. The same direct call already exists in
   * `ai-twin.service.ts` — wrapping it here gives the group-call service
   * a clean injection seam for unit-testing without spying on LiveKit
   * internals.
   *
   * Best-effort from the caller's perspective: LiveKit returns success when
   * the participant is already gone, so callers don't need to pre-check
   * existence. If the LK server is transiently down, callers should swallow
   * the error and rely on their DB write (status=LEFT) as the source of
   * truth — the participant will be reaped by LiveKit's `departureTimeout`.
   */
  async removeParticipant(roomName: string, identity: string): Promise<void> {
    await this.rooms.removeParticipant(roomName, identity);
  }

  /**
   * Единственный путь сообщения в чат комнаты: и от людей, и от ассистента.
   * Сначала запись в ленту — иначе читать через API было бы нечего, — потом
   * рассылка в data-канал. Если рассылка не удалась, запись снимается: то,
   * чего никто не видел, не должно всплыть у открывшего историю. (Известный
   * не чинённый пограничный случай: если `sendData` отвалится по таймауту
   * ПОСЛЕ того, как LiveKit уже фактически доставил пакет всем, этот откат
   * всё равно случится — сообщение останется у всех на экранах, но исчезнет
   * из истории при следующей перезагрузке; расхождение серверное, клиент
   * здесь ведёт себя правильно.)
   *
   * `text` и `name` нормализуются здесь, а не в вызывающем коде: метод —
   * переиспользуемый шов (ручка, ассистент), и инвариант должен быть один
   * на всех. `name` в вебе рисуется как имя автора, поэтому режется по длине
   * и подменяется дефолтом, если пришёл пустым или не строкой.
   *
   * `actor` — необязательный идентификатор отправителя для потолка частоты
   * (`RoomChatBufferService.hitRateLimit`). Без него потолок не проверяется:
   * серверные вызовы (ассистент) не обязаны его передавать, а вот ручка для
   * гостя/участника — обязана. `actor` также попадает в саму запись ленты
   * (`RoomChatEntry.actor`) — так `RoomChatBufferService.read` может
   * посчитать `own` для того, кто её потом читает; наружу (ни в пакет
   * data-канала, ни в HTTP-ответ этого метода) actor не идёт — см. сборку
   * `packet` ниже, она собрана явным списком полей, а не спредом `stored`.
   *
   * `clientMsgId` — необязательный клиентский id сообщения. Валидность
   * решает одно условие на весь метод (`echoClientMsgId` ниже: `actor` есть
   * и `isValidClientMsgId(clientMsgId)`), и дальше три разных потребителя
   * читают её результат, а не пересчитывают:
   *  1. `buildChatMsgId` использует само (`actor`, `clientMsgId`) — так же,
   *     как и раньше, — чтобы построить итоговый `msgId` в пространстве
   *     имён отправителя (подделка бессмысленна, см. её докстринг). Иначе
   *     (невалидный формат, нет `actor`) — обычный `server_<uuid>`.
   *  2. `echoClientMsgId` попадает в саму запись ленты (`RoomChatEntry.
   *     clientMsgId`) — и оттуда, через `RoomChatBufferService.read`,
   *     наружу в GET как есть (не вырезается, в отличие от `actor`: это
   *     безобидная случайная строка от клиента, не идентификатор
   *     участника). Это единственное, что закрывает гонку «GET-ответ
   *     обгоняет echo»: пока летит первый GET, пользователь отправляет
   *     сообщение, сервер успевает дописать его в ленту раньше, чем придёт
   *     echo из data-канала — и без `clientMsgId` в GET-ответе клиенту
   *     нечем было сопоставить строку истории с уже отрисованным
   *     оптимистичным пузырём: `own` говорит «моё», но не говорит «ровно этот
   *     пузырь». Раньше поле уходило только в пакет и не в запись — тем же
   *     путём баг и воспроизводился.
   *  3. То же значение (`stored.clientMsgId`, а не отдельная проверка) идёт
   *     в `packet` ниже, эхом, ровно тем значением, что прислал клиент —
   *     это разрывает вторую гонку, «echo обгоняет HTTP-ответ»: `sendData`
   *     уходит в комнату ДО того, как резолвится этот HTTP-ответ (см.
   *     «пишет в ленту раньше, чем рассылает» — тот же порядок и для
   *     sendData относительно возврата из этого метода), так что клиент не
   *     может узнать namespaced `msgId` из ответа вовремя (и не должен —
   *     воспроизводить sha256(actor) на клиенте не нужно и не
   *     предполагается), а вот `clientMsgId` он и так знает, сам его
   *     сгенерировал, и просто сравнивает строки в пришедшем пакете со
   *     своим ещё не отрисованным значением.
   * Если условие не выполнено — ключа `clientMsgId` нет вовсе ни в записи
   * ленты, ни в GET, ни в `packet` (не `undefined`, не пустая строка):
   * лишнее поле и в приватной истории, и в протоколе, который видят все
   * участники комнаты, не бесплатно.
   *
   * Клиент SFU берётся через `sfuFor`, а не из `this.rooms` напрямую —
   * ради симметрии с `deleteRoom` и `joinRoom`. Сама CIS-развилка сейчас
   * не задействована: с 2026-07-25 `createRoom` всегда выдаёт `call-<uuid>`,
   * комнат `call-ru-…` никто не создаёт (см. `void region` в `createRoom`).
   * Одно и то же `roomName` обязано уйти и в `chatBuffer`, и в `sendData` —
   * лента и рассылка это разные комнаты по определению, если имена разойдутся.
   *
   * Бросает, если LiveKit недоступен. Ошибка не глотается намеренно:
   * ретраев у нас нет, и молчаливый успех означал бы, что вызывающий считает
   * сообщение доставленным, тогда как в комнате его никто не увидел.
   *
   * Отказ самого хранилища (Redis недоступен, а не «превышен потолок» —
   * это законный `HttpException`, а не отказ) на этапе `hitRateLimit`/
   * `append` превращается в `ServiceUnavailableException`: голый `Error`
   * снаружи ушёл бы через общий `HttpExceptionFilter` как безликий 500,
   * неотличимый от «ты прислал ерунду», и без единой строки в логе.
   */
  async sendRoomChatMessage(
    roomName: string,
    text: string,
    name: string,
    actor?: string,
    clientMsgId?: unknown,
  ): Promise<{ ts: number; seq: number; msgId: string }> {
    const trimmed = typeof text === 'string' ? text.trim() : '';
    if (!trimmed) throw new BadRequestException('text is empty');
    if (trimmed.length > 500) {
      throw new BadRequestException('text is longer than 500 characters');
    }
    const who =
      (typeof name === 'string' ? name.trim() : '').slice(0, 64) || 'Taler ID';

    // Единственное вычисление валидности clientMsgId на весь метод — источник
    // истины для записи ленты (ниже), а пакет и GET-ответ (через read())
    // берут его оттуда, а не проверяют заново. Раньше пакет пересчитывал то
    // же самое условие сам — из-за этого clientMsgId не попадал в саму
    // запись, и GET, догнавший echo из data-канала (пока летел первый GET,
    // пользователь успевал отправить сообщение — сервер дописывал его в
    // ленту раньше echo), не мог сообщить клиенту, какую строку истории он
    // уже отрисовал: own говорит «моё», но не говорит «ровно тот пузырь».
    const echoClientMsgId =
      actor && isValidClientMsgId(clientMsgId) ? clientMsgId : undefined;

    let stored: RoomChatEntry;
    try {
      if (actor && (await this.chatBuffer.hitRateLimit(roomName, actor))) {
        throw new HttpException(
          'too many chat messages, slow down',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
      const entry: Omit<RoomChatEntry, 'seq'> = {
        msgId: buildChatMsgId(actor, clientMsgId),
        text: trimmed,
        name: who,
        ts: Date.now(),
        actor,
      };
      // Ключ добавляется, только если условие выполнено, — не выставляется
      // в undefined при провале. Разница ощутима именно на этом сыром
      // объекте (до RPUSH/JSON.stringify внутри append(), который такой
      // ключ бы и сам молча съел): `key in entry` истинен и для `{clientMsgId:
      // undefined}`, поэтому неусловная запись `clientMsgId: echoClientMsgId`
      // не была бы отличима от «поля не было» на этом шаге — только позже,
      // после сериализации. Источник обязан быть точным сам по себе, а не
      // полагаться на то, что сериализация ниже подчистит за него.
      if (echoClientMsgId !== undefined) {
        entry.clientMsgId = echoClientMsgId;
      }
      stored = await this.chatBuffer.append(roomName, entry);
    } catch (e) {
      // 429 выше — законный, ожидаемый отказ: пробрасываем как есть. Всё
      // остальное здесь — отказ самого Redis (hitRateLimit тоже бросает,
      // а не только резолвит fail-open: fail-open у него только на уровне
      // одного повреждённого слота внутри УСПЕШНОЙ транзакции; если Redis
      // недоступен целиком, exec() отклоняется, и hitRateLimit падает
      // ровно как append).
      if (e instanceof HttpException) throw e;
      this.log.error(
        `хранилище ленты чата недоступно для комнаты ${roomName}: ${e}`,
      );
      throw new ServiceUnavailableException(
        'chat storage is unavailable, try again',
      );
    }

    // Явный список полей, а не `{ type: 'chat_message', ...stored }`: спред
    // разложил бы и `actor` — участники комнаты (включая гостей) не должны
    // получить идентификатор отправителя через data-канал (см. докстринг
    // RoomChatEntry.actor). Список полей дублирует форму RoomChatEntry
    // намеренно: новое чувствительное поле в записи ленты не должно суметь
    // просочиться в комнату молча, просто потому что кто-то расширил
    // `stored` спредом где-то ещё, — на этом месте расширение обязано быть
    // явным решением, а не побочным эффектом.
    const packet: {
      type: string;
      msgId: string;
      text: string;
      name: string;
      ts: number;
      seq: number;
      clientMsgId?: string;
    } = {
      type: 'chat_message',
      msgId: stored.msgId,
      text: stored.text,
      name: stored.name,
      ts: stored.ts,
      seq: stored.seq,
    };
    // clientMsgId — эхо клиентского id (докстринг метода, пункт 3) ровно тем
    // значением, что прислал клиент, а НЕ производный от него namespaced
    // msgId. Источник — уже сохранённая запись (`stored.clientMsgId`,
    // проставлена через `echoClientMsgId` выше), а не повторная проверка
    // `isValidClientMsgId` здесь: пакет, запись ленты и GET-ответ обязаны
    // сходиться в том, что считают «годным», а не полагаться на то, что две
    // независимые проверки одного и того же условия случайно не разойдутся.
    // Ключ добавляется, только если он есть в `stored`, — не выставляется в
    // undefined/'' и не через спред: лишнее поле в протоколе, который видят
    // все участники комнаты, не бесплатно.
    if (stored.clientMsgId !== undefined) {
      packet.clientMsgId = stored.clientMsgId;
    }

    try {
      await this.sfuFor(roomName).client.sendData(
        roomName,
        new TextEncoder().encode(JSON.stringify(packet)),
        DataPacket_Kind.RELIABLE,
        // SendDataOptions актуальной перегрузки sendData — без этого аргумента
        // вызов уходит в @deprecated-ветку с позиционным списком получателей.
        {},
      );
    } catch (e) {
      const removed = await this.chatBuffer.remove(roomName, stored);
      if (removed === 0) {
        // Ноль тут значит одно из двух: штатное вытеснение LTRIM'ом (500
        // сообщений успели прилететь между append и этим remove — обычное
        // дело под нагрузкой) — или что запись так и не попала в ленту,
        // хотя append() отрапортовал об успехе. Второе теперь перекрыто
        // проверкой слотов транзакции внутри append() (см. её комментарий),
        // но remove() смотрит только на своё единственное число и не может
        // доказать, какая из причин сработала, — поэтому предупреждаем при
        // любой, а не только когда уверены.
        this.log.warn(
          `chatBuffer.remove() вернул 0 сразу после append() для ${roomName} ` +
            `seq=${stored.seq} msgId=${stored.msgId}: рассылка отказала, откат ` +
            `не подтверждён`,
        );
      }
      // Сообщение уже снято из ленты (либо залогировано выше, если снять не
      // удалось) — эта строка единственный оставшийся след того, что
      // рассылка в комнату не задалась.
      this.log.error(
        `не удалось разослать сообщение чата в комнату ${roomName}: ${e}`,
      );
      throw e;
    }

    return { ts: stored.ts, seq: stored.seq, msgId: stored.msgId };
  }

  /**
   * Лента комнаты для клиента и внешнего ассистента. Явный тип возврата
   * не для красоты: это HTTP-контракт GET-ручки, и смена формы страницы
   * внутри буфера не должна молча поменять ответ API.
   *
   * `actor` — идентификатор запрашивающего (контроллер передаёт
   * `@RoomActor()`), нужен только чтобы `chatBuffer.read` посчитал `own` на
   * каждом сообщении; сам метод его больше никак не использует.
   */
  async readRoomChat(
    roomName: string,
    since?: number,
    actor?: string,
  ): Promise<RoomChatPage> {
    return this.chatBuffer.read(roomName, since, actor);
  }

  async endCallLog(roomName: string): Promise<void> {
    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName } });
      if (!log || log.endedAt) return;
      const endedAt = new Date();
      // durationSec = talk time (from answeredAt), or 0 if never answered
      const durationSec = log.answeredAt
        ? Math.round((endedAt.getTime() - log.answeredAt.getTime()) / 1000)
        : 0;
      await this.prisma.callLog.update({
        where: { roomName },
        data: { endedAt, durationSec },
      });
    } catch (_) {}
    try {
      const pub = await this.prisma.publicRoom.findFirst({
        where: { roomName },
      });
      if (pub && pub.type === 'temporary' && pub.isActive) {
        await this.prisma.publicRoom.update({
          where: { code: pub.code },
          data: { isActive: false },
        });
      }
    } catch (_) {}
  }

  async getCallHistory(userId: string, page = 0, limit = 50) {
    const logs = await this.prisma.callLog.findMany({
      where: { participantIds: { has: userId } },
      orderBy: { startedAt: 'desc' },
      skip: page * limit,
      take: limit,
      include: {
        meetingSummary: {
          select: { id: true, summary: true, recordingUrl: true },
        },
      },
    });
    const result = await Promise.all(
      logs.map(async (log) => {
        let otherIds = [...new Set(log.participantIds)].filter(
          (id: string) => id !== userId,
        );
        if (otherIds.length === 0 && log.conversationId) {
          const convParticipants =
            await this.prisma.conversationParticipant.findMany({
              where: {
                conversationId: log.conversationId,
                userId: { not: userId },
              },
              select: { userId: true },
            });
          otherIds = convParticipants.map((cp) => cp.userId);
        }
        // Query User (not Profile) so we can fall back to username when the
        // profile has no firstName/lastName — matches makeToken() below, which
        // already does fullName || username || userId. Without this fallback,
        // users like VKOVAL (username set, profile names empty) showed up as
        // raw UUIDs in call history while LiveKit identified them by username.
        const users = await this.prisma.user.findMany({
          where: { id: { in: otherIds } },
          select: {
            id: true,
            username: true,
            profile: {
              select: { firstName: true, lastName: true, avatarUrl: true },
            },
          },
        });
        const usersById = new Map(users.map((u) => [u.id, u]));
        const participants = otherIds.map((id) => {
          const u = usersById.get(id);
          const fullName =
            `${u?.profile?.firstName ?? ''} ${u?.profile?.lastName ?? ''}`.trim();
          return {
            userId: id,
            displayName: fullName || u?.username || id,
            avatarUrl: u?.profile?.avatarUrl ?? undefined,
          };
        });
        return {
          id: log.id,
          roomName: log.roomName,
          conversationId: log.conversationId,
          isOutgoing: log.initiatorId === userId,
          isMissed:
            !log.answeredAt &&
            log.endedAt != null &&
            log.initiatorId !== userId,
          startedAt: log.startedAt,
          endedAt: log.endedAt,
          durationSec: log.durationSec,
          withAi: log.withAi,
          aiTwinSummary: log.aiTwinSummary ?? null,
          aiTwinTranscript: log.aiTwinTranscript ?? null,
          meetingSummary: log.meetingSummary
            ? {
                id: log.meetingSummary.id,
                summary: log.meetingSummary.summary,
                recordingUrl: log.meetingSummary.recordingUrl,
              }
            : null,
          participants,
        };
      }),
    );
    return result;
  }

  /**
   * Called by the Python ai-twin-agent after a call session ends. Stores the
   * full transcript + GPT-generated summary on the CallLog so the owner of
   * the twin can see what was said while they were away.
   */
  async saveAiTwinCallData(
    roomName: string,
    transcript: unknown,
    summary: string,
  ): Promise<void> {
    try {
      await this.prisma.callLog.update({
        where: { roomName },
        data: {
          aiTwinTranscript: transcript as any,
          aiTwinSummary: summary,
        },
      });
      console.log(
        `[saveAiTwinCallData] saved transcript+summary for room=${roomName}`,
      );
    } catch (e) {
      console.warn(
        `[saveAiTwinCallData] failed for room=${roomName}:`,
        (e as Error).message,
      );
    }
  }

  async getCallDetail(callId: string, userId: string) {
    const log = await this.prisma.callLog.findUnique({
      where: { id: callId },
      include: { meetingSummary: true },
    });
    if (!log) throw new Error('Call not found');
    if (!log.participantIds.includes(userId)) throw new Error('Access denied');
    // Same User+Profile lookup as getCallHistory — fall back to username when
    // firstName/lastName are empty (matches makeToken behaviour).
    const users = await this.prisma.user.findMany({
      where: { id: { in: log.participantIds } },
      select: {
        id: true,
        username: true,
        profile: {
          select: { firstName: true, lastName: true, avatarUrl: true },
        },
      },
    });
    const usersById = new Map(users.map((u) => [u.id, u]));
    const participants = log.participantIds.map((id) => {
      const u = usersById.get(id);
      const fullName =
        `${u?.profile?.firstName ?? ''} ${u?.profile?.lastName ?? ''}`.trim();
      return {
        userId: id,
        displayName: fullName || u?.username || id,
        avatarUrl: u?.profile?.avatarUrl ?? undefined,
      };
    });
    return {
      id: log.id,
      roomName: log.roomName,
      conversationId: log.conversationId,
      isOutgoing: log.initiatorId === userId,
      startedAt: log.startedAt,
      endedAt: log.endedAt,
      durationSec: log.durationSec,
      withAi: log.withAi,
      aiTwinSummary: log.aiTwinSummary ?? null,
      aiTwinTranscript: log.aiTwinTranscript ?? null,
      participants,
      summary: log.meetingSummary
        ? {
            id: log.meetingSummary.id,
            summary: log.meetingSummary.summary,
            keyPoints: log.meetingSummary.keyPoints,
            actionItems: log.meetingSummary.actionItems,
            decisions: log.meetingSummary.decisions,
            transcript: log.meetingSummary.transcript,
            status: log.meetingSummary.status,
            recordingUrl: log.meetingSummary.recordingUrl,
          }
        : null,
    };
  }

  async createVoiceSession(userId: string) {
    if (!OPENAI_API_KEY)
      throw new Error('OPENAI_API_KEY not configured on server');

    // Billing pre-check: feature toggle + minReserve balance. Throws
    // FeatureDisabledException (→403) or InsufficientFundsException (→402),
    // mapped by BillingExceptionFilter on the controller.
    const billingSession = await this.gating.startSession(
      userId,
      FEATURE_KEYS.VOICE_ASSISTANT,
    );

    try {
      // GA Realtime API: ephemeral key is minted via /v1/realtime/client_secrets
      // (the old /v1/realtime/sessions endpoint was deprecated 2026-05-20).
      // Response shape changed: top-level { value, expires_at } instead of
      // { client_secret: { value } }.
      const response = await fetch(
        'https://api.openai.com/v1/realtime/client_secrets',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${OPENAI_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            session: {
              type: 'realtime',
              model: 'gpt-realtime-mini-2025-12-15',
              audio: {
                output: { voice: 'marin' },
              },
              instructions:
                'Ты — голосовой ассистент Taler ID. Помогай пользователям с их цифровой идентификацией, статусом KYC-верификации и данными профиля. Будь краток и полезен. Отвечай на русском языке. Ты можешь использовать инструменты для чтения или обновления профиля пользователя.',
            },
          }),
        },
      );
      if (!response.ok) {
        const err = await response.text();
        throw new Error(`OpenAI session error ${response.status}: ${err}`);
      }
      const data = (await response.json()) as any;
      return {
        clientSecret: data.value as string,
        billingSessionId: billingSession.id,
      };
    } catch (err) {
      // Roll back the billing session so we don't leak an 'active' AiSession
      // whose OpenAI counterpart never existed.
      await this.gating.endSession(billingSession.id, 'failed').catch(() => {});
      throw err;
    }
  }

  /**
   * Client-initiated close of a voice_assistant session. Reports the actual
   * duration (for final adjustment debit) and marks the AiSession completed.
   * Report failures are swallowed — MeteringService.tick (cron) has already
   * been draining the balance at ~1-minute granularity, so the final debit
   * is only an adjustment. Ending the session must always succeed.
   */
  async closeVoiceSession(
    userId: string,
    sessionId: string,
    durationSec: number,
  ): Promise<void> {
    const session = await this.prisma.aiSession.findUnique({
      where: { id: sessionId },
      select: { userId: true, status: true },
    });
    // Return 404 (not 403) to avoid revealing whether a sessionId exists.
    if (!session || session.userId !== userId) {
      throw new NotFoundException('session not found');
    }

    const safeDuration =
      Number.isFinite(durationSec) && durationSec > 0 ? durationSec : 0;
    const durationMin = safeDuration / 60;
    try {
      await this.metering.reportUsage(sessionId, durationMin, 'client');
    } catch {
      // Swallow report failure so session close always succeeds. Metering's cron
      // tick has already been draining at ~10-second granularity, so a swallowed
      // final report means at most ~10 seconds of under-billing drift, not lost billing.
    }
    await this.gating.endSession(sessionId, 'completed');
  }

  // ─── Public rooms ───

  async getOrCreatePersonalRoom(userId: string) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException('Profile not found');

    if (profile.personalRoomCode) {
      const existing = await this.prisma.publicRoom.findUnique({
        where: { code: profile.personalRoomCode },
      });
      if (existing) {
        return {
          code: existing.code,
          link: `${BASE_URL}/room/${existing.code}`,
        };
      }
    }

    const code = crypto.randomBytes(4).toString('hex');
    const roomName = 'personal-' + userId.slice(0, 8) + '-' + code;
    await this.prisma.publicRoom.create({
      data: { code, roomName, creatorId: userId, title: '', type: 'permanent' },
    });
    await this.prisma.profile.update({
      where: { userId },
      data: { personalRoomCode: code },
    });
    return { code, link: `${BASE_URL}/room/${code}` };
  }

  /**
   * Нормализует пароль встречи перед хешированием — единая точка для
   * `createTemporaryRoom`/`createPublicRoom`, а не логика, продублированная
   * в каждом из них по отдельности (два места легко разойтись молча).
   *
   * Нормализация была односторонней: пароль задают три клиента (веб,
   * мобилка, чужие вызовы API), и раньше инвариант «в хеше нет краевых
   * пробелов» держали только те из них, что сами обрезают ввод перед
   * отправкой (веб — при входе, мобилка — при создании), а бэкенд при
   * СОЗДАНИИ хешировал ровно то, что пришло. Пароль `" секрет "`, заданный
   * через API напрямую, был затем НАВСЕГДА недостижим из веба: веб на входе
   * шлёт `секрет`, сверка с хешем пробела не сходится, и человек видит
   * «Неверный пароль» — сообщение, которое в этом случае врёт (пароль
   * верный, просто клиент и сервер по-разному считали его границы).
   * Обрезка вынесена на сторону создания (а не входа) намеренно: клиентов
   * три, а точка создания хеша — одна, и инвариант должен держаться для
   * всех, а не только для тех, кто не забыл обрезать перед отправкой.
   *
   * Обрезка — до хеширования, а не после: хешируется то же значение, что
   * потом сверяется при входе (входные пути уже получают обрезанный текст
   * от клиентов, которые обрезают сами).
   *
   * Пустое после обрезки — то же самое, что «пароль не задан», а не пароль
   * из одних пробелов: такой пароль на входе стал бы пустой строкой (веб
   * обрезает перед отправкой и вовсе не шлёт пустое поле) и был бы НЕВВОДИМ
   * ничем, при этом бэкенд без этой нормализации считал бы его настоящим и
   * хешировал. Возвращаем `undefined`, а не пустую строку: вызывающие
   * методы не хешируют `undefined` (та же ветка `normalizedPassword ? ... :
   * null`, что была раньше с сырым `password`), и `passwordHash` не
   * попадает в запись вовсе — гостю или чужому не нужно вводить пароль от
   * комнаты, где владелец фактически пароль не задал.
   *
   * 64 символа — тот же предел, что `maxlength="64"` в веб-форме и в
   * диалоге мобилки; раньше он жил только в клиентах, и пароль длиннее
   * можно было создать через API и потом не набрать в браузере ничем.
   * Проверка — после обрезки, не до: считается длина того, что реально
   * придётся набрать при входе, а не число отправленных байт (иначе пароль
   * из пробелов и шести значащих символов отклонялся бы напрасно).
   */
  private normalizeRoomPassword(password?: string): string | undefined {
    if (!password) return undefined;
    const trimmed = password.trim();
    if (!trimmed) return undefined;
    if (trimmed.length > 64) {
      throw new BadRequestException('password is longer than 64 characters');
    }
    return trimmed;
  }

  async createTemporaryRoom(userId: string, title?: string, password?: string) {
    const normalizedPassword = this.normalizeRoomPassword(password);
    const roomName = 'tmp-' + uuidv4();
    const code = crypto.randomBytes(4).toString('hex');
    await this.rooms.createRoom({
      name: roomName,
      emptyTimeout: 300,
      departureTimeout: 60,
      maxParticipants: 20,
    });
    const passwordHash = normalizedPassword
      ? await bcrypt.hash(normalizedPassword, 10)
      : null;
    await this.prisma.publicRoom.create({
      data: {
        code,
        roomName,
        creatorId: userId,
        title: title || '',
        type: 'temporary',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        ...(passwordHash ? { passwordHash } : {}),
      },
    });
    return { code, link: `${BASE_URL}/room/${code}` };
  }

  async deactivateTemporaryRoom(code: string, userId: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || room.type !== 'temporary')
      throw new NotFoundException('Room not found');
    if (room.creatorId !== userId) throw new NotFoundException('Not your room');
    await this.prisma.publicRoom.update({
      where: { code },
      data: { isActive: false },
    });
  }

  async createPublicRoom(userId?: string, title?: string, password?: string) {
    const normalizedPassword = this.normalizeRoomPassword(password);
    const roomName = 'pub-' + uuidv4();
    const code = crypto.randomBytes(4).toString('hex');
    await this.rooms.createRoom({
      name: roomName,
      emptyTimeout: 600,
      departureTimeout: 120,
      maxParticipants: 20,
    });
    const passwordHash = normalizedPassword
      ? await bcrypt.hash(normalizedPassword, 10)
      : null;
    await this.prisma.publicRoom.create({
      data: {
        code,
        roomName,
        creatorId: userId ?? null,
        title: title || '',
        ...(passwordHash ? { passwordHash } : {}),
      },
    });
    return { code, roomName, link: `${BASE_URL}/room/${code}` };
  }

  async getPublicRoom(code: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || !room.isActive) throw new NotFoundException('Room not found');

    let creatorName: string | null = null;
    let creatorAvatar: string | null = null;
    if (room.creatorId) {
      const profile = await this.prisma.profile.findUnique({
        where: { userId: room.creatorId },
      });
      if (profile) {
        creatorName =
          `${profile.firstName ?? ''} ${profile.lastName ?? ''}`.trim() || null;
        creatorAvatar = (profile as any).avatarUrl ?? null;
      }
    }

    return {
      code: room.code,
      title: room.title,
      roomName: room.roomName,
      isActive: room.isActive,
      requiresPassword: !!room.passwordHash,
      creatorName,
      creatorAvatar,
    };
  }

  async joinPublicRoom(code: string, guestName: string, password?: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || !room.isActive) throw new NotFoundException('Room not found');
    if (
      room.type === 'temporary' &&
      room.expiresAt &&
      new Date() > room.expiresAt
    ) {
      await this.prisma.publicRoom.update({
        where: { code },
        data: { isActive: false },
      });
      throw new NotFoundException('Room has expired');
    }
    if (room.passwordHash) {
      if (!password || !(await bcrypt.compare(password, room.passwordHash))) {
        throw new ForbiddenException('Invalid room password');
      }
    }
    try {
      const timeout = room.type === 'permanent' ? 600 : 300;
      await this.rooms.createRoom({
        name: room.roomName,
        emptyTimeout: timeout,
        departureTimeout: 120,
        maxParticipants: 20,
      });
    } catch (_) {}
    await this.clearChatIfNewMeeting(room.roomName);
    return {
      token: await this.makeGuestToken(room.roomName, guestName),
      roomName: room.roomName,
    };
  }

  async joinPublicRoomAuth(
    code: string,
    userId: string,
    password?: string,
    sessionId?: string,
  ) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || !room.isActive) throw new NotFoundException('Room not found');
    if (
      room.type === 'temporary' &&
      room.expiresAt &&
      new Date() > room.expiresAt
    ) {
      await this.prisma.publicRoom.update({
        where: { code },
        data: { isActive: false },
      });
      throw new NotFoundException('Room has expired');
    }
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
    try {
      const timeout = room.type === 'permanent' ? 600 : 300;
      await this.rooms.createRoom({
        name: room.roomName,
        emptyTimeout: timeout,
        departureTimeout: 120,
        maxParticipants: 20,
      });
    } catch (_) {}
    await this.clearChatIfNewMeeting(room.roomName);
    return {
      token: await this.makeToken(room.roomName, userId, sessionId),
      roomName: room.roomName,
    };
  }

  /**
   * Meeting-boundary heuristic for the room chat feed. LiveKit webhooks
   * (`room_finished`) aren't configured on any environment as of this
   * writing — DEV, TEST and DO-media configs all lack a `webhook` section —
   * so there's no clean "this meeting just ended" signal to clear the feed
   * on exit. The boundary is caught on entry instead: called from every
   * join path right before a token is handed out, it asks LiveKit who's
   * already in the room — through `participantsCheckClient`, a dedicated
   * short-timeout client pair, not `sfuFor`'s shared one; see that field's
   * comment for why a call sitting on the join critical path can't use the
   * SDK's 60s default.
   *
   * `listParticipants` on a room that doesn't exist yet resolves an empty
   * array rather than rejecting — confirmed against a live LiveKit instance
   * (2026-09-07: `listParticipants("no-such-room-…")` → `ok, participants =
   * []`), not assumed. So "nobody's here" and "room not created yet" are
   * the same successful, empty response, and both correctly mean "this join
   * starts a new meeting": whatever chat is left over from a previous
   * meeting under this room name gets cleared (`RoomChatBufferService.
   * clearFeed` — note it deliberately leaves the `seq` counter alone; see
   * its docstring for why, and for the horizon that reasoning stops holding
   * at).
   *
   * A *rejected* call is a different thing and is handled differently: it
   * means the LiveKit API itself is unreachable or erroring, which says
   * nothing about who's actually in the room — the "room doesn't exist yet"
   * case that a reject-means-clear rule would have been protecting against
   * is already covered by the empty-array behavior above, so there's no
   * scenario left where clearing-on-reject helps. Clearing on it anyway
   * would let a transient LiveKit outage wipe a live meeting's chat for a
   * reason that has nothing to do with whether the room is empty. So a
   * rejection does not clear — it's logged and the feed is left alone,
   * same "don't know, don't touch" policy as a `clearFeed` failure below.
   *
   * Not called from `createRoom`: that path always mints a fresh
   * `call-<uuid>` room name, so there is no previous meeting's chat to
   * inherit and the LiveKit round-trip would be pure overhead.
   *
   * Best-effort by construction on the clearing side — nothing here is
   * allowed to stop someone from joining. A person locked out because the
   * feed wouldn't clear is a far worse outcome than one meeting's chat
   * surviving into the next, so a `clearFeed` failure (Redis down) is
   * caught and logged, never thrown. Two people joining at the same moment
   * can both observe zero participants and both clear — accepted as
   * harmless. Not *quite* nothing-to-lose in the strictest sense: the
   * loser's `clearFeed` could in principle land after the winner has
   * already connected and sent the new meeting's first message, wiping
   * that instead of anything from the old one. The window for that is not
   * the sub-millisecond gap to Redis — it lasts until the winner has
   * actually connected to the SFU, since `listParticipants` only reports a
   * participant once their ICE handshake completes, so realistically a
   * couple of seconds after their token was minted. The cost is still just
   * one lost chat line, not a correctness break, so it's accepted rather
   * than synchronized against. `clearFeed` itself is safe to call more than
   * once regardless.
   */
  private async clearChatIfNewMeeting(roomName: string): Promise<void> {
    let participants;
    try {
      participants =
        await this.participantsCheckClient(roomName).listParticipants(roomName);
    } catch (e) {
      // API-авария — не то же самое, что пустая комната (см. докстринг):
      // не трогаем ленту вслепую, только предупреждаем.
      this.log.warn(
        `listParticipants(${roomName}) не отработал на входе в комнату — ` +
          `лента не тронута: ${e}`,
      );
      return;
    }
    if (participants.length > 0) return;

    try {
      await this.chatBuffer.clearFeed(roomName);
    } catch (e) {
      this.log.warn(
        `не удалось очистить ленту чата ${roomName} на входе в комнату: ${e}`,
      );
    }
  }

  private async makeGuestToken(room: string, displayName: string) {
    const identity = 'guest-' + crypto.randomBytes(4).toString('hex');
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity,
      name: displayName,
    });
    at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
    return await at.toJwt();
  }

  private async makeToken(room: string, userId: string, sessionId?: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { profile: { select: { firstName: true, lastName: true } } },
    });
    const fullName = user
      ? `${user.profile?.firstName ?? ''} ${user.profile?.lastName ?? ''}`.trim()
      : '';
    const displayName = fullName || user?.username || userId;
    // Device-unique identity so the same account on multiple devices doesn't
    // collide (DUPLICATE_IDENTITY). Display name still rides the token `name`.
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: makeParticipantIdentity(userId, sessionId),
      name: displayName,
    });
    at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
    return await at.toJwt();
  }

  // ─── E2EE ───

  async disableE2EE(roomName: string) {
    try {
      await this.rooms.updateRoomMetadata(
        roomName,
        JSON.stringify({ e2ee_disabled: true }),
      );
      return { ok: true };
    } catch (e) {
      console.error('Failed to update room metadata for E2EE disable:', e);
      return { ok: false, reason: (e as Error).message };
    }
  }

  // ─── Voice Translator ───

  async getTranslatorLanguages() {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/languages');
      return await res.json();
    } catch (e) {
      // Fallback if agent is unavailable
      return [
        { code: 'ru', name: 'Русский' },
        { code: 'en', name: 'English' },
        { code: 'de', name: 'Deutsch' },
        { code: 'it', name: 'Italiano' },
      ];
    }
  }

  async startTranslator(roomName: string) {
    // Disable E2EE first — translator needs unencrypted audio
    await this.disableE2EE(roomName);

    // Clear any leftover lang metadata from previous translator sessions
    try {
      const participants = await this.rooms.listParticipants(roomName);
      for (const p of participants) {
        if (
          p.identity === 'voice-translator' ||
          p.identity === 'ai-assistant' ||
          p.identity === 'meeting-recorder'
        )
          continue;
        try {
          const meta = p.metadata ? JSON.parse(p.metadata) : {};
          if (meta.lang) {
            // Remove lang/sourceLang so translator doesn't create unnecessary sessions
            delete meta.lang;
            delete meta.sourceLang;
            await this.rooms.updateParticipant(roomName, p.identity, {
              metadata:
                Object.keys(meta).length > 0 ? JSON.stringify(meta) : '',
            });
          }
        } catch (_) {}
      }
    } catch (_) {}

    try {
      const res = await fetch(AI_AGENT_URL + '/translator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      const data = (await res.json()) as any;
      return { status: data.status || 'started' };
    } catch (e) {
      console.error('Failed to start translator:', e);
      throw new Error('Translator service unavailable');
    }
  }

  async stopTranslator(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      const data = (await res.json()) as any;
      return { status: data.status || 'stopped' };
    } catch (e) {
      console.error('Failed to stop translator:', e);
      throw new Error('Translator service unavailable');
    }
  }

  async setTranslatorLang(
    roomName: string,
    userId: string,
    lang: string,
    sourceLang?: string,
  ) {
    // Also set LiveKit participant metadata so translator can read lang from existing participants
    try {
      await this.rooms.updateParticipant(roomName, userId, {
        metadata: JSON.stringify({ lang, sourceLang: sourceLang || lang }),
      });
    } catch (e) {
      console.warn(
        'Failed to update participant metadata:',
        (e as Error).message,
      );
    }
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/set-lang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          roomName,
          userId,
          lang,
          sourceLang: sourceLang || lang,
        }),
      });
      return await res.json();
    } catch (e) {
      return { ok: false, reason: 'Translator service unavailable' };
    }
  }

  async setTranslatorLangByIdentity(
    roomName: string,
    identity: string,
    lang: string,
  ) {
    // Same as setTranslatorLang but uses participant identity directly (for guests)
    try {
      await this.rooms.updateParticipant(roomName, identity, {
        metadata: JSON.stringify({ lang }),
      });
    } catch (e) {
      console.warn(
        'Failed to update participant metadata:',
        (e as Error).message,
      );
    }
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/set-lang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName, userId: identity, lang }),
      });
      return await res.json();
    } catch (e) {
      return { ok: false, reason: 'Translator service unavailable' };
    }
  }

  async getTranslatorStatus(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/status/' + roomName);
      return await res.json();
    } catch (e) {
      return { running: false };
    }
  }

  // Post-deploy smoke: proxies to livekit-ai-agent's /translator/selftest,
  // which opens a brief WS to OpenAI Realtime with the translator's exact
  // session.update shape. Returns { ok, reason, latencyMs }.
  async translatorSelftest() {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/selftest');
      return await res.json();
    } catch (e) {
      return { ok: false, reason: 'agent unreachable: ' + (e as Error).message };
    }
  }

  // ─── Meeting Recorder ───

  async startRecorder(roomName: string, withAi = true) {
    try {
      const res = await fetch(AI_AGENT_URL + '/record', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName, withAi }),
      });
      const data = (await res.json()) as any;
      return { status: data.status || 'started' };
    } catch (e) {
      console.error('Failed to start recorder:', e);
      throw new Error('Recorder service unavailable');
    }
  }

  async stopRecorder(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/stop-record', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      const data = (await res.json()) as any;
      return { status: data.status || 'stopping' };
    } catch (e) {
      console.error('Failed to stop recorder:', e);
      throw new Error('Recorder service unavailable');
    }
  }

  async getRecorderStatus(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/record-status/' + roomName);
      return await res.json();
    } catch (e) {
      return { recording: false };
    }
  }

  async saveMeetingSummary(data: {
    id?: string;
    roomName: string;
    transcript: string;
    summary: string;
    keyPoints: any;
    actionItems: any;
    decisions: any;
    participants: string[];
    participantIds?: string[];
    durationSec?: number;
    recordingUrl?: string;
    status?: string;
    participantTracks?: any;
  }) {
    // If id provided — update existing record (pending → done)
    if (data.id) {
      const updated = await this.prisma.meetingSummary.update({
        where: { id: data.id },
        data: {
          transcript: data.transcript,
          summary: data.summary,
          keyPoints: data.keyPoints,
          actionItems: data.actionItems,
          decisions: data.decisions,
          recordingUrl: data.recordingUrl ?? null,
          durationSec: data.durationSec ?? null,
          status: data.status ?? 'done',
          ...(data.participants && { participants: data.participants }),
          ...(data.participantIds &&
            data.participantIds.length > 0 && {
              participantIds: data.participantIds,
            }),
          ...(data.participantTracks && {
            participantTracks: data.participantTracks,
          }),
        },
      });
      return { id: updated.id };
    }

    let callLogId: string | null = null;
    try {
      const log = await this.prisma.callLog.findUnique({
        where: { roomName: data.roomName },
      });
      if (log) callLogId = log.id;
    } catch (_) {}

    const summary = await this.prisma.meetingSummary.create({
      data: {
        roomName: data.roomName,
        callLogId,
        transcript: data.transcript,
        summary: data.summary,
        keyPoints: data.keyPoints,
        actionItems: data.actionItems,
        decisions: data.decisions,
        participants: data.participants,
        participantIds: data.participantIds ?? [],
        durationSec: data.durationSec ?? null,
        recordingUrl: data.recordingUrl ?? null,
        status: data.status ?? 'done',
        ...(data.participantTracks && {
          participantTracks: data.participantTracks,
        }),
      },
    });
    return { id: summary.id };
  }

  async getMeetingSummaries(userId: string, page = 0, limit = 20) {
    const logs = await this.prisma.callLog.findMany({
      where: {
        participantIds: { has: userId },
        meetingSummary: { isNot: null },
      },
      orderBy: { startedAt: 'desc' },
      skip: page * limit,
      take: limit,
      include: { meetingSummary: true },
    });

    const publicSummaries = await this.prisma.meetingSummary.findMany({
      where: {
        callLogId: null,
        OR: [
          { participantIds: { has: userId } },
          { roomName: { startsWith: `personal-${userId.substring(0, 8)}` } },
        ],
      },
      orderBy: { createdAt: 'desc' },
      skip: page * limit,
      take: limit,
    });

    const fromLogs = logs
      .filter((l) => l.meetingSummary)
      .map((l) => ({
        id: l.meetingSummary!.id,
        roomName: l.roomName,
        summary: l.meetingSummary!.summary,
        participants: l.meetingSummary!.participants,
        durationSec: l.meetingSummary!.durationSec,
        actionItemsCount: Array.isArray(l.meetingSummary!.actionItems)
          ? (l.meetingSummary!.actionItems as any[]).length
          : 0,
        createdAt: l.meetingSummary!.createdAt,
        recordingUrl: l.meetingSummary!.recordingUrl,
        status: (l.meetingSummary as any).status ?? 'done',
      }));

    const fromPublic = publicSummaries.map((s) => ({
      id: s.id,
      roomName: s.roomName,
      summary: s.summary,
      participants: s.participants,
      durationSec: s.durationSec,
      actionItemsCount: Array.isArray(s.actionItems)
        ? (s.actionItems as any[]).length
        : 0,
      createdAt: s.createdAt,
      recordingUrl: s.recordingUrl,
      status: (s as any).status ?? 'done',
    }));

    return [...fromLogs, ...fromPublic].sort(
      (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
    );
  }

  async getMeetingRecordings(userId: string, page = 0, limit = 20) {
    const logs = await this.prisma.callLog.findMany({
      where: {
        participantIds: { has: userId },
        meetingSummary: { isNot: null },
      },
      orderBy: { startedAt: 'desc' },
      skip: page * limit,
      take: limit,
      include: { meetingSummary: true },
    });

    const publicSummaries = await this.prisma.meetingSummary.findMany({
      where: {
        callLogId: null,
        recordingUrl: { not: null },
        OR: [
          { participantIds: { has: userId } },
          { roomName: { startsWith: `personal-${userId.substring(0, 8)}` } },
        ],
      },
      orderBy: { createdAt: 'desc' },
      skip: page * limit,
      take: limit,
    });

    const fromLogs = logs
      .filter((l) => l.meetingSummary?.recordingUrl)
      .map((l) => ({
        id: l.meetingSummary!.id,
        roomName: l.roomName,
        participants: l.meetingSummary!.participants,
        durationSec: l.meetingSummary!.durationSec,
        createdAt: l.meetingSummary!.createdAt,
        recordingUrl: l.meetingSummary!.recordingUrl!,
        status: (l.meetingSummary as any).status ?? 'done',
        hasTranscript:
          !!l.meetingSummary!.transcript &&
          l.meetingSummary!.transcript.length > 0,
        hasSummary:
          !!l.meetingSummary!.summary && l.meetingSummary!.summary.length > 0,
      }));

    const fromPublic = publicSummaries.map((s) => ({
      id: s.id,
      roomName: s.roomName,
      participants: s.participants,
      durationSec: s.durationSec,
      createdAt: s.createdAt,
      recordingUrl: s.recordingUrl!,
      status: (s as any).status ?? 'done',
      hasTranscript: !!s.transcript && s.transcript.length > 0,
      hasSummary: !!s.summary && s.summary.length > 0,
    }));

    return [...fromLogs, ...fromPublic].sort(
      (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
    );
  }

  async getMeetingSummary(id: string) {
    const summary = await this.prisma.meetingSummary.findUnique({
      where: { id },
    });
    if (!summary) throw new NotFoundException('Meeting summary not found');
    return summary;
  }

  async transcribeExistingRecording(userId: string, meetingId: string) {
    const meeting = await this.prisma.meetingSummary.findUnique({
      where: { id: meetingId },
    });
    if (!meeting) throw new NotFoundException('Meeting not found');
    if (!meeting.recordingUrl) throw new Error('No recording URL');

    // Ownership: a participant OR the personal-room owner can kick off transcription
    // (and be billed). The owner clause mirrors getMeetingRecordings(): when everyone
    // joined a personal room via web guest links, participantIds contains only
    // guest-* identities, yet the owner sees the recording in their list.
    // If participantIds wasn't populated on legacy rows, skip the check rather than hard-fail —
    // the JWT guard already ensures an authenticated user.
    const isPersonalRoomOwner = meeting.roomName.startsWith(
      `personal-${userId.substring(0, 8)}`,
    );
    if (
      meeting.participantIds.length > 0 &&
      !meeting.participantIds.includes(userId) &&
      !isPersonalRoomOwner
    ) {
      throw new ForbiddenException('Not a participant of this meeting');
    }

    // Mark as processing
    await this.prisma.meetingSummary.update({
      where: { id: meetingId },
      data: { status: 'processing' },
    });

    // Download recording
    let audioBuffer: Buffer;
    const url = meeting.recordingUrl;

    if (url.includes('/messenger/files/download?key=')) {
      // S3 stored — read via FileStorageService
      const key = decodeURIComponent(url.split('key=')[1]);
      const { stream } = await this.fileStorage.getObject(key);
      const chunks: Buffer[] = [];
      for await (const chunk of stream) chunks.push(Buffer.from(chunk));
      audioBuffer = Buffer.concat(chunks);
    } else {
      // External URL — fetch
      const res = await fetch(url);
      if (!res.ok)
        throw new Error(`Failed to download recording: ${res.status}`);
      audioBuffer = Buffer.from(await res.arrayBuffer());
    }

    // Check if we have per-participant tracks for speaker diarization
    const participantTracks = (meeting as any).participantTracks as Record<
      string,
      string
    > | null;
    const hasMultipleTracks =
      participantTracks &&
      typeof participantTracks === 'object' &&
      Object.keys(participantTracks).length > 1;

    // ─── Whisper billing pre-check + pre-debit ───
    // Whisper charges per audio-minute. For diarization we send each track (same length
    // as the call) separately, so billable minutes = numTracks × durationSec. For the
    // single-mixed path it's just durationSec. Fall back to 1 min if durationSec is null
    // on legacy rows — pricing rounds up and refunds on failure anyway.
    const baseDurationSec =
      meeting.durationSec && meeting.durationSec > 0 ? meeting.durationSec : 60;
    const trackCount = hasMultipleTracks
      ? Object.keys(participantTracks!).length
      : 1;
    const whisperMinutes = (baseDurationSec * trackCount) / 60;

    const whisperSession = await this.gating.startSession(
      userId,
      FEATURE_KEYS.WHISPER_TRANSCRIBE,
    );
    const whisperCost = await this.pricing.calculatePlanckCost(
      FEATURE_KEYS.WHISPER_TRANSCRIBE,
      whisperMinutes,
    );

    let whisperTx: { id: string };
    try {
      whisperTx = await this.ledger.debit(userId, whisperCost, 'SPEND', {
        featureKey: FEATURE_KEYS.WHISPER_TRANSCRIBE,
        sessionId: whisperSession.id,
        metadata: { meetingId, durationMin: whisperMinutes, trackCount },
      });
    } catch (err) {
      // Debit failed (insufficient funds) before Whisper ran — mark the meeting
      // as failed so the UI doesn't show stale "processing" or misleading "done".
      await this.gating.endSession(whisperSession.id, 'failed').catch(() => {});
      await this.prisma.meetingSummary
        .update({ where: { id: meetingId }, data: { status: 'failed' } })
        .catch(() => {});
      throw err;
    }

    let transcript = '';

    try {
      if (hasMultipleTracks) {
        // Speaker diarization: transcribe each participant track separately and merge by timestamp
        console.log(
          '[VOICE] Speaker diarization: transcribing',
          Object.keys(participantTracks).length,
          'tracks separately',
        );
        const allSegments: {
          start: number;
          end: number;
          text: string;
          speaker: string;
        }[] = [];

        for (const [speakerName, trackUrl] of Object.entries(
          participantTracks,
        )) {
          try {
            // Download individual track
            let trackBuffer: Buffer;
            if (
              (trackUrl as string).includes('/messenger/files/download?key=')
            ) {
              const key = decodeURIComponent(
                (trackUrl as string).split('key=')[1],
              );
              const { stream } = await this.fileStorage.getObject(key);
              const chunks: Buffer[] = [];
              for await (const chunk of stream) chunks.push(Buffer.from(chunk));
              trackBuffer = Buffer.concat(chunks);
            } else {
              const trackRes = await fetch(trackUrl as string);
              if (!trackRes.ok) {
                console.warn(
                  '[VOICE] Failed to download track for',
                  speakerName,
                );
                continue;
              }
              trackBuffer = Buffer.from(await trackRes.arrayBuffer());
            }

            // Transcribe this track
            const trackForm = new FormData();
            const trackBlob = new Blob([new Uint8Array(trackBuffer)], {
              type: 'audio/ogg',
            });
            trackForm.append('file', trackBlob, speakerName + '.ogg');
            trackForm.append('model', 'whisper-1');
            trackForm.append('response_format', 'verbose_json');
            trackForm.append('timestamp_granularities[]', 'segment');

            const trackWhisperRes = await fetch(
              'https://api.openai.com/v1/audio/transcriptions',
              {
                method: 'POST',
                headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
                body: trackForm,
              },
            );

            if (!trackWhisperRes.ok) {
              console.warn(
                '[VOICE] Whisper error for track',
                speakerName,
                ':',
                trackWhisperRes.status,
              );
              continue;
            }

            const trackData = (await trackWhisperRes.json()) as any;
            const segs = trackData.segments ?? [];
            for (const s of segs) {
              allSegments.push({
                start: s.start,
                end: s.end,
                text: s.text.trim(),
                speaker: speakerName,
              });
            }
            if (segs.length === 0 && trackData.text) {
              allSegments.push({
                start: 0,
                end: 0,
                text: trackData.text.trim(),
                speaker: speakerName,
              });
            }
          } catch (e) {
            console.warn(
              '[VOICE] Error transcribing track for',
              speakerName,
              ':',
              (e as Error).message,
            );
          }
        }

        // If every track failed (per-track catches swallow errors), we'd end up with
        // an empty transcript, skip GPT-4o, and silently mark the session completed —
        // leaving the user charged for N tracks × duration with nothing to show.
        // Throw so the outer catch refunds and marks the meeting failed.
        if (allSegments.length === 0) {
          throw new Error(
            'diarization_all_tracks_failed: no transcript produced',
          );
        }

        // Sort by timestamp and format
        allSegments.sort((a, b) => a.start - b.start);
        transcript = allSegments
          .map((s) => {
            const mm = String(Math.floor(s.start / 60)).padStart(2, '0');
            const ss = String(Math.floor(s.start % 60)).padStart(2, '0');
            return `[${mm}:${ss}] ${s.speaker}: ${s.text}`;
          })
          .join('\n');
      } else {
        // Single mixed recording - transcribe without speaker info
        const formData = new FormData();
        const blob = new Blob([new Uint8Array(audioBuffer)], {
          type: 'audio/mpeg',
        });
        formData.append('file', blob, 'recording.mp3');
        formData.append('model', 'whisper-1');
        formData.append('response_format', 'verbose_json');
        formData.append('timestamp_granularities[]', 'segment');

        const whisperRes = await fetch(
          'https://api.openai.com/v1/audio/transcriptions',
          {
            method: 'POST',
            headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
            body: formData,
          },
        );

        if (!whisperRes.ok) {
          const errText = await whisperRes.text();
          throw new Error(`Whisper error ${whisperRes.status}: ${errText}`);
        }

        const whisperData = (await whisperRes.json()) as any;
        const segments = whisperData.segments ?? [];
        transcript =
          segments.length > 0
            ? segments
                .map((s: any) => {
                  const mm = String(Math.floor(s.start / 60)).padStart(2, '0');
                  const ss = String(Math.floor(s.start % 60)).padStart(2, '0');
                  return `[${mm}:${ss}] ${s.text.trim()}`;
                })
                .join('\n')
            : (whisperData.text?.trim() ?? '');
      }
      await this.gating.endSession(whisperSession.id, 'completed');
    } catch (err) {
      // Transcription failed — covers both the single-mixed path (Whisper HTTP error)
      // and the diarization path (all tracks failed → we throw above). Mark the
      // meeting as failed so UI stops showing "processing", refund the pre-debit,
      // and close the gating session.
      await this.prisma.meetingSummary
        .update({ where: { id: meetingId }, data: { status: 'failed' } })
        .catch(() => {});
      await this.ledger
        .refund(whisperTx.id, `whisper error: ${String(err).slice(0, 200)}`)
        .catch(() => {});
      await this.gating.endSession(whisperSession.id, 'failed').catch(() => {});
      throw err;
    }

    // ─── GPT-4o meeting summary (exact post-call debit from usage.total_tokens) ───
    let summary = {
      summary: '',
      keyPoints: [] as string[],
      actionItems: [] as any[],
      decisions: [] as string[],
    };
    if (transcript.length > 0) {
      const summarySession = await this.gating.startSession(
        userId,
        FEATURE_KEYS.MEETING_SUMMARY,
      );

      try {
        const gptRes = await fetch(
          'https://api.openai.com/v1/chat/completions',
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${OPENAI_API_KEY}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              model: 'gpt-4o',
              response_format: { type: 'json_object' },
              messages: [
                {
                  role: 'system',
                  content: `Ты — профессиональный ассистент для анализа деловых встреч. Внимательно проанализируй транскрипт и верни JSON с полями:
- "summary": структурированное резюме встречи (2-3 абзаца). Включи контекст встречи, основные обсуждённые темы и общий итог. Пиши на языке встречи.
- "keyPoints": массив ключевых моментов (строки). Каждый пункт должен быть конкретным и информативным — не общие фразы, а суть обсуждённого. Формат: "[Тема] — описание".
- "actionItems": массив задач, каждая: { "task": "конкретное описание задачи с ожидаемым результатом", "assignee": "имя ответственного или null", "deadline": "срок или null" }. Извлекай задачи из явных обещаний, договорённостей и поручений.
- "decisions": массив принятых решений (строки). Включай только явно согласованные решения, а не предложения или обсуждения.
Пиши резюме на том же языке, на котором проходила встреча. Если есть спикеры — указывай кто что сказал/предложил/решил.`,
                },
                { role: 'user', content: transcript },
              ],
              max_tokens: 4096,
            }),
          },
        );

        if (gptRes.ok) {
          const gptData = (await gptRes.json()) as any;
          // Exact cost from actual token usage; fallback to 0 only if usage missing.
          const totalTokens = gptData.usage?.total_tokens ?? 0;
          const tokensK = totalTokens / 1000;
          const summaryCost = await this.pricing.calculatePlanckCost(
            FEATURE_KEYS.MEETING_SUMMARY,
            tokensK,
          );

          try {
            // Zero tokens happens only when GPT-4o returns an empty response (edge case,
            // already logged). Skipping the debit is intentional — don't charge for nothing.
            if (summaryCost > 0n) {
              await this.ledger.debit(userId, summaryCost, 'SPEND', {
                featureKey: FEATURE_KEYS.MEETING_SUMMARY,
                sessionId: summarySession.id,
                metadata: { meetingId, totalTokens },
              });
            }
          } catch (debitErr) {
            // Post-call debit failed (insufficient funds). We already spent money on GPT-4o.
            // Fail closed: mark session failed and throw — better to 500 than silently
            // give the user free summaries.
            this.log.error(
              `meeting_summary post-call debit failed for user=${userId} session=${summarySession.id}: ${String(debitErr)}`,
            );
            await this.gating
              .endSession(summarySession.id, 'failed')
              .catch(() => {});
            throw debitErr;
          }

          try {
            summary = JSON.parse(gptData.choices[0].message.content);
          } catch {
            summary.summary = gptData.choices[0].message.content;
          }
          await this.gating.endSession(summarySession.id, 'completed');
        } else {
          // GPT-4o 4xx/5xx — no debit needed (we only bill on successful response),
          // but still close the session so cron doesn't sweep it as "active".
          await this.gating
            .endSession(summarySession.id, 'failed')
            .catch(() => {});
        }
      } catch (err) {
        // OpenAI network error OR the inner debit-fail rethrow. Ensure session is closed.
        // endSession is idempotent on already-ended rows via Prisma where-clause match,
        // but we guard with catch-all to avoid double-close errors on the debit-fail path.
        await this.gating
          .endSession(summarySession.id, 'failed')
          .catch(() => {});
        throw err;
      }
    }

    // Update meeting summary
    const updated = await this.prisma.meetingSummary.update({
      where: { id: meetingId },
      data: {
        transcript,
        summary: summary.summary || '',
        keyPoints: summary.keyPoints || [],
        actionItems: summary.actionItems || [],
        decisions: summary.decisions || [],
        status: 'done',
      },
    });

    return { id: updated.id, status: 'done' };
  }

  // ─── Hold Music ───

  async startHoldMusic(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/hold-music/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      return await res.json();
    } catch (e) {
      console.error('Failed to start hold music:', e);
      return { error: 'Hold music agent unavailable' };
    }
  }

  async stopHoldMusic(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/hold-music/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      return await res.json();
    } catch (e) {
      console.error('Failed to stop hold music:', e);
      return { error: 'Hold music agent unavailable' };
    }
  }
}
