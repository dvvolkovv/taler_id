/**
 * Пример интеграции с мессенджером Taler ID — для разработчиков партнёра (nadi).
 * Проходит весь путь: двое людей → контакт → токены → сокеты → личка → группа.
 * Показывает и переподключение сокета со свежим токеном после того, как
 * сервер закрыл его сам (см. docs/partner-messenger-api.md, разделы
 * «Приложение: токен и сокет» и «Сокет: от приложения»).
 * В конце удаляет созданные аккаунты.
 *
 * Запуск (Node 20+, в пустом каталоге):
 *   npm i axios socket.io-client tsx
 *   BASE_URL=https://staging.id.taler.tirol TALERID_PARTNER_KEY=tidp_… npx tsx example-client.ts
 */
import axios from 'axios';
import { io, Socket } from 'socket.io-client';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const KEY = process.env.TALERID_PARTNER_KEY ?? '';

// Ваш бэкенд: ключ партнёра — только здесь.
const partner = axios.create({
  baseURL: `${BASE_URL}/partner/v1`,
  headers: { Authorization: `Bearer ${KEY}` },
});

// Ваше приложение: только короткий токен конкретного человека.
function messenger(token: string) {
  return axios.create({ baseURL: `${BASE_URL}/messenger`, headers: { Authorization: `Bearer ${token}` } });
}

interface MessengerToken {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  talerUserId: string;
}

async function mintToken(externalId: string): Promise<MessengerToken> {
  return (await partner.post(`/users/${externalId}/token`)).data;
}

/**
 * Подключает сокет мессенджера и держит его живым дольше одного токена (15 мин).
 *
 * Taler ID сам закрывает сокет в момент истечения токена — `disconnect` с
 * причиной `io server disconnect` — а socket.io-client именно после НЕЁ сам
 * не переподключается (это единственная причина disconnect, после которой
 * нет автоматического релогина). Поэтому только на эту причину мы берём у
 * своего бэкенда свежий токен, кладём его в `socket.auth` и зовём
 * `socket.connect()` повторно — тем же сокетом, не создавая новый. Любая
 * другая причина (обрыв сети, пинг-таймаут) — временная проблема транспорта,
 * и встроенный реконнект socket.io-client уже сам всё сделает со старым токеном.
 */
async function connect(label: string, externalId: string, token: string): Promise<Socket> {
  const socket = io(`${BASE_URL}/messenger`, {
    auth: { token },
    transports: ['websocket'],
  });
  socket.on('disconnect', (reason) => {
    console.log(`${label}: disconnected (${reason})`);
    if (reason !== 'io server disconnect') return;
    mintToken(externalId)
      .then(({ accessToken }) => {
        socket.auth = { token: accessToken };
        socket.connect();
      })
      .catch((e) => console.error(`${label}: couldn't refresh token`, e.response?.data ?? e));
  });
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => resolve());
    socket.once('connect_error', reject);
  });
  return socket;
}

async function main(): Promise<void> {
  if (!KEY) throw new Error('TALERID_PARTNER_KEY is required');
  const run = Date.now().toString(36);
  const people = [
    { externalId: `example-a-${run}`, email: `example-a-${run}@example.com`, firstName: 'Олена' },
    { externalId: `example-b-${run}`, email: `example-b-${run}@example.com`, firstName: 'Петро' },
  ];

  let socketA: Socket | undefined;
  let socketB: Socket | undefined;
  try {
    // 1. Бэкенд заводит людей — у nadi при регистрации или входе.
    for (const person of people) {
      console.log('provision', person.externalId, (await partner.post('/users', person)).data);
    }
    const [a, b] = people;

    // 2. Дружба у вас → контакт в Taler ID.
    console.log('contact', (await partner.put(`/contacts/${a.externalId}/${b.externalId}`)).data);

    // 3. Приложение просит токены у своего бэкенда, бэкенд — у Taler ID.
    const tokenA = await mintToken(a.externalId);
    const tokenB = await mintToken(b.externalId);

    // 4. Сокеты. Чтобы получать new_message, join не нужен.
    socketA = await connect('A', a.externalId, tokenA.accessToken);
    socketB = await connect('B', b.externalId, tokenB.accessToken);
    socketB.on('new_message', (m: any) => console.log('B got:', m.senderName, '—', m.content));
    socketA.on('message_acked', (ack: any) => console.log('A acked:', ack));

    // 5. Личный чат и сообщение.
    const direct = (await messenger(tokenA.accessToken).post('/conversations', { participantId: tokenB.talerUserId }))
      .data;
    socketA.emit('message', { conversationId: direct.id, content: 'Привіт!', clientTempId: `tmp-${run}` });

    // 6. Группа из контактов.
    const group = (
      await messenger(tokenA.accessToken).post('/conversations/group', {
        name: 'Толока',
        participantIds: [tokenB.talerUserId],
      })
    ).data;
    socketA.emit('message', { conversationId: group.id, content: 'Збираємося в суботу' });

    await new Promise((r) => setTimeout(r, 2000));
  } finally {
    socketA?.disconnect();
    socketB?.disconnect();
    // Аккаунты создали мы, и человек в Taler ID сам не входил — их можно удалить.
    for (const person of people) {
      await partner.delete(`/users/${person.externalId}`, { params: { deleteAccount: 'true' } }).catch(() => undefined);
    }
  }
}

main().catch((e) => {
  console.error(e.response?.data ?? e);
  process.exit(1);
});
