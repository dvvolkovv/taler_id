/**
 * Пред-деплойная проверка расшифровки ДЛИННОЙ встречи.
 *
 * Обычная батарея (`taler_id_tests`) чёрно-ящичная: она ходит только по HTTP и
 * поэтому не может создать встречу с часовой записью — записать её по-настоящему
 * стоило бы час. Из-за этого путь «запись больше 25 МиБ» не проверялся ничем,
 * кроме юнит-тестов, и три предела подряд доехали до прода незамеченными:
 *
 *   1. Whisper отказывает на выгрузке больше 25 МиБ (26 214 400 байт) — 413.
 *   2. У встроенного в Node fetch зашит таймаут заголовков в 300 с, и один
 *      вызов на часовой записи в него не укладывается.
 *   3. Четыре одновременных куска встают в очередь на стороне OpenAI, из-за
 *      чего тот же кусок отвечает то за 200 с, то дольше 300 с.
 *
 * Скрипт собирает длинную запись из короткой (ffmpeg, склейка без перекодирования),
 * кладёт её в хранилище, заводит встречу, дёргает настоящую ручку расшифровки и
 * проверяет результат. За собой убирает.
 *
 * Запускать на хосте бэкенда — нужны доступ к базе, к S3 и ffmpeg:
 *   cd ~/taler-id && npx ts-node -r dotenv/config scripts/verify-long-transcription.ts \
 *     --email integration_test@taler-test.com --password 'IntegrationTest123!'
 *
 * Необязательные ключи:
 *   --minutes 53     желаемая длительность (по умолчанию 53 — чуть за потолком)
 *   --seed <s3-key>  короткая запись-донор; по умолчанию берётся самая свежая
 *   --keep           не удалять встречу и файл (для разбора)
 */
import { PrismaClient } from '@prisma/client';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectsV2Command,
} from '@aws-sdk/client-s3';
import { Readable } from 'stream';

const execFileAsync = promisify(execFile);
const WHISPER_CAP = 26_214_400;

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const has = (name: string) => process.argv.includes(`--${name}`);

const BASE_URL = (process.env.BASE_URL ?? 'http://localhost:3000').replace(
  /\/$/,
  '',
);
const EMAIL = arg('email');
const PASSWORD = arg('password');
const MINUTES = Number(arg('minutes', '53'));
const KEEP = has('keep');

const bucket = process.env.S3_FILES_BUCKET ?? 'taler-id-files';
const s3 = new S3Client({
  endpoint: process.env.S3_ENDPOINT ?? 'http://localhost:9000',
  region: process.env.S3_REGION ?? 'us-east-1',
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY ?? 'minioadmin',
    secretAccessKey: process.env.S3_SECRET_KEY ?? 'minioadmin123',
  },
  forcePathStyle: true,
});
const prisma = new PrismaClient();

let failures = 0;
function check(label: string, ok: boolean, detail = '') {
  console.log(`${ok ? '  ✓' : '  ✗'} ${label}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures++;
}

async function readObject(key: string): Promise<Buffer> {
  const resp = await s3.send(
    new GetObjectCommand({ Bucket: bucket, Key: key }),
  );
  const chunks: Buffer[] = [];
  for await (const c of resp.Body as Readable) chunks.push(Buffer.from(c));
  return Buffer.concat(chunks);
}

/** Самая свежая короткая запись — донор речи для склейки. */
async function pickSeedKey(): Promise<string> {
  const explicit = arg('seed');
  if (explicit) return explicit;
  const listed = await s3.send(
    new ListObjectsV2Command({ Bucket: bucket, Prefix: 'recordings/' }),
  );
  const candidates = (listed.Contents ?? [])
    .filter((o) => o.Key?.endsWith('.mp3') && (o.Size ?? 0) > 20_000)
    // Мелкие: склейка длинной записи из большой донорской — лишние гигабайты.
    .filter((o) => (o.Size ?? 0) < 2_000_000)
    .sort(
      (a, b) =>
        (b.LastModified?.getTime() ?? 0) - (a.LastModified?.getTime() ?? 0),
    );
  if (!candidates.length) {
    throw new Error(
      'не нашлось короткой записи-донора в recordings/ — укажите --seed <key>',
    );
  }
  return candidates[0].Key!;
}

async function main() {
  if (!EMAIL || !PASSWORD) {
    throw new Error('нужны --email и --password тестового пользователя');
  }
  console.log(`\n── Расшифровка длинной встречи (${BASE_URL}) ──\n`);

  const seedKey = await pickSeedKey();
  const seed = await readObject(seedKey);
  console.log(`  донор: ${seedKey} (${seed.length} Б)`);

  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'longcheck-'));
  const seedPath = path.join(dir, 'seed.mp3');
  const listPath = path.join(dir, 'list.txt');
  const longPath = path.join(dir, 'long.mp3');
  let s3Key: string | null = null;
  let meetingId: string | null = null;

  try {
    await fs.promises.writeFile(seedPath, seed);
    const { stdout } = await execFileAsync('ffprobe', [
      '-v', 'error', '-show_entries', 'format=duration',
      '-of', 'default=nw=1:nk=1', seedPath,
    ]);
    const seedSec = Number.parseFloat(stdout.trim());
    const repeats = Math.ceil((MINUTES * 60) / seedSec);
    await fs.promises.writeFile(
      listPath,
      Array.from({ length: repeats }, () => `file '${seedPath}'`).join('\n'),
    );
    // Склейка копированием: без перекодирования, так что битрейт остаётся тем
    // же, что пишет LiveKit — именно он и задаёт, где проходит потолок в байтах.
    await execFileAsync(
      'ffmpeg',
      ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0',
       '-i', listPath, '-c', 'copy', longPath],
      { timeout: 600000 },
    );
    const long = await fs.promises.readFile(longPath);
    check(
      `склеена запись на ~${MINUTES} мин, ${long.length} Б`,
      long.length > WHISPER_CAP,
      long.length > WHISPER_CAP
        ? `на ${long.length - WHISPER_CAP} Б за потолком Whisper`
        : 'НЕ превышает потолок — проверка ничего не докажет, увеличьте --minutes',
    );
    if (long.length <= WHISPER_CAP) throw new Error('запись вышла слишком мала');

    s3Key = `recordings/verify-long-${Date.now()}.mp3`;
    await s3.send(
      new PutObjectCommand({
        Bucket: bucket, Key: s3Key, Body: long, ContentType: 'audio/mpeg',
      }),
    );

    const login = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    const loginBody = (await login.json()) as any;
    const token = loginBody.accessToken;
    check('вход тестового пользователя', typeof token === 'string');
    if (!token) throw new Error(`не выдан токен: ${JSON.stringify(loginBody)}`);

    const user = await prisma.user.findUnique({ where: { email: EMAIL } });
    if (!user) throw new Error(`пользователь ${EMAIL} не найден в базе`);

    const durationSec = Math.round(repeats * seedSec);
    const meeting = await prisma.meetingSummary.create({
      data: {
        roomName: `verify-long-${Date.now()}`,
        transcript: '',
        summary: '',
        participants: ['verify-long'],
        participantIds: [user.id],
        recordingUrl: `${BASE_URL}/messenger/files/download?key=${encodeURIComponent(s3Key)}`,
        durationSec,
        status: 'pending',
      },
    });
    meetingId = meeting.id;

    console.log(`  встреча ${meetingId}, ${durationSec} с — запускаем расшифровку`);
    const started = Date.now();
    // Ответ по HTTP может не дождаться: nginx и балансировщик рвут соединение
    // раньше, чем бэкенд заканчивает. Нас интересует итог в базе, а не ответ.
    fetch(`${BASE_URL}/voice/recordings/${meetingId}/transcribe`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    }).catch(() => {});

    let row = meeting;
    const deadline = Date.now() + 20 * 60 * 1000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 15000));
      row = (await prisma.meetingSummary.findUnique({
        where: { id: meetingId },
      }))!;
      if (row.status === 'done' || row.status === 'failed') break;
      process.stdout.write(`\r  ${row.status}… ${Math.round((Date.now() - started) / 1000)} с`);
    }
    process.stdout.write('\n');
    const elapsed = Math.round((Date.now() - started) / 1000);

    check(`расшифровка завершилась (${elapsed} с)`, row.status === 'done', `status=${row.status}`);
    check('транскрипт не пуст', row.transcript.length > 0, `${row.transcript.length} символов`);
    check('резюме не пусто', row.summary.length > 0, `${row.summary.length} символов`);

    // Куски должны быть сшиты: если склейка потерялась, все таймкоды
    // схлопнутся в первые минуты вместо того, чтобы дойти до конца записи.
    const stamps = row.transcript
      .split('\n')
      .map((l) => l.match(/\[(\d+):(\d+)\]/))
      .filter(Boolean)
      .map((m) => Number(m![1]) * 60 + Number(m![2]));
    const last = stamps.length ? Math.max(...stamps) : 0;
    check(
      'таймкоды доходят до конца записи',
      last > durationSec * 0.6,
      `последний ${Math.floor(last / 60)}:${String(last % 60).padStart(2, '0')} из ${Math.floor(durationSec / 60)} мин`,
    );
    check(
      'таймкоды идут по возрастанию',
      stamps.every((v, i) => i === 0 || v >= stamps[i - 1]),
    );
  } finally {
    await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
    if (!KEEP) {
      if (meetingId) {
        await prisma.meetingSummary
          .delete({ where: { id: meetingId } })
          .catch(() => {});
      }
      if (s3Key) {
        await s3
          .send(new DeleteObjectCommand({ Bucket: bucket, Key: s3Key }))
          .catch(() => {});
      }
    } else if (meetingId) {
      console.log(`\n  --keep: встреча ${meetingId} и ключ ${s3Key} оставлены`);
    }
    await prisma.$disconnect();
  }
}

main()
  .then(() => {
    console.log(
      failures === 0
        ? '\n  Проверка пройдена\n'
        : `\n  Провалено проверок: ${failures}\n`,
    );
    process.exit(failures === 0 ? 0 : 1);
  })
  .catch(async (e) => {
    console.error(`\n  ОШИБКА: ${e.message}\n`);
    await prisma.$disconnect().catch(() => {});
    process.exit(1);
  });
