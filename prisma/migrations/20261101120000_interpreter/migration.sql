-- Разговор с переводом: двое рядом, у каждого свой телефон.
-- Спека: docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
--
-- Всё аддитивно: два enum'а, новая таблица и строка прайса. Старый код о них не
-- знает, поэтому миграцию можно накатить до рестарта нод.
--
-- Prisma гонит этот файл одной неявной транзакцией. Если `prisma migrate
-- deploy` упадёт по lock_timeout ниже — откатится весь файл, и перед повтором
-- нужно сначала снять пометку "failed":
--   npx prisma migrate resolve --rolled-back 20261101120000_interpreter

-- Короткий lock_timeout: внешние ключи на "User" ниже встают в очередь за живыми
-- записями в эту таблицу и, пока ждут, задерживают новые. Лучше упасть быстро и
-- повторить, чем подвесить прод. LOCAL — чтобы настройка закончилась вместе с
-- транзакцией этой миграции и не утекла в следующие на том же соединении.
SET LOCAL lock_timeout = '5s';

-- CreateEnum
CREATE TYPE "InterpreterStatus" AS ENUM ('WAITING', 'ACTIVE', 'ENDED');

-- CreateEnum
CREATE TYPE "InterpreterEndReason" AS ENUM ('HANGUP', 'PARTNER_LEFT', 'NO_FUNDS', 'MAX_DURATION', 'TRANSLATION_FAILED', 'AGENT_LOST', 'EXPIRED');

-- CreateTable
CREATE TABLE "InterpreterSession" (
    "id" TEXT NOT NULL,
    "roomName" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "guestId" TEXT,
    "hostLang" TEXT NOT NULL,
    "guestLang" TEXT,
    "codeHash" TEXT,
    "codeExpiresAt" TIMESTAMP(3),
    "status" "InterpreterStatus" NOT NULL DEFAULT 'WAITING',
    "billingSessionId" UUID,
    "agentSeenAt" TIMESTAMP(3),
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "endReason" "InterpreterEndReason",
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InterpreterSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "InterpreterSession_roomName_key" ON "InterpreterSession"("roomName");

-- CreateIndex
CREATE UNIQUE INDEX "InterpreterSession_codeHash_key" ON "InterpreterSession"("codeHash");

-- CreateIndex
CREATE INDEX "InterpreterSession_hostId_status_idx" ON "InterpreterSession"("hostId", "status");

-- CreateIndex
CREATE INDEX "InterpreterSession_guestId_status_idx" ON "InterpreterSession"("guestId", "status");

-- CreateIndex
CREATE INDEX "InterpreterSession_status_codeExpiresAt_idx" ON "InterpreterSession"("status", "codeExpiresAt");

-- AddForeignKey
ALTER TABLE "InterpreterSession" ADD CONSTRAINT "InterpreterSession_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InterpreterSession" ADD CONSTRAINT "InterpreterSession_guestId_fkey" FOREIGN KEY ("guestId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Статья прайса. Себестоимость $0.07/мин — два синхронных потока
-- gpt-realtime-translate по $0.034; наценка общая, ×2. Резерв — две минуты по
-- курсу сида (1 TAL = $11 700): 2 × $0.14 / 11 700 × 10¹² ≈ 24M planck.
-- Дальше цена правится админской ручкой прайса, без релиза.
-- ON CONFLICT: строку могли завести руками до миграции — её и подобранную цену не трогаем.
INSERT INTO "AiPricebook" (id, "featureKey", unit, "costUsdPerUnit", "markupMultiplier", "minReservePlanck", "updatedAt") VALUES
  ('pb_interpreter', 'interpreter', 'minute', 0.07, 2.0, 24000000, NOW())
ON CONFLICT ("featureKey") DO NOTHING;
