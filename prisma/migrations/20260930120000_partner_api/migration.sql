-- Партнёрский API мессенджера (первый партнёр — nadi).
-- Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
--
-- Всё аддитивно: новые таблицы и колонка с дефолтом. Старый код продолжает
-- работать поверх этой схемы, поэтому миграцию можно накатить до рестарта нод.
--
-- Prisma гонит этот файл одной неявной транзакцией. Если `prisma migrate
-- deploy` упадёт по lock_timeout ниже — весь файл откатится целиком, и
-- перед повтором нужно сначала снять пометку "failed":
--   npx prisma migrate resolve --rolled-back 20260930120000_partner_api
-- и только потом запускать deploy заново.

-- Короткий lock_timeout вместо дефолтного (обычно без ограничения): FK на
-- "User" ниже встаёт в очередь за живыми записями в эту таблицу, а колонка
-- BlockedUser в самом конце файла читается на каждой отправке сообщения —
-- держать на них эксклюзивную блокировку долго на живой базе нельзя, лучше
-- упасть быстро и повторить миграцию, чем подвесить прод.
SET lock_timeout = '5s';

-- CreateEnum
CREATE TYPE "PartnerLinkStatus" AS ENUM ('PENDING', 'ACTIVE', 'REVOKED');

-- CreateTable
CREATE TABLE "Partner" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "ipAllowlist" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "webhookUrl" TEXT,
    "webhookSecretEnc" TEXT,
    "oauthClientId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Partner_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartnerLink" (
    "id" TEXT NOT NULL,
    "partnerId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "PartnerLinkStatus" NOT NULL,
    "createdAccount" BOOLEAN NOT NULL DEFAULT false,
    "grantId" TEXT,
    "codeHash" TEXT,
    "codeExpiresAt" TIMESTAMP(3),
    "codeAttempts" INTEGER NOT NULL DEFAULT 0,
    "activatedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PartnerLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartnerContact" (
    "id" TEXT NOT NULL,
    "partnerId" TEXT NOT NULL,
    "userAId" TEXT NOT NULL,
    "userBId" TEXT NOT NULL,
    "createdContact" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PartnerContact_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Partner_slug_key" ON "Partner"("slug");
CREATE UNIQUE INDEX "Partner_oauthClientId_key" ON "Partner"("oauthClientId");
CREATE UNIQUE INDEX "PartnerLink_partnerId_externalId_key" ON "PartnerLink"("partnerId", "externalId");
CREATE UNIQUE INDEX "PartnerLink_partnerId_userId_key" ON "PartnerLink"("partnerId", "userId");
CREATE INDEX "PartnerLink_userId_status_idx" ON "PartnerLink"("userId", "status");
CREATE UNIQUE INDEX "PartnerContact_partnerId_userAId_userBId_key" ON "PartnerContact"("partnerId", "userAId", "userBId");
CREATE INDEX "PartnerContact_userAId_userBId_idx" ON "PartnerContact"("userAId", "userBId");

-- AddForeignKey
-- Партнёра нельзя удалить SQL-уровнем DELETE — выключают через Partner.enabled=false.
-- RESTRICT — чтобы случайный DELETE FROM "Partner" не снёс тихо все связки и контакты.
ALTER TABLE "PartnerLink" ADD CONSTRAINT "PartnerLink_partnerId_fkey" FOREIGN KEY ("partnerId") REFERENCES "Partner"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "PartnerLink" ADD CONSTRAINT "PartnerLink_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PartnerContact" ADD CONSTRAINT "PartnerContact_partnerId_fkey" FOREIGN KEY ("partnerId") REFERENCES "Partner"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Блокировки, сделанные до этой миграции, получают false: неизвестно, были ли
-- люди контактами, и безопаснее не восстанавливать контакт при разблокировке.
-- Эта колонка — последняя в файле: BlockedUser читается на каждой отправке
-- сообщения, и эксклюзивная блокировка на ALTER должна держаться минимум времени.
ALTER TABLE "BlockedUser" ADD COLUMN "hadContact" BOOLEAN NOT NULL DEFAULT false;
