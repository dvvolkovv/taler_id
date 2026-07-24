-- CreateEnum
CREATE TYPE "MailAccountStatus" AS ENUM ('PROVISIONING', 'ACTIVE', 'SUSPENDED');

-- CreateTable
CREATE TABLE "MailAccount" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "localpart" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "status" "MailAccountStatus" NOT NULL DEFAULT 'PROVISIONING',
    "quotaBytes" BIGINT NOT NULL DEFAULT 1073741824,
    "masterSecret" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MailAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MailAppPassword" (
    "id" TEXT NOT NULL,
    "mailAccountId" TEXT NOT NULL,
    "mailcowId" INTEGER NOT NULL,
    "label" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "MailAppPassword_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "MailAccount_userId_key" ON "MailAccount"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "MailAccount_localpart_key" ON "MailAccount"("localpart");

-- CreateIndex
CREATE INDEX "MailAccount_status_idx" ON "MailAccount"("status");

-- CreateIndex
CREATE INDEX "MailAppPassword_mailAccountId_idx" ON "MailAppPassword"("mailAccountId");

-- AddForeignKey
ALTER TABLE "MailAccount" ADD CONSTRAINT "MailAccount_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MailAppPassword" ADD CONSTRAINT "MailAppPassword_mailAccountId_fkey" FOREIGN KEY ("mailAccountId") REFERENCES "MailAccount"("id") ON DELETE CASCADE ON UPDATE CASCADE;
