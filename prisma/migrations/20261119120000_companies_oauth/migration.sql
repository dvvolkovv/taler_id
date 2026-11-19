-- Вход от имени компании и передача проверенных компаний через OAuth.
-- Спека: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
-- Индекс TenantMember(userId) — выбор компаний человека идёт на каждый /oauth/me.
--
-- Всё аддитивно: две новые таблицы, старый код о них не знает — миграцию можно
-- накатить до рестарта нод. Внешний ключ на "Tenant" встаёт в очередь за живыми
-- записями в эту таблицу; короткий lock_timeout — чтобы не подвесить прод.
-- Упала по таймауту — откатится весь файл, перед повтором:
--   npx prisma migrate resolve --rolled-back 20261119120000_companies_oauth
SET LOCAL lock_timeout = '5s';

-- CreateTable
CREATE TABLE "CompanyKybProfile" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "applicantId" TEXT NOT NULL,
    "legalName" TEXT,
    "registrationNumber" TEXT,
    "taxId" TEXT,
    "legalForm" TEXT,
    "incorporatedOn" DATE,
    "country" TEXT,
    "city" TEXT,
    "legalAddress" TEXT,
    "website" TEXT,
    "raw" JSONB NOT NULL,
    "verifiedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CompanyKybProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OAuthCompanySelection" (
    "grantId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "actAsTenantId" TEXT,
    "sharedTenantIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OAuthCompanySelection_pkey" PRIMARY KEY ("grantId")
);

-- CreateIndex
CREATE UNIQUE INDEX "CompanyKybProfile_tenantId_key" ON "CompanyKybProfile"("tenantId");

-- CreateIndex
CREATE INDEX "OAuthCompanySelection_userId_clientId_createdAt_idx" ON "OAuthCompanySelection"("userId", "clientId", "createdAt");

-- CreateIndex
CREATE INDEX "TenantMember_userId_idx" ON "TenantMember"("userId");

-- AddForeignKey
ALTER TABLE "CompanyKybProfile" ADD CONSTRAINT "CompanyKybProfile_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

