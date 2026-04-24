-- CreateEnum
CREATE TYPE "TxType" AS ENUM ('TOPUP_STUB', 'TOPUP_ONCHAIN', 'SPEND', 'REFUND', 'ADMIN_CREDIT', 'ADMIN_DEBIT', 'WITHDRAW');

-- CreateEnum
CREATE TYPE "TxStatus" AS ENUM ('PENDING', 'COMPLETED', 'FAILED', 'REVERSED');

-- CreateTable
CREATE TABLE "AiPricebook" (
    "id" TEXT NOT NULL,
    "featureKey" TEXT NOT NULL,
    "unit" TEXT NOT NULL,
    "costUsdPerUnit" DECIMAL(12,8) NOT NULL,
    "markupMultiplier" DECIMAL(4,2) NOT NULL DEFAULT 2.0,
    "minReservePlanck" BIGINT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiPricebook_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BillingConfig" (
    "id" TEXT NOT NULL DEFAULT 'singleton',
    "talUsdRate" DECIMAL(14,4) NOT NULL,
    "billingEnforced" BOOLEAN NOT NULL DEFAULT false,
    "welcomeBonusPlanck" BIGINT NOT NULL DEFAULT 50000000,
    "lastSeenBlock" INTEGER,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BillingConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserWallet" (
    "userId" TEXT NOT NULL,
    "custodialAddress" TEXT NOT NULL,
    "custodialKeyEnc" TEXT NOT NULL,
    "balancePlanck" BIGINT NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserWallet_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "BillingTransaction" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "TxType" NOT NULL,
    "status" "TxStatus" NOT NULL DEFAULT 'COMPLETED',
    "amountPlanck" BIGINT NOT NULL,
    "featureKey" TEXT,
    "sessionId" UUID,
    "chainTxHash" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BillingTransaction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiSession" (
    "id" UUID NOT NULL,
    "userId" TEXT NOT NULL,
    "featureKey" TEXT NOT NULL,
    "contextRef" TEXT,
    "status" TEXT NOT NULL DEFAULT 'active',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastMeteredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "totalSpentPlanck" BIGINT NOT NULL DEFAULT 0,
    "metadata" JSONB,

    CONSTRAINT "AiSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserFeatureToggle" (
    "userId" TEXT NOT NULL,
    "featureKey" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserFeatureToggle_pkey" PRIMARY KEY ("userId","featureKey")
);

-- CreateTable
CREATE TABLE "UsageLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" UUID,
    "featureKey" TEXT NOT NULL,
    "unit" TEXT NOT NULL,
    "units" DECIMAL(14,4) NOT NULL,
    "reporter" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UsageLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AiPricebook_featureKey_key" ON "AiPricebook"("featureKey");

-- CreateIndex
CREATE UNIQUE INDEX "UserWallet_custodialAddress_key" ON "UserWallet"("custodialAddress");

-- CreateIndex
CREATE INDEX "BillingTransaction_userId_createdAt_idx" ON "BillingTransaction"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "BillingTransaction_sessionId_idx" ON "BillingTransaction"("sessionId");

-- CreateIndex
CREATE INDEX "AiSession_userId_status_idx" ON "AiSession"("userId", "status");

-- CreateIndex
CREATE INDEX "AiSession_contextRef_idx" ON "AiSession"("contextRef");

-- CreateIndex
CREATE INDEX "UsageLog_userId_createdAt_idx" ON "UsageLog"("userId", "createdAt");

-- AddForeignKey
ALTER TABLE "UserWallet" ADD CONSTRAINT "UserWallet_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BillingTransaction" ADD CONSTRAINT "BillingTransaction_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BillingTransaction" ADD CONSTRAINT "BillingTransaction_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "AiSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AiSession" ADD CONSTRAINT "AiSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UsageLog" ADD CONSTRAINT "UsageLog_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "AiSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Enforce BillingConfig singleton invariant at the DB level.
ALTER TABLE "BillingConfig" ADD CONSTRAINT "BillingConfig_singleton_check" CHECK (id = 'singleton');

-- Seed pricebook (costs in USD, planck = 10⁻¹² TAL)
-- At rate 1 TAL = $11,700, voice_assistant post-markup = $0.15 × 2.0 = $0.30/min
-- ≈ 25.6M planck/min. minReservePlanck sized per-feature:
--   voice_assistant / ai_twin: ~60s reserve
--   outbound_call:             ~60s reserve (at higher $0.40/min post-markup)
--   web_search:                ~1 request ahead
--   whisper_transcribe:        ~5 min typical call recording length
--   meeting_summary:           ~2K tokens typical one-shot summary
INSERT INTO "AiPricebook" (id, "featureKey", unit, "costUsdPerUnit", "markupMultiplier", "minReservePlanck", "updatedAt") VALUES
  ('pb_voice_assistant',    'voice_assistant',    'minute',    0.15,  2.0, 26000000, NOW()),
  ('pb_web_search',         'web_search',         'request',   0.005, 2.0,  1000000, NOW()),
  ('pb_ai_twin',            'ai_twin',            'minute',    0.15,  2.0, 26000000, NOW()),
  ('pb_outbound_call',      'outbound_call',      'minute',    0.20,  2.0, 35000000, NOW()),
  ('pb_whisper_transcribe', 'whisper_transcribe', 'minute',    0.006, 2.0,  5000000, NOW()),
  ('pb_meeting_summary',    'meeting_summary',    '1k_tokens', 0.01,  2.0,  4000000, NOW());

-- Singleton config row
INSERT INTO "BillingConfig" (id, "talUsdRate", "billingEnforced", "welcomeBonusPlanck", "updatedAt")
  VALUES ('singleton', 11700, false, 50000000, NOW());
