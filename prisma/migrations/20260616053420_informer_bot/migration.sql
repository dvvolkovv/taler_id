-- AlterEnum: add AI_INFORMER to ConvType
ALTER TYPE "ConvType" ADD VALUE IF NOT EXISTS 'AI_INFORMER';

-- AlterTable: add informerAccess flag on Profile
ALTER TABLE "Profile" ADD COLUMN "informerAccess" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable: InformerSeenWallet
CREATE TABLE "InformerSeenWallet" (
    "id" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "network" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "amount" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "notifiedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "InformerSeenWallet_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "InformerSeenWallet_address_network_token_key" ON "InformerSeenWallet"("address", "network", "token");

-- CreateIndex
CREATE INDEX "InformerSeenWallet_firstSeenAt_idx" ON "InformerSeenWallet"("firstSeenAt");
