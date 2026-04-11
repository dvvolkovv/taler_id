-- AlterTable
ALTER TABLE "Profile" ADD COLUMN "aiTwinEnabled" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Profile" ADD COLUMN "aiTwinTimeoutSeconds" INTEGER NOT NULL DEFAULT 30;
ALTER TABLE "Profile" ADD COLUMN "aiTwinPrompt" TEXT;
ALTER TABLE "Profile" ADD COLUMN "aiTwinVoiceId" TEXT;
