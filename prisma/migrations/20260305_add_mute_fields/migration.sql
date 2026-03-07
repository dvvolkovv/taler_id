-- AlterTable
ALTER TABLE "ConversationParticipant" ADD COLUMN "isMuted" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "ConversationParticipant" ADD COLUMN "mutedUntil" TIMESTAMP(3);
