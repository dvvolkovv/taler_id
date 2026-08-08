-- AlterTable
ALTER TABLE "Message" ADD COLUMN "pinnedAt" TIMESTAMP(3);
ALTER TABLE "Message" ADD COLUMN "pinnedById" TEXT;

-- CreateIndex
-- Частичный: pinnedAt заполнен у ничтожной доли строк, а Message — самая
-- горячая на запись таблица. Вставка сообщения (pinnedAt = NULL) индекс не
-- трогает вовсе; его касается только редкий UPDATE при закрепе.
CREATE INDEX "Message_conversationId_pinnedAt_idx" ON "Message"("conversationId", "pinnedAt") WHERE "pinnedAt" IS NOT NULL;

-- AlterTable
ALTER TABLE "ConversationParticipant" ADD COLUMN "pinsDismissedAt" TIMESTAMP(3);
