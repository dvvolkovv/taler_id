-- AlterTable
-- Состояние списка чатов переезжает из локального Hive на сервер: черновик,
-- архив и закрепление беседы принадлежат участнику, а не устройству.
ALTER TABLE "ConversationParticipant" ADD COLUMN "draft" TEXT;
ALTER TABLE "ConversationParticipant" ADD COLUMN "draftAt" TIMESTAMP(3);
ALTER TABLE "ConversationParticipant" ADD COLUMN "archivedAt" TIMESTAMP(3);
ALTER TABLE "ConversationParticipant" ADD COLUMN "chatPinnedAt" TIMESTAMP(3);

-- CreateIndex
-- Частичный: закреплённых чатов у человека единицы, а строк в таблице —
-- по одной на каждое участие. Обычная вставка участника индекс не трогает.
CREATE INDEX "ConversationParticipant_userId_chatPinnedAt_idx"
  ON "ConversationParticipant"("userId", "chatPinnedAt") WHERE "chatPinnedAt" IS NOT NULL;
