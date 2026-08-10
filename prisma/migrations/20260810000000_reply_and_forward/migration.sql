-- AlterTable
ALTER TABLE "Message" ADD COLUMN "replyToId" TEXT;
ALTER TABLE "Message" ADD COLUMN "forwardedFromUserId" TEXT;
ALTER TABLE "Message" ADD COLUMN "forwardedFromName" TEXT;
ALTER TABLE "Message" ADD COLUMN "forwardedFromMessageId" TEXT;

-- CreateIndex
-- Частичный по той же причине, что и индекс закреплений: replyToId заполнен у
-- меньшинства строк, а Message — самая горячая на запись таблица. Обычная
-- вставка (replyToId = NULL) индекс не трогает.
CREATE INDEX "Message_replyToId_idx" ON "Message"("replyToId") WHERE "replyToId" IS NOT NULL;

-- AddForeignKey
-- ON DELETE SET NULL: жёсткое удаление оригинала не должно уносить ответы на
-- него. Мягкое удаление (deletedAt) строку оставляет, и цитата рисуется как
-- «Сообщение удалено».
ALTER TABLE "Message" ADD CONSTRAINT "Message_replyToId_fkey"
  FOREIGN KEY ("replyToId") REFERENCES "Message"("id") ON DELETE SET NULL ON UPDATE CASCADE;
