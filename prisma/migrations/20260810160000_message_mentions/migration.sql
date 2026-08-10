-- AlterTable
ALTER TABLE "Message" ADD COLUMN "mentionedUserIds" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- CreateIndex
-- GIN: единственный вопрос к этой колонке — «упомянут ли такой-то», то есть
-- проверка вхождения в массив. B-tree на массиве для этого бесполезен.
CREATE INDEX "Message_mentionedUserIds_idx" ON "Message" USING GIN ("mentionedUserIds");
