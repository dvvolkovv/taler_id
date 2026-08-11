-- CreateIndex
-- Просмотры постов канала и список прочитавших в группе выводятся из курсоров
-- чтения. Без этого индекса каждый такой вопрос — полный проход по участникам,
-- а у системного канала их больше двенадцати тысяч.
CREATE INDEX "ConversationParticipant_conversationId_lastReadAt_idx"
  ON "ConversationParticipant"("conversationId", "lastReadAt");
