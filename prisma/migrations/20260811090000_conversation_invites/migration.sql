-- AlterTable
ALTER TABLE "Conversation" ADD COLUMN "publicUsername" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Conversation_publicUsername_key" ON "Conversation"("publicUsername");

-- CreateTable
CREATE TABLE "ConversationInvite" (
    "id" TEXT NOT NULL,
    "conversationId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "maxUses" INTEGER,
    "uses" INTEGER NOT NULL DEFAULT 0,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "ConversationInvite_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ConversationInvite_code_key" ON "ConversationInvite"("code");
CREATE INDEX "ConversationInvite_conversationId_idx" ON "ConversationInvite"("conversationId");

-- AddForeignKey
-- Cascade: удалили беседу — ссылки на неё смысла не имеют.
ALTER TABLE "ConversationInvite" ADD CONSTRAINT "ConversationInvite_conversationId_fkey"
  FOREIGN KEY ("conversationId") REFERENCES "Conversation"("id") ON DELETE CASCADE ON UPDATE CASCADE;
