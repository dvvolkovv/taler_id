-- CreateTable
CREATE TABLE "ScheduledMessage" (
    "id" TEXT NOT NULL,
    "conversationId" TEXT NOT NULL,
    "senderId" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "sendAt" TIMESTAMP(3) NOT NULL,
    "fileUrl" TEXT,
    "fileName" TEXT,
    "fileSize" INTEGER,
    "fileType" TEXT,
    "s3Key" TEXT,
    "topicId" TEXT,
    "replyToId" TEXT,
    "silent" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sentAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),
    "lastError" TEXT,

    CONSTRAINT "ScheduledMessage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
-- Планировщик спрашивает ровно одно: что уже пора и ещё не отправлено.
CREATE INDEX "ScheduledMessage_sendAt_sentAt_idx" ON "ScheduledMessage"("sendAt", "sentAt");
CREATE INDEX "ScheduledMessage_senderId_idx" ON "ScheduledMessage"("senderId");
