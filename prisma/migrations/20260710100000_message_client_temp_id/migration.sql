-- Durable client-side idempotency for message sends: the Redis dedup key
-- expires after 24h, but broken client outboxes retry for weeks.
ALTER TABLE "Message" ADD COLUMN "clientTempId" TEXT;
CREATE UNIQUE INDEX "Message_senderId_clientTempId_key" ON "Message"("senderId", "clientTempId");
