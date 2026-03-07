CREATE TABLE "PublicRoom" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "roomName" TEXT NOT NULL,
    "creatorId" TEXT,
    "title" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT "PublicRoom_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "PublicRoom_code_key" ON "PublicRoom"("code");
