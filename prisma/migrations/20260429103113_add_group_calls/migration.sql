-- CreateEnum
CREATE TYPE "GroupCallStatus" AS ENUM ('LOBBY', 'ACTIVE', 'ENDED');

-- CreateEnum
CREATE TYPE "GroupCallInviteStatus" AS ENUM ('CALLING', 'JOINED', 'DECLINED', 'TIMEOUT', 'LEFT');

-- CreateTable
CREATE TABLE "GroupCall" (
    "id" TEXT NOT NULL,
    "livekitRoomName" TEXT NOT NULL,
    "hostUserId" TEXT NOT NULL,
    "status" "GroupCallStatus" NOT NULL DEFAULT 'LOBBY',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "endedReason" TEXT,

    CONSTRAINT "GroupCall_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GroupCallInvite" (
    "id" TEXT NOT NULL,
    "groupCallId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "GroupCallInviteStatus" NOT NULL DEFAULT 'CALLING',
    "invitedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "respondedAt" TIMESTAMP(3),
    "joinedAt" TIMESTAMP(3),
    "leftAt" TIMESTAMP(3),
    "invitedBy" TEXT NOT NULL,

    CONSTRAINT "GroupCallInvite_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "GroupCall_livekitRoomName_key" ON "GroupCall"("livekitRoomName");

-- CreateIndex
CREATE INDEX "GroupCall_status_startedAt_idx" ON "GroupCall"("status", "startedAt");

-- CreateIndex
CREATE INDEX "GroupCall_hostUserId_startedAt_idx" ON "GroupCall"("hostUserId", "startedAt");

-- CreateIndex
CREATE INDEX "GroupCallInvite_userId_status_idx" ON "GroupCallInvite"("userId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "GroupCallInvite_groupCallId_userId_key" ON "GroupCallInvite"("groupCallId", "userId");

-- AddForeignKey
ALTER TABLE "GroupCall" ADD CONSTRAINT "GroupCall_hostUserId_fkey" FOREIGN KEY ("hostUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupCallInvite" ADD CONSTRAINT "GroupCallInvite_groupCallId_fkey" FOREIGN KEY ("groupCallId") REFERENCES "GroupCall"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GroupCallInvite" ADD CONSTRAINT "GroupCallInvite_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

