-- CreateEnum
CREATE TYPE "GroupRole" AS ENUM ('OWNER', 'ADMIN', 'MEMBER');

-- AlterTable: Conversation
ALTER TABLE "Conversation" ADD COLUMN "name" TEXT;
ALTER TABLE "Conversation" ADD COLUMN "avatarUrl" TEXT;
ALTER TABLE "Conversation" ADD COLUMN "createdById" TEXT;
ALTER TABLE "Conversation" ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- AlterTable: ConversationParticipant
ALTER TABLE "ConversationParticipant" ADD COLUMN "role" "GroupRole" NOT NULL DEFAULT 'MEMBER';
ALTER TABLE "ConversationParticipant" ADD COLUMN "joinedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- AlterTable: Message
ALTER TABLE "Message" ADD COLUMN "isSystem" BOOLEAN NOT NULL DEFAULT false;
