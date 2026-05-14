-- CreateEnum
CREATE TYPE "LastSeenPrivacy" AS ENUM ('EVERYONE', 'CONTACTS', 'NOBODY');

-- AlterTable
ALTER TABLE "Profile" ADD COLUMN "lastSeenAt" TIMESTAMP(3),
ADD COLUMN "lastSeenPrivacy" "LastSeenPrivacy" NOT NULL DEFAULT 'EVERYONE';
