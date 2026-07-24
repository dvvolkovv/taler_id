-- AlterTable
ALTER TABLE "OAuthClient" ADD COLUMN     "verifiedPartner" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isDynamic" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "dcrMetadata" JSONB;
