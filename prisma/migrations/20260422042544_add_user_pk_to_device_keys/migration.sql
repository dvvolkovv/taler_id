-- AlterTable
ALTER TABLE "DeviceKey" ADD COLUMN "userPk" TEXT;

-- CreateIndex
CREATE INDEX "DeviceKey_userPk_idx" ON "DeviceKey"("userPk");
