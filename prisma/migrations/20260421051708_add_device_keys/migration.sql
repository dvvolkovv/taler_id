-- CreateTable
CREATE TABLE "DeviceKey" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "devicePk" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'X25519',
    "validUntil" TIMESTAMP(3) NOT NULL,
    "certificate" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DeviceKey_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DeviceKey_devicePk_key" ON "DeviceKey"("devicePk");

-- CreateIndex
CREATE INDEX "DeviceKey_userId_idx" ON "DeviceKey"("userId");

-- CreateIndex
CREATE INDEX "DeviceKey_userId_revokedAt_idx" ON "DeviceKey"("userId", "revokedAt");

-- AddForeignKey
ALTER TABLE "DeviceKey" ADD CONSTRAINT "DeviceKey_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
