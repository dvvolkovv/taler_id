-- CreateTable
CREATE TABLE "LinkPreview" (
    "url" TEXT NOT NULL,
    "title" TEXT,
    "description" TEXT,
    "imageUrl" TEXT,
    "siteName" TEXT,
    "ok" BOOLEAN NOT NULL DEFAULT true,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LinkPreview_pkey" PRIMARY KEY ("url")
);

-- CreateIndex
-- По времени выборки чистят протухшее; отдельного поиска по нему нет.
CREATE INDEX "LinkPreview_fetchedAt_idx" ON "LinkPreview"("fetchedAt");
