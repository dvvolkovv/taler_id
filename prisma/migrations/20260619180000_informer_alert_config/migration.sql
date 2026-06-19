-- Informer V2 / Sub-3 — per-user refill alerter control and escalation state.
-- One row per user, created lazily on first config mutation or first digest send.
-- Cascade delete with User so cleaning up a user purges the config automatically.
CREATE TABLE "InformerAlertConfig" (
    "userId"          TEXT      NOT NULL,
    "enabled"         BOOLEAN   NOT NULL DEFAULT true,
    "snoozedUntil"    TIMESTAMP(3),
    "lastDigestStage" INTEGER   NOT NULL DEFAULT 0,
    "lastDigestAt"    TIMESTAMP(3),
    "createdAt"       TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"       TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InformerAlertConfig_pkey" PRIMARY KEY ("userId")
);

CREATE INDEX "InformerAlertConfig_snoozedUntil_idx" ON "InformerAlertConfig"("snoozedUntil");
CREATE INDEX "InformerAlertConfig_enabled_snoozedUntil_idx" ON "InformerAlertConfig"("enabled", "snoozedUntil");

ALTER TABLE "InformerAlertConfig"
    ADD CONSTRAINT "InformerAlertConfig_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "User"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
