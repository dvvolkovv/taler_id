-- Multi-device push: store FCM/VoIP push tokens per session (device), so a user
-- logged in on several devices (tablet + PC + phone) gets call/message wake-pushes
-- on ALL of them, instead of only the last device to register (single User.fcmToken).
-- Additive + nullable: safe/backwards-compatible; code reads these defensively and
-- falls back to User.fcmToken when absent (so envs without this migration don't break).
ALTER TABLE "Session" ADD COLUMN IF NOT EXISTS "fcmToken" TEXT;
ALTER TABLE "Session" ADD COLUMN IF NOT EXISTS "voipToken" TEXT;
