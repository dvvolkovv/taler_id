-- Индекс под сверку разговора с переводом: раз в 10 с на каждой app-ноде она
-- ищет открытый биллинг одной статьи (featureKey, status = 'active', startedAt).
-- Без индекса это полный проход по "AiSession" — растущей таблице всех
-- AI-функций.
--
-- Пока индекс строится, CREATE INDEX держит на "AiSession" блокировку, при
-- которой записи метеринга (раз в 10 с) ждут. Таблица небольшая, строится
-- быстро; короткий lock_timeout не даёт миграции самой встать в очередь за
-- длинной транзакцией и задержать за собой всех. Упала по таймауту — файл
-- откатится целиком, перед повтором:
--   npx prisma migrate resolve --rolled-back 20261101130000_interpreter_billing_index
SET LOCAL lock_timeout = '5s';

-- CreateIndex
CREATE INDEX "AiSession_featureKey_status_startedAt_idx" ON "AiSession"("featureKey", "status", "startedAt");
