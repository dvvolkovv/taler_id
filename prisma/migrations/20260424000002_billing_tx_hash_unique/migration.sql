-- Ensures DepositWatcher can't double-credit on replay / reconnect.
CREATE UNIQUE INDEX "BillingTransaction_chainTxHash_key" ON "BillingTransaction"("chainTxHash");
