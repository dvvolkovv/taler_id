'use strict';
/**
 * Tells the backend that an interpreter session ended on the agent's side
 * (someone stayed away, the translation could not be restored, the agent lost
 * LiveKit), so it can close billing and the room. Never throws: the backend
 * also reconciles on its own, and the agent must finish stopping either way.
 *
 * One retry after a network error or a 5xx. Without it a callback lost to a
 * backend restart (a plain `pm2 restart` on DEV and TEST) is noticed only by
 * the backend's reconciliation, up to a minute later and as `agent_lost`, and
 * the host pays for that minute. A 4xx is not retried: it will not change.
 * The backend's handler is idempotent, so a retry after a lost answer is safe.
 */
async function attempt({ url, secret, reason, sessionId, fetchFn, timeoutMs, log }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-interpreter-secret': secret },
      body: JSON.stringify({ reason }),
      signal: controller.signal,
    });
    // fetch resolves on the headers. Unread, a body that stalls after them
    // would hold the socket open long after the timer below is cleared.
    if (res.body && typeof res.body.cancel === 'function') res.body.cancel().catch(() => {});
    if (!res.ok) log.warn(`[INTERPRETER] agent-ended for ${sessionId}: HTTP ${res.status}`);
    return { ok: res.ok, status: res.status };
  } catch (e) {
    log.warn(`[INTERPRETER] agent-ended for ${sessionId} failed: ${e && e.message}`);
    return { ok: false, status: 0 };
  } finally {
    clearTimeout(timer);
  }
}

async function notifyAgentEnded({
  backendUrl,
  secret,
  sessionId,
  reason,
  fetchFn = fetch,
  timeoutMs = 5000,
  retries = 1,
  retryDelayMs = 1500,
  setTimer = setTimeout,
  log = console,
}) {
  const url = `${String(backendUrl).replace(/\/+$/, '')}/interpreter/internal/sessions/${encodeURIComponent(sessionId)}/agent-ended`;
  for (let tries = 0; ; tries++) {
    const outcome = await attempt({ url, secret, reason, sessionId, fetchFn, timeoutMs, log });
    const transient = !outcome.ok && (outcome.status === 0 || outcome.status >= 500);
    if (!transient || tries >= retries) return outcome;
    log.warn(`[INTERPRETER] agent-ended for ${sessionId}: retrying in ${retryDelayMs} ms`);
    await new Promise((resolve) => setTimer(resolve, retryDelayMs));
  }
}

module.exports = { notifyAgentEnded };
