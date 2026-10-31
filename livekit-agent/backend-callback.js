'use strict';
/**
 * Tells the backend that an interpreter session ended on the agent's side
 * (someone stayed away, the translation could not be restored, the agent lost
 * LiveKit), so it can close billing and the room. Never throws: the backend
 * also reconciles on its own, and the agent must finish stopping either way.
 */
async function notifyAgentEnded({ backendUrl, secret, sessionId, reason, fetchFn = fetch, timeoutMs = 5000, log = console }) {
  const url = `${String(backendUrl).replace(/\/+$/, '')}/interpreter/internal/sessions/${encodeURIComponent(sessionId)}/agent-ended`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-interpreter-secret': secret },
      body: JSON.stringify({ reason }),
      signal: controller.signal,
    });
    if (!res.ok) log.warn(`[INTERPRETER] agent-ended for ${sessionId}: HTTP ${res.status}`);
    return { ok: res.ok, status: res.status };
  } catch (e) {
    log.warn(`[INTERPRETER] agent-ended for ${sessionId} failed: ${e.message}`);
    return { ok: false, status: 0 };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { notifyAgentEnded };
