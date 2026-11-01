'use strict';
/**
 * The interpreter's HTTP surface on the agent port (:3100). Only the backend
 * calls it, with INTERPRETER_SHARED_SECRET in x-interpreter-secret: start
 * carries both people's voice prints, and on some hosts the port is reachable
 * from more than localhost.
 */
const crypto = require('crypto');

function sameSecret(given, expected) {
  const a = Buffer.from(String(given));
  const b = Buffer.from(String(expected));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function registerInterpreterRoutes(app, { secret, start, stop, status, selftest }) {
  const guard = (req, res, next) => {
    if (!secret) return res.status(503).json({ error: 'INTERPRETER_SHARED_SECRET is not set on the agent' });
    if (!sameSecret(req.get('x-interpreter-secret') || '', secret)) return res.status(401).json({ error: 'unauthorized' });
    return next();
  };

  app.post('/interpreter/start', guard, async (req, res) => {
    try {
      res.json(await start(req.body || {}));
    } catch (e) {
      console.error('[INTERPRETER] start failed:', e.message);
      res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  app.post('/interpreter/stop', guard, async (req, res) => {
    const { roomName } = req.body || {};
    if (!roomName) return res.status(400).json({ error: 'roomName required' });
    try {
      return res.json(await stop(roomName));
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  app.get('/interpreter/status/:roomName', guard, (req, res) => {
    // Uncaught, a throw here would reach Express's default handler: an HTML
    // page with the stack trace instead of JSON.
    try {
      res.json(status(req.params.roomName));
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/interpreter/selftest', guard, async (req, res) => {
    const t0 = Date.now();
    try {
      const result = await selftest();
      res.json({ ...result, latencyMs: Date.now() - t0 });
    } catch (e) {
      res.status(500).json({ ok: false, reason: e.message, latencyMs: Date.now() - t0 });
    }
  });
}

module.exports = { registerInterpreterRoutes };
