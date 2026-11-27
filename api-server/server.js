const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { runSetup } = require('../scripts/setup-keys');
const db = require('./db');

// Load .env cleanly (auto-generate unique keys if missing — zero hardcoded secrets!)
const ENV_PATH = path.join(__dirname, '.env');
if (!fs.existsSync(ENV_PATH)) {
  const generated = runSetup({ force: false });
  if (!generated.skipped) {
    console.log('[Server] Generated fresh Ed25519 keys & ADMIN_SECRET in api-server/.env');
    console.log(`[Server] Your ADMIN_SECRET: ${generated.adminSecret}`);
  }
}

function loadEnvFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const k = trimmed.slice(0, eq).trim();
    const v = trimmed.slice(eq + 1).trim();
    if (!process.env[k]) {
      process.env[k] = v;
    }
  }
}
loadEnvFile(ENV_PATH);

const PORT = Number(process.env.PORT || 3840);
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const PRIVATE_KEY_B64 = process.env.ED25519_PRIVATE_KEY;

if (!ADMIN_SECRET || !PRIVATE_KEY_B64) {
  console.error('[Server] Fatal: ADMIN_SECRET or ED25519_PRIVATE_KEY missing in api-server/.env. Run `npm run setup`.');
  process.exit(1);
}

const PRIVATE_KEY_PEM = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8');

// Rate limiter & replay nonce cache
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 30;
const NONCE_TTL_MS = 120_000;
const rateBuckets = new Map();
const seenNonces = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const bucket = (rateBuckets.get(ip) || []).filter((ts) => now - ts < RATE_WINDOW_MS);
  bucket.push(now);
  rateBuckets.set(ip, bucket);
  return bucket.length > RATE_MAX_REQUESTS;
}

function checkAndStoreNonce(nonce) {
  const now = Date.now();
  for (const [k, exp] of seenNonces.entries()) {
    if (exp < now) seenNonces.delete(k);
  }
  if (seenNonces.has(nonce)) return false;
  seenNonces.set(nonce, now + NONCE_TTL_MS);
  return true;
}

function timingSafeMatch(input, expected) {
  const a = Buffer.from(String(input || ''), 'utf8');
  const b = Buffer.from(String(expected || ''), 'utf8');
  if (a.length !== b.length || a.length === 0) return false;
  return crypto.timingSafeEqual(a, b);
}

// Sign response payload using Ed25519 Private Key (only backend has this key!)
function signPayload(payload) {
  const canonical = JSON.stringify(payload);
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), PRIVATE_KEY_PEM).toString('hex');
}

function sendJson(res, statusCode, body) {
  const json = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 65536) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const clientIp = req.socket.remoteAddress || 'unknown';
  if (isRateLimited(clientIp)) {
    return sendJson(res, 429, { valid: false, error: 'Rate limit exceeded. Wait 1 minute.' });
  }

  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

  // Serve Admin Dashboard HTML
  if (req.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
    const html = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });
    return res.end(html);
  }

  if (req.method === 'GET' && url.pathname === '/api/v1/health') {
    return sendJson(res, 200, { ok: true, service: 'no-name-license-api', db: 'sqlite', crypto: 'ed25519', time: Date.now() });
  }

  // 1. Authenticate license key + bind HWID + issue server-side session
  if (req.method === 'POST' && url.pathname === '/api/v1/auth/verify') {
    try {
      const { key, hwid, nonce } = await readBody(req);
      if (!key || !hwid || !nonce) {
        return sendJson(res, 400, { valid: false, error: 'Missing key, hwid, or nonce' });
      }
      if (!checkAndStoreNonce(String(nonce))) {
        db.logEvent({ eventType: 'replay_detected', key: String(key), hwid: String(hwid), ip: clientIp, details: 'Duplicate nonce' });
        return sendJson(res, 403, { valid: false, error: 'Replay attempt detected' });
      }

      const cleanKey = String(key).trim().toUpperCase();
      const record = db.getLicense(cleanKey);

      if (!record) {
        db.logEvent({ eventType: 'login_failed', key: cleanKey, hwid: String(hwid), ip: clientIp, details: 'Key not found' });
        return sendJson(res, 401, { valid: false, error: 'License key not found' });
      }
      if (record.revoked) {
        db.logEvent({ eventType: 'login_failed', key: cleanKey, hwid: String(hwid), ip: clientIp, details: 'Revoked key' });
        return sendJson(res, 403, { valid: false, error: 'License key has been revoked' });
      }

      const expiresMs = record.expiresAt ? Date.parse(record.expiresAt) : null;
      if (expiresMs && Date.now() > expiresMs) {
        db.logEvent({ eventType: 'login_failed', key: cleanKey, hwid: String(hwid), ip: clientIp, details: 'Expired subscription' });
        return sendJson(res, 403, { valid: false, error: 'Subscription expired' });
      }

      if (record.hwid && record.hwid !== String(hwid)) {
        db.logEvent({ eventType: 'hwid_mismatch', key: cleanKey, hwid: String(hwid), ip: clientIp, details: `Expected ${record.hwid.slice(0, 8)}...` });
        return sendJson(res, 403, { valid: false, error: 'HWID mismatch — key is bound to another device' });
      }

      db.bindHwidAndTouch(cleanKey, String(hwid));
      const session = db.createSession(cleanKey, String(hwid));
      db.logEvent({ eventType: 'login_success', key: cleanKey, hwid: String(hwid), ip: clientIp, details: `Tier: ${record.tier}` });

      const payload = {
        valid: true,
        sessionId: session.sessionId,
        username: record.username,
        tier: record.tier,
        expiresAt: record.expiresAt || 'Lifetime',
        products: record.products,
        branches: record.branches,
        hwid: String(hwid),
        nonce: String(nonce),
        issuedAt: Date.now()
      };

      const signature = signPayload(payload);
      return sendJson(res, 200, { payload, signature });
    } catch (_) {
      return sendJson(res, 400, { valid: false, error: 'Invalid request body' });
    }
  }

  // 2. Server-side Launch Authorization (every Launch calls backend + logs analytics!)
  if (req.method === 'POST' && url.pathname === '/api/v1/software/authorize') {
    try {
      const { sessionId, hwid, productId, branch, nonce } = await readBody(req);
      if (!sessionId || !hwid || !productId || !branch || !nonce) {
        return sendJson(res, 400, { ok: false, error: 'Missing authorization parameters' });
      }
      if (!checkAndStoreNonce(String(nonce))) {
        db.logEvent({ eventType: 'replay_detected', hwid: String(hwid), ip: clientIp, details: 'Launch nonce replay' });
        return sendJson(res, 403, { ok: false, error: 'Replay attempt detected' });
      }

      const sessionRow = db.getValidSession(String(sessionId), String(hwid));
      if (!sessionRow) {
        return sendJson(res, 401, { ok: false, error: 'Session expired or invalid HWID. Please sign in again.' });
      }

      const record = db.getLicense(sessionRow.license_key);
      if (!record || record.revoked) {
        return sendJson(res, 403, { ok: false, error: 'License revoked' });
      }
      const expiresMs = record.expiresAt ? Date.parse(record.expiresAt) : null;
      if (expiresMs && Date.now() > expiresMs) {
        return sendJson(res, 403, { ok: false, error: 'Subscription expired' });
      }
      if (!record.products.includes(productId)) {
        return sendJson(res, 403, { ok: false, error: `Tier (${record.tier}) does not include ${productId}` });
      }
      if (!record.branches.includes(branch)) {
        return sendJson(res, 403, { ok: false, error: `Branch "${branch}" requires a higher tier` });
      }

      db.incrementLaunchCount(record.key);
      db.logEvent({
        eventType: 'launch_authorized',
        key: record.key,
        hwid: String(hwid),
        ip: clientIp,
        productId: String(productId),
        branch: String(branch),
        details: 'Launch ticket issued'
      });

      const payload = {
        authorized: true,
        productId: String(productId),
        branch: String(branch),
        hwid: String(hwid),
        nonce: String(nonce),
        ticketExpiresAt: Date.now() + 30_000,
        issuedAt: Date.now()
      };
      const signature = signPayload(payload);
      return sendJson(res, 200, { payload, signature });
    } catch (_) {
      return sendJson(res, 400, { ok: false, error: 'Invalid request body' });
    }
  }

  // 3. Security / Anti-Tamper Telemetry Endpoint
  if (req.method === 'POST' && url.pathname === '/api/v1/telemetry') {
    try {
      const { eventType, hwid, key, details } = await readBody(req);
      db.logEvent({
        eventType: String(eventType || 'anti_tamper_alert'),
        key: key ? String(key) : null,
        hwid: hwid ? String(hwid) : null,
        ip: clientIp,
        details: String(details || 'Client security event').slice(0, 200)
      });
      return sendJson(res, 200, { ok: true });
    } catch (_) {
      return sendJson(res, 400, { ok: false });
    }
  }

  // 4. Admin API Endpoints (protected by ADMIN_SECRET)
  if (url.pathname.startsWith('/api/v1/admin/')) {
    if (!timingSafeMatch(req.headers['x-admin-secret'], ADMIN_SECRET)) {
      return sendJson(res, 403, { ok: false, error: 'Unauthorized: invalid x-admin-secret' });
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/admin/analytics') {
      return sendJson(res, 200, {
        ok: true,
        ...db.getAnalyticsSummary(),
        licenses: db.listLicenses()
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/keys') {
      try {
        const { action, key, username, tier, days, products, branches } = await readBody(req);

        if (action === 'create') {
          const expiresAt = days === 'lifetime'
            ? null
            : new Date(Date.now() + (Number(days || 30) * 86400000)).toISOString();

          const created = db.createLicense({ key, username, tier, expiresAt, products, branches });
          db.logEvent({ eventType: 'key_created', key: created.key, ip: clientIp, details: `Tier: ${created.tier}` });
          return sendJson(res, 201, { ok: true, key: created.key, record: created });
        }

        if (action === 'reset-hwid' && key) {
          const updated = db.resetLicenseHwid(key);
          if (!updated) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          db.logEvent({ eventType: 'hwid_reset', key, ip: clientIp, details: 'Admin reset HWID' });
          return sendJson(res, 200, { ok: true, key, message: 'HWID reset' });
        }

        if (action === 'revoke' && key) {
          const updated = db.setLicenseRevoked(key, true);
          if (!updated) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          db.logEvent({ eventType: 'key_revoked', key, ip: clientIp, details: 'Admin revoked key' });
          return sendJson(res, 200, { ok: true, key, message: 'Key revoked' });
        }

        if (action === 'unrevoke' && key) {
          const updated = db.setLicenseRevoked(key, false);
          if (!updated) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          return sendJson(res, 200, { ok: true, key, message: 'Key restored' });
        }

        if (action === 'delete' && key) {
          const deleted = db.deleteLicense(key);
          if (!deleted) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          return sendJson(res, 200, { ok: true, key, message: 'Key deleted' });
        }

        return sendJson(res, 400, { ok: false, error: 'Unknown admin action' });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: err.message || 'Invalid JSON' });
      }
    }
  }

  sendJson(res, 404, { ok: false, error: 'Endpoint not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[no name License API] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[no name Admin Panel] Open http://127.0.0.1:${PORT}/admin`);
});
