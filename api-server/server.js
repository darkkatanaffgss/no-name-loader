const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3840);
const API_SECRET = process.env.API_SECRET || 'noname-opensource-hmac-secret-change-me';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'noname-admin-secret-change-me';
const DB_PATH = path.join(__dirname, 'licenses.json');

// Sliding-window per-IP rate limiter & nonce replay cache
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 20;
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

function loadDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (_) {
    return { licenses: {} };
  }
}

function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

function signPayload(payload) {
  const canonical = JSON.stringify(payload);
  return crypto.createHmac('sha256', API_SECRET).update(canonical).digest('hex');
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
    return sendJson(res, 429, { valid: false, error: 'Too many requests. Please wait a minute.' });
  }

  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

  if (req.method === 'GET' && url.pathname === '/api/v1/health') {
    return sendJson(res, 200, { ok: true, service: 'no-name-license-api', time: Date.now() });
  }

  if (req.method === 'POST' && url.pathname === '/api/v1/auth/verify') {
    try {
      const { key, hwid, nonce } = await readBody(req);
      if (!key || !hwid || !nonce) {
        return sendJson(res, 400, { valid: false, error: 'Missing key, hwid, or nonce' });
      }
      if (!checkAndStoreNonce(String(nonce))) {
        return sendJson(res, 403, { valid: false, error: 'Replay attempt detected (duplicate nonce)' });
      }

      const cleanKey = String(key).trim().toUpperCase();
      const db = loadDb();
      const record = db.licenses[cleanKey];

      if (!record) {
        return sendJson(res, 401, { valid: false, error: 'License key not found' });
      }
      if (record.revoked) {
        return sendJson(res, 403, { valid: false, error: 'License key has been revoked' });
      }

      const expiresMs = record.expiresAt ? Date.parse(record.expiresAt) : null;
      if (expiresMs && Date.now() > expiresMs) {
        return sendJson(res, 403, { valid: false, error: 'Subscription expired' });
      }

      if (!record.hwid) {
        record.hwid = String(hwid);
        saveDb(db);
      } else if (record.hwid !== String(hwid)) {
        return sendJson(res, 403, { valid: false, error: 'HWID mismatch — key is bound to another device' });
      }

      const payload = {
        valid: true,
        username: record.username || 'User',
        tier: record.tier || 'Standard',
        expiresAt: record.expiresAt || 'Lifetime',
        products: record.products || [],
        branches: record.branches || ['Stable'],
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

  if (req.method === 'POST' && url.pathname === '/api/v1/admin/keys') {
    if (!timingSafeMatch(req.headers['x-admin-secret'], ADMIN_SECRET)) {
      return sendJson(res, 403, { ok: false, error: 'Unauthorized' });
    }

    try {
      const { action, key, username, tier, days, products, branches } = await readBody(req);
      const db = loadDb();

      if (action === 'create') {
        const newKey = (key || `NN-${crypto.randomBytes(2).toString('hex')}-${crypto.randomBytes(2).toString('hex')}-${crypto.randomBytes(2).toString('hex')}`).toUpperCase();
        const expiresAt = days === 'lifetime'
          ? null
          : new Date(Date.now() + (Number(days || 30) * 86400000)).toISOString();

        db.licenses[newKey] = {
          username: username || 'Customer',
          tier: tier || 'Pro',
          expiresAt,
          hwid: null,
          revoked: false,
          products: products || ['cs2', 'csgo', 'minecraft'],
          branches: branches || ['Stable', 'Beta', 'Nightly']
        };
        saveDb(db);
        return sendJson(res, 201, { ok: true, key: newKey, record: db.licenses[newKey] });
      }

      if (action === 'reset-hwid' && key && db.licenses[key]) {
        db.licenses[key].hwid = null;
        saveDb(db);
        return sendJson(res, 200, { ok: true, key, message: 'HWID reset' });
      }

      if (action === 'revoke' && key && db.licenses[key]) {
        db.licenses[key].revoked = true;
        saveDb(db);
        return sendJson(res, 200, { ok: true, key, message: 'License revoked' });
      }

      return sendJson(res, 400, { ok: false, error: 'Unknown admin action or key' });
    } catch (_) {
      return sendJson(res, 400, { ok: false, error: 'Invalid JSON' });
    }
  }

  sendJson(res, 404, { ok: false, error: 'Endpoint not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[no name License API] Listening on http://127.0.0.1:${PORT}`);
});
