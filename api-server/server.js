const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { runSetup } = require('../scripts/setup-keys');
const db = require('./db');

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
  console.error('[Server] Fatal: ADMIN_SECRET or ED25519_PRIVATE_KEY missing in api-server/.env.');
  process.exit(1);
}

const PRIVATE_KEY_PEM = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8');
// Pre-hash ADMIN_SECRET with SHA-512 so comparison always operates on fixed 64-byte digests
const ADMIN_DIGEST = crypto.createHash('sha512').update(ADMIN_SECRET, 'utf8').digest();

// Rate limiter, nonce replay cache, admin brute-force lockout & ephemeral admin sessions
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 35;
const NONCE_TTL_MS = 120_000;
const ADMIN_FAIL_LIMIT = 5;
const ADMIN_LOCK_MS = 15 * 60_000;
const ADMIN_SESSION_TTL_MS = 30 * 60_000;

const rateBuckets = new Map();
const seenNonces = new Map();
const adminFailures = new Map(); // ip -> { count, lockedUntil }
const adminSessions = new Map(); // token -> { ip, uaHash, expiresAt }

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

function verifyAdminSecret(inputSecret) {
  const inputDigest = crypto.createHash('sha512').update(String(inputSecret || ''), 'utf8').digest();
  return crypto.timingSafeEqual(inputDigest, ADMIN_DIGEST);
}

function isAdminIpLocked(ip) {
  const entry = adminFailures.get(ip);
  if (!entry) return false;
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    return true;
  }
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
    adminFailures.delete(ip);
  }
  return false;
}

function recordAdminFailure(ip) {
  const entry = adminFailures.get(ip) || { count: 0, lockedUntil: 0 };
  entry.count += 1;
  if (entry.count >= ADMIN_FAIL_LIMIT) {
    entry.lockedUntil = Date.now() + ADMIN_LOCK_MS;
    db.logEvent({ eventType: 'admin_bruteforce_blocked', ip, details: `Locked 15m after ${entry.count} failed attempts` });
  }
  adminFailures.set(ip, entry);
  return entry;
}

function hashUserAgent(req) {
  return crypto.createHash('sha256').update(String(req.headers['user-agent'] || '')).digest('hex');
}

function issueAdminSession(ip, req) {
  const now = Date.now();
  for (const [t, s] of adminSessions.entries()) {
    if (s.expiresAt < now) adminSessions.delete(t);
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, {
    ip,
    uaHash: hashUserAgent(req),
    expiresAt: now + ADMIN_SESSION_TTL_MS
  });
  return token;
}

function validateAdminBearer(req, ip) {
  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  const sess = adminSessions.get(token);
  if (!sess) return null;
  if (Date.now() > sess.expiresAt || sess.ip !== ip || sess.uaHash !== hashUserAgent(req)) {
    adminSessions.delete(token);
    return null;
  }
  return token;
}

// Sign payload with Ed25519 Private Key
function signEnvelope(envelope) {
  const canonical = JSON.stringify(envelope);
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), PRIVATE_KEY_PEM).toString('hex');
}

// Encrypt response payload using Ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM
function encryptAndSignForClient(payload, clientEphemeralPubB64) {
  const clientPubKey = crypto.createPublicKey({
    key: Buffer.from(String(clientEphemeralPubB64), 'base64'),
    format: 'der',
    type: 'spki'
  });

  const serverEcdh = crypto.generateKeyPairSync('x25519');
  const sharedSecret = crypto.diffieHellman({
    privateKey: serverEcdh.privateKey,
    publicKey: clientPubKey
  });

  const salt = crypto.randomBytes(16);
  const aesKey = crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from('noname-loader-e2e-v2'), 32);
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const serverPubDerB64 = serverEcdh.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

  const envelope = {
    alg: 'X25519-HKDF-AES256GCM-ED25519',
    serverEphemeralPub: serverPubDerB64,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    nonce: payload.nonce,
    issuedAt: payload.issuedAt
  };

  const signature = signEnvelope(envelope);
  return { envelope, signature };
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

  // Serve strict CSP-hardened Admin UI and external admin.js
  if (req.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
    const html = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });
    return res.end(html);
  }

  if (req.method === 'GET' && url.pathname === '/admin.js') {
    const js = fs.readFileSync(path.join(__dirname, 'admin.js'), 'utf8');
    res.writeHead(200, {
      'Content-Type': 'application/javascript; charset=utf-8',
      'X-Content-Type-Options': 'nosniff'
    });
    return res.end(js);
  }

  if (req.method === 'GET' && url.pathname === '/api/v1/health') {
    return sendJson(res, 200, {
      ok: true,
      service: 'no-name-license-api',
      db: 'sqlite',
      crypto: 'ed25519+x25519+aes-256-gcm',
      time: Date.now()
    });
  }

  // 1. License Auth (X25519 Encrypted + Ed25519 Signed)
  if (req.method === 'POST' && url.pathname === '/api/v1/auth/verify') {
    try {
      const { key, hwid, nonce, clientPub } = await readBody(req);
      if (!key || !hwid || !nonce || !clientPub) {
        return sendJson(res, 400, { valid: false, error: 'Missing key, hwid, nonce, or clientPub' });
      }
      if (!checkAndStoreNonce(String(nonce))) {
        db.logEvent({ eventType: 'replay_detected', key: String(key), hwid: String(hwid), ip: clientIp, details: 'Duplicate auth nonce' });
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

      const sealed = encryptAndSignForClient(payload, clientPub);
      return sendJson(res, 200, sealed);
    } catch (_) {
      return sendJson(res, 400, { valid: false, error: 'Invalid request body' });
    }
  }

  // 2. Active Session Heartbeat (auto-kicks revoked/reset-HWID sessions)
  if (req.method === 'POST' && url.pathname === '/api/v1/auth/heartbeat') {
    try {
      const { sessionId, hwid } = await readBody(req);
      const sessionRow = db.getValidSession(String(sessionId || ''), String(hwid || ''));
      if (!sessionRow) {
        return sendJson(res, 401, { active: false, error: 'Session expired or revoked' });
      }
      const record = db.getLicense(sessionRow.license_key);
      if (!record || record.revoked || (record.hwid && record.hwid !== String(hwid))) {
        db.deleteSession(String(sessionId));
        return sendJson(res, 403, { active: false, error: 'License revoked or HWID reset' });
      }
      const expiresMs = record.expiresAt ? Date.parse(record.expiresAt) : null;
      if (expiresMs && Date.now() > expiresMs) {
        return sendJson(res, 403, { active: false, error: 'Subscription expired' });
      }
      return sendJson(res, 200, { active: true });
    } catch (_) {
      return sendJson(res, 400, { active: false });
    }
  }

  // 3. Server-Side Launch Authorization (X25519 Encrypted + Ed25519 Signed 30s Ticket)
  if (req.method === 'POST' && url.pathname === '/api/v1/software/authorize') {
    try {
      const { sessionId, hwid, productId, branch, nonce, clientPub } = await readBody(req);
      if (!sessionId || !hwid || !productId || !branch || !nonce || !clientPub) {
        return sendJson(res, 400, { ok: false, error: 'Missing authorization parameters' });
      }
      if (!checkAndStoreNonce(String(nonce))) {
        db.logEvent({ eventType: 'replay_detected', hwid: String(hwid), ip: clientIp, details: 'Launch nonce replay' });
        return sendJson(res, 403, { ok: false, error: 'Replay attempt detected' });
      }

      const sessionRow = db.getValidSession(String(sessionId), String(hwid));
      if (!sessionRow) {
        return sendJson(res, 401, { ok: false, error: 'Session expired or invalid HWID. Sign in again.' });
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
        details: 'Encrypted launch ticket issued'
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

      const sealed = encryptAndSignForClient(payload, clientPub);
      return sendJson(res, 200, sealed);
    } catch (_) {
      return sendJson(res, 400, { ok: false, error: 'Invalid request body' });
    }
  }

  // 4. Anti-Tamper Telemetry
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

  // 5. Hardened Admin Authentication (Brute-force lockout + Ephemeral Bearer Session)
  if (req.method === 'POST' && url.pathname === '/api/v1/admin/login') {
    if (isAdminIpLocked(clientIp)) {
      return sendJson(res, 429, { ok: false, error: 'Admin login locked for 15 minutes due to failed attempts.' });
    }
    try {
      const { secret } = await readBody(req);
      if (!verifyAdminSecret(secret)) {
        const fail = recordAdminFailure(clientIp);
        const remaining = Math.max(0, ADMIN_FAIL_LIMIT - fail.count);
        return sendJson(res, 403, { ok: false, error: `Invalid ADMIN_SECRET (${remaining} attempts left)` });
      }
      adminFailures.delete(clientIp);
      const token = issueAdminSession(clientIp, req);
      db.logEvent({ eventType: 'admin_login', ip: clientIp, details: 'Admin session issued (30m TTL)' });
      return sendJson(res, 200, { ok: true, token, expiresInSec: ADMIN_SESSION_TTL_MS / 1000 });
    } catch (_) {
      return sendJson(res, 400, { ok: false, error: 'Invalid request body' });
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/v1/admin/logout') {
    const token = validateAdminBearer(req, clientIp);
    if (token) adminSessions.delete(token);
    return sendJson(res, 200, { ok: true });
  }

  // 6. Protected Admin Endpoints (Bearer Session Token required)
  if (url.pathname.startsWith('/api/v1/admin/')) {
    const token = validateAdminBearer(req, clientIp);
    if (!token) {
      return sendJson(res, 401, { ok: false, error: 'Admin session missing or expired. Please authenticate.' });
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
          db.revokeSessionsForKey(key);
          db.logEvent({ eventType: 'hwid_reset', key, ip: clientIp, details: 'Admin reset HWID & cleared sessions' });
          return sendJson(res, 200, { ok: true, key, message: 'HWID reset' });
        }

        if (action === 'revoke' && key) {
          const updated = db.setLicenseRevoked(key, true);
          if (!updated) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          db.revokeSessionsForKey(key);
          db.logEvent({ eventType: 'key_revoked', key, ip: clientIp, details: 'Admin revoked key & terminated sessions' });
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
