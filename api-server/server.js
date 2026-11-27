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
const ALLOWED_ADMIN_IPS = new Set(
  (process.env.ADMIN_ALLOWED_IPS || '127.0.0.1,::1').split(',').map((s) => s.trim()).filter(Boolean)
);

if (!ADMIN_SECRET || !PRIVATE_KEY_B64) {
  console.error('[Server] Fatal: ADMIN_SECRET or ED25519_PRIVATE_KEY missing in api-server/.env.');
  process.exit(1);
}

const PRIVATE_KEY_PEM = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8');
const ADMIN_DIGEST_HEX = crypto.createHash('sha512').update(ADMIN_SECRET, 'utf8').digest('hex');

// Rate limits, nonce replay cache, admin challenge-response & session stores
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 45;
const NONCE_TTL_MS = 120_000;
const CHALLENGE_TTL_MS = 30_000;
const ADMIN_FAIL_LIMIT = 5;
const ADMIN_LOCK_MS = 15 * 60_000;
const ADMIN_SESSION_TTL_MS = 30 * 60_000;
const ADMIN_IDLE_TTL_MS = 10 * 60_000;

const rateBuckets = new Map();
const seenNonces = new Map();
const adminChallenges = new Map(); // challenge -> { ip, expiresAt }
const adminFailures = new Map();   // ip -> { count, lockedUntil }
const adminSessions = new Map();   // token -> { ip, uaHash, csrfToken, expiresAt, lastActiveAt }

function normalizeIp(rawIp) {
  const s = String(rawIp || 'unknown');
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

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

function isAdminIpAllowed(ip) {
  if (ALLOWED_ADMIN_IPS.has('*')) return true;
  return ALLOWED_ADMIN_IPS.has(ip);
}

function isAdminIpLocked(ip) {
  const entry = adminFailures.get(ip);
  if (!entry) return false;
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) return true;
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) adminFailures.delete(ip);
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

function parseCookies(req) {
  const out = {};
  const header = String(req.headers.cookie || '');
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return out;
}

function issueAdminSession(ip, req) {
  const now = Date.now();
  for (const [t, s] of adminSessions.entries()) {
    if (s.expiresAt < now || now - s.lastActiveAt > ADMIN_IDLE_TTL_MS) adminSessions.delete(t);
  }
  const token = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(24).toString('hex');
  adminSessions.set(token, {
    ip,
    uaHash: hashUserAgent(req),
    csrfToken,
    expiresAt: now + ADMIN_SESSION_TTL_MS,
    lastActiveAt: now
  });
  return { token, csrfToken };
}

function validateAdminSession(req, ip, requireCsrf = false) {
  const cookies = parseCookies(req);
  const authHeader = String(req.headers.authorization || '');
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const token = cookies.nn_admin_sid || bearerToken;

  if (!token) return null;
  const sess = adminSessions.get(token);
  if (!sess) return null;

  const now = Date.now();
  if (now > sess.expiresAt || now - sess.lastActiveAt > ADMIN_IDLE_TTL_MS) {
    adminSessions.delete(token);
    return null;
  }
  if (sess.ip !== ip || sess.uaHash !== hashUserAgent(req)) {
    adminSessions.delete(token);
    db.logEvent({ eventType: 'admin_session_hijack_blocked', ip, details: 'IP/User-Agent mismatch' });
    return null;
  }
  if (requireCsrf) {
    const csrfHeader = String(req.headers['x-csrf-token'] || '');
    const a = Buffer.from(csrfHeader, 'utf8');
    const b = Buffer.from(sess.csrfToken, 'utf8');
    if (a.length !== b.length || a.length === 0 || !crypto.timingSafeEqual(a, b)) {
      return null;
    }
  }

  sess.lastActiveAt = now;
  return { token, sess };
}

function signEnvelope(envelope) {
  const canonical = JSON.stringify(envelope);
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), PRIVATE_KEY_PEM).toString('hex');
}

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

function sendJson(res, statusCode, body, extraHeaders = {}) {
  const json = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    ...extraHeaders
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
  const startedAt = Date.now();
  const clientIp = normalizeIp(req.socket.remoteAddress);
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

  // Record every non-polling API traffic hit into SQLite traffic_logs
  res.on('finish', () => {
    if (url.pathname.startsWith('/api/v1/') && url.pathname !== '/api/v1/admin/analytics') {
      try {
        db.logTraffic({
          method: req.method,
          path: url.pathname,
          ip: clientIp,
          statusCode: res.statusCode,
          latencyMs: Math.max(0, Date.now() - startedAt),
          userAgent: req.headers['user-agent'] || ''
        });
      } catch (_) {}
    }
  });

  // 1. Check IP Ban List immediately
  if (db.isIpBanned(clientIp)) {
    db.logEvent({ eventType: 'banned_ip_blocked', ip: clientIp, details: `Blocked ${req.method} ${url.pathname}` });
    return sendJson(res, 403, { ok: false, valid: false, error: 'Your IP address is blocked.' });
  }

  // 2. Rate limit (higher allowance for admin polling, strict on public auth)
  if (!url.pathname.startsWith('/api/v1/admin/analytics') && isRateLimited(clientIp)) {
    return sendJson(res, 429, { valid: false, error: 'Rate limit exceeded. Wait 1 minute.' });
  }

  // 3. Serve CSP-hardened Admin UI & external script (only for allowlisted Admin IPs)
  if (req.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
    if (!isAdminIpAllowed(clientIp)) {
      return sendJson(res, 403, { ok: false, error: 'Admin panel restricted to allowlisted IPs' });
    }
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
    if (!isAdminIpAllowed(clientIp)) {
      return sendJson(res, 403, { ok: false, error: 'Forbidden' });
    }
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

  // 4. Client Auth
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
      const session = db.createSession(cleanKey, String(hwid), clientIp);
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

      return sendJson(res, 200, encryptAndSignForClient(payload, clientPub));
    } catch (_) {
      return sendJson(res, 400, { valid: false, error: 'Invalid request body' });
    }
  }

  // 5. Client Heartbeat
  if (req.method === 'POST' && url.pathname === '/api/v1/auth/heartbeat') {
    try {
      const { sessionId, hwid } = await readBody(req);
      const sessionRow = db.getValidSession(String(sessionId || ''), String(hwid || ''));
      if (!sessionRow) {
        return sendJson(res, 401, { active: false, error: 'Session expired or terminated' });
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

  // 6. Launch Authorization
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

      return sendJson(res, 200, encryptAndSignForClient(payload, clientPub));
    } catch (_) {
      return sendJson(res, 400, { ok: false, error: 'Invalid request body' });
    }
  }

  // 7. Telemetry
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

  // 8. Admin Challenge-Response Auth (raw ADMIN_SECRET never crosses network!)
  if (req.method === 'GET' && url.pathname === '/api/v1/admin/challenge') {
    if (!isAdminIpAllowed(clientIp)) {
      return sendJson(res, 403, { ok: false, error: 'IP not in ADMIN_ALLOWED_IPS' });
    }
    if (isAdminIpLocked(clientIp)) {
      return sendJson(res, 429, { ok: false, error: 'Admin login locked for 15 minutes.' });
    }
    const now = Date.now();
    for (const [c, meta] of adminChallenges.entries()) {
      if (meta.expiresAt < now) adminChallenges.delete(c);
    }
    const challenge = crypto.randomBytes(24).toString('hex');
    adminChallenges.set(challenge, { ip: clientIp, expiresAt: now + CHALLENGE_TTL_MS });
    return sendJson(res, 200, { ok: true, challenge });
  }

  if (req.method === 'POST' && url.pathname === '/api/v1/admin/login') {
    if (!isAdminIpAllowed(clientIp)) {
      return sendJson(res, 403, { ok: false, error: 'IP not in ADMIN_ALLOWED_IPS' });
    }
    if (isAdminIpLocked(clientIp)) {
      return sendJson(res, 429, { ok: false, error: 'Admin login locked for 15 minutes due to failed attempts.' });
    }
    try {
      const { challenge, proof, secret } = await readBody(req);
      let verified = false;

      // Support Challenge-Response HMAC proof (browser admin) OR constant-time SHA-512 hash (CLI tools)
      if (challenge && proof) {
        const chMeta = adminChallenges.get(String(challenge));
        adminChallenges.delete(String(challenge));
        if (chMeta && chMeta.ip === clientIp && Date.now() <= chMeta.expiresAt) {
          const expectedProof = crypto.createHmac('sha256', ADMIN_DIGEST_HEX).update(String(challenge)).digest('hex');
          const a = Buffer.from(String(proof), 'hex');
          const b = Buffer.from(expectedProof, 'hex');
          if (a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b)) {
            verified = true;
          }
        }
      } else if (secret) {
        const inputHex = crypto.createHash('sha512').update(String(secret), 'utf8').digest('hex');
        const a = Buffer.from(inputHex, 'hex');
        const b = Buffer.from(ADMIN_DIGEST_HEX, 'hex');
        if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
          verified = true;
        }
      }

      if (!verified) {
        const fail = recordAdminFailure(clientIp);
        const remaining = Math.max(0, ADMIN_FAIL_LIMIT - fail.count);
        return sendJson(res, 403, { ok: false, error: `Invalid credentials (${remaining} attempts left)` });
      }

      adminFailures.delete(clientIp);
      const { token, csrfToken } = issueAdminSession(clientIp, req);
      db.logEvent({ eventType: 'admin_login', ip: clientIp, details: 'Challenge-response verified (HttpOnly + CSRF)' });

      return sendJson(
        res,
        200,
        { ok: true, token, csrfToken, expiresInSec: ADMIN_SESSION_TTL_MS / 1000 },
        { 'Set-Cookie': `nn_admin_sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ADMIN_SESSION_TTL_MS / 1000}` }
      );
    } catch (_) {
      return sendJson(res, 400, { ok: false, error: 'Invalid request body' });
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/v1/admin/logout') {
    const valid = validateAdminSession(req, clientIp, false);
    if (valid) adminSessions.delete(valid.token);
    return sendJson(
      res,
      200,
      { ok: true },
      { 'Set-Cookie': 'nn_admin_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }
    );
  }

  // 9. Protected Admin Routes
  if (url.pathname.startsWith('/api/v1/admin/')) {
    if (!isAdminIpAllowed(clientIp)) {
      return sendJson(res, 403, { ok: false, error: 'IP not allowlisted' });
    }
    const requireCsrf = req.method === 'POST';
    const valid = validateAdminSession(req, clientIp, requireCsrf);
    if (!valid) {
      return sendJson(res, 401, { ok: false, error: 'Admin session missing, expired, or invalid CSRF token.' });
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
          if (!db.resetLicenseHwid(key)) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          db.revokeSessionsForKey(key);
          db.logEvent({ eventType: 'hwid_reset', key, ip: clientIp, details: 'Admin reset HWID & cleared sessions' });
          return sendJson(res, 200, { ok: true, key });
        }

        if (action === 'revoke' && key) {
          if (!db.setLicenseRevoked(key, true)) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          db.revokeSessionsForKey(key);
          db.logEvent({ eventType: 'key_revoked', key, ip: clientIp, details: 'Admin revoked key & terminated sessions' });
          return sendJson(res, 200, { ok: true, key });
        }

        if (action === 'unrevoke' && key) {
          if (!db.setLicenseRevoked(key, false)) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          return sendJson(res, 200, { ok: true, key });
        }

        if (action === 'delete' && key) {
          if (!db.deleteLicense(key)) return sendJson(res, 404, { ok: false, error: 'Key not found' });
          return sendJson(res, 200, { ok: true, key });
        }

        return sendJson(res, 400, { ok: false, error: 'Unknown admin action' });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: err.message || 'Invalid JSON' });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/sessions/kick') {
      const { sessionId } = await readBody(req);
      if (!sessionId || !db.deleteSession(String(sessionId))) {
        return sendJson(res, 404, { ok: false, error: 'Session not found' });
      }
      db.logEvent({ eventType: 'session_kicked', ip: clientIp, details: `Kicked session ${String(sessionId).slice(0, 10)}…` });
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/ips') {
      const { action, ip, reason } = await readBody(req);
      const cleanIp = normalizeIp(ip);
      if (!cleanIp || cleanIp === 'unknown') {
        return sendJson(res, 400, { ok: false, error: 'Invalid IP' });
      }
      if (action === 'ban') {
        db.banIp(cleanIp, reason || 'Blocked by admin');
        db.logEvent({ eventType: 'ip_banned', ip: cleanIp, details: reason || 'Banned via Admin Panel' });
        return sendJson(res, 200, { ok: true });
      }
      if (action === 'unban') {
        db.unbanIp(cleanIp);
        db.logEvent({ eventType: 'ip_unbanned', ip: cleanIp, details: 'Unbanned via Admin Panel' });
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 400, { ok: false, error: 'Unknown IP action' });
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/logs/clear') {
      db.clearLogs();
      db.logEvent({ eventType: 'logs_cleared', ip: clientIp, details: 'Admin cleared traffic & event logs' });
      return sendJson(res, 200, { ok: true });
    }
  }

  sendJson(res, 404, { ok: false, error: 'Endpoint not found' });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[no name License API] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[no name Admin Panel] Open http://127.0.0.1:${PORT}/admin`);
});
