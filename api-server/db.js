const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = path.join(__dirname, 'database.sqlite');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    tier TEXT NOT NULL,
    expires_at TEXT,
    hwid TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    products_json TEXT NOT NULL,
    branches_json TEXT NOT NULL,
    launch_count INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    license_key TEXT NOT NULL,
    hwid TEXT NOT NULL,
    ip TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (license_key) REFERENCES licenses(key) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    license_key TEXT,
    hwid TEXT,
    ip TEXT,
    product_id TEXT,
    branch TEXT,
    details TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    ip TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    user_agent TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    blocked_at TEXT NOT NULL
  );
`);

// Ensure existing tables created prior to ip column get ip column safely
try {
  db.exec('ALTER TABLE sessions ADD COLUMN ip TEXT');
} catch (_) {
  // Column already exists
}

function seedInitialDemoKey() {
  const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM licenses').get();
  if (countRow && countRow.cnt === 0) {
    db.prepare(`
      INSERT INTO licenses (key, username, tier, expires_at, hwid, revoked, products_json, branches_json, created_at)
      VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
    `).run(
      'NN-DEMO-2026-OPEN',
      'Developer',
      'Enterprise',
      '2035-05-09T03:00:00.000Z',
      null,
      JSON.stringify(['cs2', 'csgo', 'minecraft']),
      JSON.stringify(['Stable', 'Beta', 'Nightly']),
      new Date().toISOString()
    );
  }
}
seedInitialDemoKey();

function mapLicenseRow(row) {
  if (!row) return null;
  return {
    key: row.key,
    username: row.username,
    tier: row.tier,
    expiresAt: row.expires_at,
    hwid: row.hwid,
    revoked: Boolean(row.revoked),
    products: JSON.parse(row.products_json),
    branches: JSON.parse(row.branches_json),
    launchCount: row.launch_count,
    lastSeenAt: row.last_seen_at,
    createdAt: row.created_at
  };
}

function getLicense(key) {
  return mapLicenseRow(db.prepare('SELECT * FROM licenses WHERE key = ?').get(key));
}

function listLicenses() {
  return db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all().map(mapLicenseRow);
}

function bindHwidAndTouch(key, hwid) {
  db.prepare('UPDATE licenses SET hwid = COALESCE(hwid, ?), last_seen_at = ? WHERE key = ?').run(
    hwid,
    new Date().toISOString(),
    key
  );
}

function incrementLaunchCount(key) {
  db.prepare('UPDATE licenses SET launch_count = launch_count + 1, last_seen_at = ? WHERE key = ?').run(
    new Date().toISOString(),
    key
  );
}

function createLicense({ key, username, tier, expiresAt, products, branches }) {
  const generatedKey = (
    key ||
    `NN-${crypto.randomBytes(2).toString('hex')}-${crypto.randomBytes(2).toString('hex')}-${crypto.randomBytes(2).toString('hex')}`
  ).toUpperCase();

  db.prepare(`
    INSERT INTO licenses (key, username, tier, expires_at, hwid, revoked, products_json, branches_json, created_at)
    VALUES (?, ?, ?, ?, NULL, 0, ?, ?, ?)
  `).run(
    generatedKey,
    username || 'Customer',
    tier || 'Pro',
    expiresAt || null,
    JSON.stringify(products || ['cs2', 'csgo', 'minecraft']),
    JSON.stringify(branches || ['Stable', 'Beta', 'Nightly']),
    new Date().toISOString()
  );
  return getLicense(generatedKey);
}

function resetLicenseHwid(key) {
  return db.prepare('UPDATE licenses SET hwid = NULL WHERE key = ?').run(key).changes > 0;
}

function setLicenseRevoked(key, revoked) {
  return db.prepare('UPDATE licenses SET revoked = ? WHERE key = ?').run(revoked ? 1 : 0, key).changes > 0;
}

function deleteLicense(key) {
  return db.prepare('DELETE FROM licenses WHERE key = ?').run(key).changes > 0;
}

function createSession(licenseKey, hwid, ip = null, ttlMs = 12 * 60 * 60 * 1000) {
  const sessionId = crypto.randomBytes(24).toString('hex');
  const now = Date.now();
  const expiresAt = now + ttlMs;
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('INSERT INTO sessions (session_id, license_key, hwid, ip, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    sessionId,
    licenseKey,
    hwid,
    ip,
    expiresAt,
    now
  );
  return { sessionId, expiresAt };
}

function getValidSession(sessionId, hwid) {
  const now = Date.now();
  const row = db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId);
  if (!row) return null;
  if (row.expires_at < now || row.hwid !== hwid) return null;
  return row;
}

function listActiveSessions() {
  const now = Date.now();
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  return db.prepare('SELECT session_id, license_key, hwid, ip, expires_at, created_at FROM sessions ORDER BY created_at DESC').all();
}

function revokeSessionsForKey(licenseKey) {
  return db.prepare('DELETE FROM sessions WHERE license_key = ?').run(licenseKey).changes;
}

function deleteSession(sessionId) {
  return db.prepare('DELETE FROM sessions WHERE session_id = ?').run(sessionId).changes > 0;
}

function logEvent({ eventType, key = null, hwid = null, ip = null, productId = null, branch = null, details = null }) {
  db.prepare(`
    INSERT INTO analytics_events (event_type, license_key, hwid, ip, product_id, branch, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(eventType, key, hwid, ip, productId, branch, details, new Date().toISOString());
}

function logTraffic({ method, path: reqPath, ip, statusCode, latencyMs, userAgent = '' }) {
  db.prepare(`
    INSERT INTO traffic_logs (method, path, ip, status_code, latency_ms, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(method, reqPath, ip, statusCode, latencyMs, String(userAgent).slice(0, 140), new Date().toISOString());
  // Keep latest 1000 traffic entries so DB stays compact
  db.prepare('DELETE FROM traffic_logs WHERE id <= (SELECT MAX(id) - 1000 FROM traffic_logs)').run();
}

function isIpBanned(ip) {
  return Boolean(db.prepare('SELECT 1 FROM blocked_ips WHERE ip = ?').get(ip));
}

function banIp(ip, reason = 'Blocked by administrator') {
  db.prepare(`
    INSERT INTO blocked_ips (ip, reason, blocked_at)
    VALUES (?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, blocked_at = excluded.blocked_at
  `).run(ip, reason, new Date().toISOString());
}

function unbanIp(ip) {
  return db.prepare('DELETE FROM blocked_ips WHERE ip = ?').run(ip).changes > 0;
}

function listBannedIps() {
  return db.prepare('SELECT * FROM blocked_ips ORDER BY blocked_at DESC').all();
}

function clearLogs() {
  db.exec('DELETE FROM traffic_logs; DELETE FROM analytics_events;');
}

function getAnalyticsSummary() {
  const now = Date.now();
  const oneMinAgoIso = new Date(now - 60_000).toISOString();

  const totalLicenses = db.prepare('SELECT COUNT(*) AS c FROM licenses').get().c;
  const activeLicenses = db.prepare('SELECT COUNT(*) AS c FROM licenses WHERE revoked = 0').get().c;
  const activeSessionsCount = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE expires_at > ?').get(now).c;
  const totalLaunches = db.prepare('SELECT COALESCE(SUM(launch_count), 0) AS s FROM licenses').get().s;
  const securityAlerts = db
    .prepare("SELECT COUNT(*) AS c FROM analytics_events WHERE event_type IN ('anti_tamper_alert', 'hwid_mismatch', 'replay_detected', 'admin_bruteforce_blocked', 'banned_ip_blocked')")
    .get().c;
  const rpm = db.prepare('SELECT COUNT(*) AS c FROM traffic_logs WHERE created_at >= ?').get(oneMinAgoIso).c;
  const avgLatencyMs = Math.round(
    db.prepare('SELECT COALESCE(AVG(latency_ms), 0) AS a FROM (SELECT latency_ms FROM traffic_logs ORDER BY id DESC LIMIT 100)').get().a
  );
  const bannedCount = db.prepare('SELECT COUNT(*) AS c FROM blocked_ips').get().c;

  const recentEvents = db.prepare('SELECT * FROM analytics_events ORDER BY id DESC LIMIT 60').all();
  const trafficLogs = db.prepare('SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 80').all();
  const activeSessions = listActiveSessions();
  const bannedIps = listBannedIps();

  return {
    stats: {
      totalLicenses,
      activeLicenses,
      activeSessions: activeSessionsCount,
      totalLaunches,
      securityAlerts,
      rpm,
      avgLatencyMs,
      bannedCount
    },
    recentEvents,
    trafficLogs,
    activeSessions,
    bannedIps
  };
}

module.exports = {
  getLicense,
  listLicenses,
  bindHwidAndTouch,
  incrementLaunchCount,
  createLicense,
  resetLicenseHwid,
  setLicenseRevoked,
  deleteLicense,
  createSession,
  getValidSession,
  listActiveSessions,
  revokeSessionsForKey,
  deleteSession,
  logEvent,
  logTraffic,
  isIpBanned,
  banIp,
  unbanIp,
  listBannedIps,
  clearLogs,
  getAnalyticsSummary
};
