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
`);

function seedInitialDemoKey() {
  const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM licenses').get();
  if (countRow && countRow.cnt === 0) {
    const stmt = db.prepare(`
      INSERT INTO licenses (key, username, tier, expires_at, hwid, revoked, products_json, branches_json, created_at)
      VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
    `);
    stmt.run(
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
  const row = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);
  return mapLicenseRow(row);
}

function listLicenses() {
  const rows = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
  return rows.map(mapLicenseRow);
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
  const res = db.prepare('UPDATE licenses SET hwid = NULL WHERE key = ?').run(key);
  return res.changes > 0;
}

function setLicenseRevoked(key, revoked) {
  const res = db.prepare('UPDATE licenses SET revoked = ? WHERE key = ?').run(revoked ? 1 : 0, key);
  return res.changes > 0;
}

function deleteLicense(key) {
  const res = db.prepare('DELETE FROM licenses WHERE key = ?').run(key);
  return res.changes > 0;
}

function createSession(licenseKey, hwid, ttlMs = 12 * 60 * 60 * 1000) {
  const sessionId = crypto.randomBytes(24).toString('hex');
  const now = Date.now();
  const expiresAt = now + ttlMs;
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  db.prepare('INSERT INTO sessions (session_id, license_key, hwid, expires_at, created_at) VALUES (?, ?, ?, ?, ?)').run(
    sessionId,
    licenseKey,
    hwid,
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

function revokeSessionsForKey(licenseKey) {
  const res = db.prepare('DELETE FROM sessions WHERE license_key = ?').run(licenseKey);
  return res.changes;
}

function deleteSession(sessionId) {
  db.prepare('DELETE FROM sessions WHERE session_id = ?').run(sessionId);
}

function logEvent({ eventType, key = null, hwid = null, ip = null, productId = null, branch = null, details = null }) {
  db.prepare(`
    INSERT INTO analytics_events (event_type, license_key, hwid, ip, product_id, branch, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(eventType, key, hwid, ip, productId, branch, details, new Date().toISOString());
}

function getAnalyticsSummary() {
  const totalLicenses = db.prepare('SELECT COUNT(*) AS c FROM licenses').get().c;
  const activeLicenses = db.prepare('SELECT COUNT(*) AS c FROM licenses WHERE revoked = 0').get().c;
  const activeSessions = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE expires_at > ?').get(Date.now()).c;
  const totalLaunches = db.prepare('SELECT COALESCE(SUM(launch_count), 0) AS s FROM licenses').get().s;
  const securityAlerts = db
    .prepare("SELECT COUNT(*) AS c FROM analytics_events WHERE event_type IN ('anti_tamper_alert', 'hwid_mismatch', 'replay_detected')")
    .get().c;
  const recentEvents = db.prepare('SELECT * FROM analytics_events ORDER BY id DESC LIMIT 40').all();

  return {
    stats: {
      totalLicenses,
      activeLicenses,
      activeSessions,
      totalLaunches,
      securityAlerts
    },
    recentEvents
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
  revokeSessionsForKey,
  deleteSession,
  logEvent,
  getAnalyticsSummary
};
