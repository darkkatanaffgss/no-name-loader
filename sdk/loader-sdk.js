/**
 * no name Open-Source Loader SDK
 * -----------------------------------------------------------
 * Uses ONLY the Ed25519 Public Key (sdk/public-config.json)
 * and Ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM
 * to decrypt and verify backend responses.
 * No private secrets ever exist in client code.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function loadPublicConfig() {
  const cfgPath = path.join(__dirname, 'public-config.json');
  if (!fs.existsSync(cfgPath)) {
    return {
      apiBaseUrl: 'http://127.0.0.1:3840',
      pinnedCertSha256: '',
      ed25519PublicKeyBase64: ''
    };
  }
  return JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
}

const PUBLIC_CFG = loadPublicConfig();

function getLockedApiUrl() {
  return PUBLIC_CFG.apiBaseUrl;
}

function verifyEd25519Signature(envelope, signatureHex) {
  if (!PUBLIC_CFG.ed25519PublicKeyBase64 || !signatureHex) {
    return false;
  }
  try {
    const publicKeyPem = Buffer.from(PUBLIC_CFG.ed25519PublicKeyBase64, 'base64').toString('utf8');
    const canonical = JSON.stringify(envelope);
    const sigBuf = Buffer.from(String(signatureHex), 'hex');
    return crypto.verify(null, Buffer.from(canonical, 'utf8'), publicKeyPem, sigBuf);
  } catch (_) {
    return false;
  }
}

function decryptServerEnvelope({ envelope, signature, clientPrivateKey, expectedNonce }) {
  if (!envelope || !signature) {
    throw new Error('Malformed server envelope');
  }
  if (!verifyEd25519Signature(envelope, signature)) {
    throw new Error('Tamper check failed: invalid Ed25519 signature');
  }
  if (envelope.nonce !== expectedNonce) {
    throw new Error('Nonce mismatch detected');
  }
  if (Math.abs(Date.now() - Number(envelope.issuedAt || 0)) > 60_000) {
    throw new Error('Stale server envelope rejected');
  }

  const serverPubKey = crypto.createPublicKey({
    key: Buffer.from(String(envelope.serverEphemeralPub), 'base64'),
    format: 'der',
    type: 'spki'
  });

  const sharedSecret = crypto.diffieHellman({
    privateKey: clientPrivateKey,
    publicKey: serverPubKey
  });

  const salt = Buffer.from(envelope.salt, 'base64');
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

  const aesKey = crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from('noname-loader-e2e-v2'), 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  return JSON.parse(decrypted);
}

const SDK_CONFIG = {
  brandName: 'no name',
  pinnedCertSha256: PUBLIC_CFG.pinnedCertSha256 || '',
  getApiBaseUrl: getLockedApiUrl,
  softwareCatalog: {
    cs2: {
      id: 'cs2',
      title: 'Counter-Strike 2',
      updated: 'Nov 13 2026 (16:15 PM)',
      lastLaunch: 'Last Month',
      defaultBranch: 'Nightly',
      changelog: [
        'X25519 ECDH + AES-256-GCM encrypted auth & launch tickets',
        'Asymmetric Ed25519 signature verification enabled',
        'Live session heartbeat & SQLite analytics'
      ]
    },
    csgo: {
      id: 'csgo',
      title: 'Counter-Strike: Global Offensive',
      updated: 'Nov 10 2026 (12:40 PM)',
      lastLaunch: '2 Weeks Ago',
      defaultBranch: 'Stable',
      changelog: [
        'Added dark tactical banner artwork',
        'Server-side HWID & session validation',
        'Updated branch selector controls'
      ]
    },
    minecraft: {
      id: 'minecraft',
      title: 'Minecraft',
      updated: 'Nov 18 2026 (19:05 PM)',
      lastLaunch: 'Yesterday',
      defaultBranch: 'Beta',
      changelog: [
        'Added voxel night banner artwork',
        'Connected server-side entitlement checks',
        'Updated release channel switcher'
      ]
    }
  }
};

async function executeLaunchHook({ productId, branch, ticketPayload }) {
  if (!ticketPayload.authorized || ticketPayload.productId !== productId || ticketPayload.branch !== branch) {
    throw new Error('Launch ticket mismatch');
  }
  if (Date.now() > Number(ticketPayload.ticketExpiresAt || 0)) {
    throw new Error('Launch ticket expired');
  }

  return {
    ok: true,
    productId,
    branch,
    message: `${SDK_CONFIG.softwareCatalog[productId].title} (${branch}) authorized by backend`
  };
}

module.exports = {
  SDK_CONFIG,
  verifyEd25519Signature,
  decryptServerEnvelope,
  executeLaunchHook
};
