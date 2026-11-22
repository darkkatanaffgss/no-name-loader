const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { SDK_CONFIG, executeLaunchHook } = require('./sdk/loader-sdk');

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

let mainWindow = null;
let activeSession = null;

function getDeviceHwid() {
  const nets = os.networkInterfaces();
  let mac = '00:00:00:00:00:00';
  for (const name of Object.keys(nets)) {
    for (const iface of nets[name] || []) {
      if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
        mac = iface.mac;
        break;
      }
    }
    if (mac !== '00:00:00:00:00:00') break;
  }

  const cpuModel = (os.cpus()[0] && os.cpus()[0].model) || 'cpu';
  const raw = `${os.hostname()}|${os.platform()}|${os.arch()}|${cpuModel}|${mac}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24).toUpperCase();
}

function verifyApiSignature(payload, signature) {
  const expected = crypto
    .createHmac('sha256', SDK_CONFIG.hmacSecret)
    .update(JSON.stringify(payload))
    .digest('hex');

  const a = Buffer.from(String(signature || ''), 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || a.length === 0) return false;
  return crypto.timingSafeEqual(a, b);
}

function verifyAppIntegrity() {
  const criticalFiles = ['index.html', 'styles.css', 'renderer.js', 'preload.js'];
  for (const file of criticalFiles) {
    const p = path.join(__dirname, file);
    if (!fs.existsSync(p)) {
      throw new Error(`Integrity check failed: missing ${file}`);
    }
  }
}

function postJson(targetUrl, bodyObj) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;
    const data = JSON.stringify(bodyObj);

    const req = client.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'POST',
        timeout: 4500,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data)
        }
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(raw) });
          } catch (err) {
            reject(new Error('Invalid JSON response from License API'));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('License API request timed out'));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function createWindow() {
  verifyAppIntegrity();

  // Exact 684x460 transparent frameless window with thickFrame: false & hasShadow: false
  // so CSS border-radius: 20px cuts cleanly to alpha=0 with zero outer shadow clipping box.
  mainWindow = new BrowserWindow({
    width: 684,
    height: 460,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    frame: false,
    thickFrame: false,
    transparent: true,
    hasShadow: false,
    icon: path.join(__dirname, 'assets', 'icon.png'),
    backgroundColor: '#00000000',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: !app.isPackaged
    }
  });

  mainWindow.webContents.on('before-input-event', (event, input) => {
    const key = (input.key || '').toLowerCase();
    const blockedCombo =
      key === 'f12' ||
      (input.control && input.shift && (key === 'i' || key === 'j' || key === 'c')) ||
      (input.control && (key === 'u' || key === 'r'));

    if (blockedCombo && app.isPackaged) {
      event.preventDefault();
    }
  });

  mainWindow.webContents.on('context-menu', (event) => {
    event.preventDefault();
  });

  mainWindow.loadFile('index.html');
}

app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

ipcMain.on('window:minimize', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.minimize();
  }
});

ipcMain.on('window:close', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.close();
  }
});

ipcMain.on('shell:open-external', (_event, url) => {
  if (typeof url === 'string' && (url.startsWith('https://') || url.startsWith('http://'))) {
    shell.openExternal(url);
  }
});

ipcMain.handle('auth:get-device-info', () => {
  return {
    hwid: getDeviceHwid(),
    apiBaseUrl: SDK_CONFIG.apiBaseUrl,
    catalog: SDK_CONFIG.softwareCatalog
  };
});

ipcMain.handle('auth:verify-key', async (_event, keyInput) => {
  const cleanKey = String(keyInput || '').trim().toUpperCase();
  if (!cleanKey) {
    return { ok: false, error: 'Please enter a license key' };
  }

  const hwid = getDeviceHwid();
  const nonce = crypto.randomBytes(12).toString('hex');

  try {
    const res = await postJson(`${SDK_CONFIG.apiBaseUrl}/api/v1/auth/verify`, {
      key: cleanKey,
      hwid,
      nonce
    });

    if (res.status !== 200 || !res.data || !res.data.payload) {
      return { ok: false, error: (res.data && res.data.error) || 'License verification rejected' };
    }

    const { payload, signature } = res.data;
    if (!verifyApiSignature(payload, signature)) {
      return { ok: false, error: 'Tamper check failed: invalid server HMAC signature' };
    }
    if (payload.nonce !== nonce || payload.hwid !== hwid) {
      return { ok: false, error: 'Session mismatch detected' };
    }

    activeSession = { ...payload, key: cleanKey, mode: 'online' };
    return { ok: true, session: activeSession };
  } catch (_) {
    if (cleanKey === 'NN-DEMO-2026-OPEN') {
      activeSession = {
        valid: true,
        key: cleanKey,
        username: 'Developer',
        tier: 'Demo (Offline)',
        expiresAt: '2035-05-09T03:00:00.000Z',
        products: ['cs2', 'csgo', 'minecraft'],
        branches: ['Stable', 'Beta', 'Nightly'],
        hwid,
        nonce,
        mode: 'offline-demo'
      };
      return { ok: true, session: activeSession };
    }

    return {
      ok: false,
      error: 'License API offline. Start server (`npm run server`) or use demo key NN-DEMO-2026-OPEN'
    };
  }
});

ipcMain.handle('auth:logout', () => {
  activeSession = null;
  return { ok: true };
});

ipcMain.handle('software:launch', async (_event, { productId, branch }) => {
  try {
    const result = await executeLaunchHook({ productId, branch, session: activeSession });
    return result;
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
