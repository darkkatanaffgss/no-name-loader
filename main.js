const { app, BrowserWindow, ipcMain, shell, session } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { SDK_CONFIG, verifyEd25519Signature, executeLaunchHook } = require('./sdk/loader-sdk');

app.enableSandbox();

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

let mainWindow = null;
let activeSession = null;

// Direct agents ignore HTTP_PROXY / HTTPS_PROXY environment hijacking
const directHttpAgent = new http.Agent({ keepAlive: false });
const directHttpsAgent = new https.Agent({ keepAlive: false, rejectUnauthorized: true });

const BLOCKED_ANALYSIS_TOOLS = [
  'ida.exe',
  'ida64.exe',
  'x64dbg.exe',
  'x32dbg.exe',
  'ollydbg.exe',
  'wireshark.exe',
  'fiddler.exe',
  'httpdebuggerui.exe',
  'httpdebuggerpro.exe',
  'dnspy.exe',
  'cheatengine-x86_64.exe',
  'processhacker.exe'
];

function hasDebuggerArgs() {
  const combined = [...process.execArgv, ...process.argv].join(' ').toLowerCase();
  return (
    combined.includes('--inspect') ||
    combined.includes('--remote-debugging-port') ||
    combined.includes('--debug-brk')
  );
}

// Defensive environment check for active analysis / sniffing tools (only enforced when packaged)
function detectAnalysisTools() {
  if (!app.isPackaged || process.platform !== 'win32') {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    execFile('tasklist', ['/FO', 'CSV', '/NH'], { timeout: 2500 }, (err, stdout) => {
      if (err || !stdout) return resolve(null);
      const lower = stdout.toLowerCase();
      for (const proc of BLOCKED_ANALYSIS_TOOLS) {
        if (lower.includes(`"${proc}"`)) {
          return resolve(proc);
        }
      }
      resolve(null);
    });
  });
}

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

function verifyAppIntegrity() {
  const criticalFiles = ['index.html', 'styles.css', 'renderer.js', 'preload.js', 'sdk/loader-sdk.js', 'sdk/public-config.json'];
  for (const file of criticalFiles) {
    const p = path.join(__dirname, file);
    if (!fs.existsSync(p)) {
      throw new Error(`Integrity check failed: missing ${file}`);
    }
  }

  const manifestPath = path.join(__dirname, 'integrity.json');
  if (app.isPackaged && fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    for (const [relPath, expectedHash] of Object.entries(manifest)) {
      const target = path.join(__dirname, relPath);
      if (!fs.existsSync(target)) {
        throw new Error(`Integrity check failed: missing ${relPath}`);
      }
      const actualHash = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
      if (actualHash !== expectedHash) {
        throw new Error(`Integrity check failed: modified ${relPath}`);
      }
    }
  }
}

function postJson(targetUrl, bodyObj) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;
    const data = JSON.stringify(bodyObj);

    const req = client.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'POST',
        timeout: 4500,
        agent: isHttps ? directHttpsAgent : directHttpAgent,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data)
        }
      },
      (res) => {
        // Optional TLS SPKI / Certificate Pinning against MITM proxies
        if (isHttps && SDK_CONFIG.pinnedCertSha256 && res.socket && typeof res.socket.getPeerCertificate === 'function') {
          const cert = res.socket.getPeerCertificate();
          const fp = (cert && cert.fingerprint256 || '').replace(/:/g, '').toLowerCase();
          if (!fp || fp !== SDK_CONFIG.pinnedCertSha256.toLowerCase()) {
            res.destroy();
            return reject(new Error('TLS certificate pinning mismatch'));
          }
        }

        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(raw) });
          } catch (_) {
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

function sendTelemetry(eventType, details, key = null) {
  const apiUrl = SDK_CONFIG.getApiBaseUrl(app.isPackaged);
  postJson(`${apiUrl}/api/v1/telemetry`, {
    eventType,
    hwid: getDeviceHwid(),
    key,
    details
  }).catch(() => {});
}

function createWindow() {
  if (hasDebuggerArgs()) {
    sendTelemetry('anti_tamper_alert', 'Blocked: debugger CLI flags detected');
    app.quit();
    return;
  }

  verifyAppIntegrity();

  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => {
    callback(false);
  });

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

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event) => {
    event.preventDefault();
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
    apiBaseUrl: SDK_CONFIG.getApiBaseUrl(app.isPackaged),
    catalog: SDK_CONFIG.softwareCatalog
  };
});

ipcMain.handle('auth:verify-key', async (_event, keyInput) => {
  const cleanKey = String(keyInput || '').trim().toUpperCase();
  if (!cleanKey) {
    return { ok: false, error: 'Please enter a license key' };
  }

  const detectedTool = await detectAnalysisTools();
  if (detectedTool) {
    sendTelemetry('anti_tamper_alert', `Analysis tool active during auth: ${detectedTool}`, cleanKey);
    return { ok: false, error: 'Security alert: close debugging/sniffing tools and retry' };
  }

  const hwid = getDeviceHwid();
  const nonce = crypto.randomBytes(12).toString('hex');
  const apiUrl = SDK_CONFIG.getApiBaseUrl(app.isPackaged);

  try {
    const res = await postJson(`${apiUrl}/api/v1/auth/verify`, {
      key: cleanKey,
      hwid,
      nonce
    });

    if (res.status !== 200 || !res.data || !res.data.payload) {
      return { ok: false, error: (res.data && res.data.error) || 'License verification rejected' };
    }

    const { payload, signature } = res.data;
    if (!verifyEd25519Signature(payload, signature)) {
      sendTelemetry('anti_tamper_alert', 'Invalid Ed25519 auth signature received', cleanKey);
      return { ok: false, error: 'Tamper check failed: invalid Ed25519 signature' };
    }
    if (payload.nonce !== nonce || payload.hwid !== hwid) {
      return { ok: false, error: 'Session mismatch detected' };
    }
    if (Math.abs(Date.now() - Number(payload.issuedAt || 0)) > 60_000) {
      return { ok: false, error: 'Stale license response rejected' };
    }

    activeSession = { ...payload, key: cleanKey, mode: 'online-ed25519' };
    return { ok: true, session: activeSession };
  } catch (err) {
    return {
      ok: false,
      error: `Backend unreachable (${apiUrl}). Start server: npm run server`
    };
  }
});

ipcMain.handle('auth:logout', () => {
  activeSession = null;
  return { ok: true };
});

ipcMain.handle('software:launch', async (_event, { productId, branch }) => {
  if (!activeSession || !activeSession.sessionId) {
    return { ok: false, error: 'Not authenticated' };
  }

  const detectedTool = await detectAnalysisTools();
  if (detectedTool) {
    sendTelemetry('anti_tamper_alert', `Analysis tool active during launch: ${detectedTool}`, activeSession.key);
    return { ok: false, error: 'Security alert: debugging/sniffing tool detected' };
  }

  const hwid = getDeviceHwid();
  const nonce = crypto.randomBytes(12).toString('hex');
  const apiUrl = SDK_CONFIG.getApiBaseUrl(app.isPackaged);

  try {
    // Request a fresh server-signed launch ticket (no offline launch allowed)
    const res = await postJson(`${apiUrl}/api/v1/software/authorize`, {
      sessionId: activeSession.sessionId,
      hwid,
      productId,
      branch,
      nonce
    });

    if (res.status !== 200 || !res.data || !res.data.payload) {
      return { ok: false, error: (res.data && res.data.error) || 'Backend rejected launch' };
    }

    const { payload, signature } = res.data;
    if (payload.nonce !== nonce || payload.hwid !== hwid) {
      return { ok: false, error: 'Launch ticket mismatch' };
    }

    const result = await executeLaunchHook({
      productId,
      branch,
      ticketPayload: payload,
      ticketSignature: signature
    });
    return result;
  } catch (err) {
    return { ok: false, error: err.message || 'Launch authorization failed' };
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
