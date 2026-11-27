(function () {
  const secretInput = document.getElementById('adminSecret');
  const connectBtn = document.getElementById('connectBtn');
  const autoRefreshBtn = document.getElementById('autoRefreshBtn');
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  const logoutAdminBtn = document.getElementById('logoutAdminBtn');
  const dashboard = document.getElementById('dashboard');
  const errBox = document.getElementById('errBox');

  let csrfToken = '';
  let autoRefresh = true;
  let refreshTimer = null;
  let lastSnapshot = null;

  function toHex(buffer) {
    return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function computeChallengeProof(secret, challenge) {
    if (!window.crypto || !window.crypto.subtle) {
      return { fallbackSecret: secret };
    }
    const enc = new TextEncoder();
    const digestBuf = await window.crypto.subtle.digest('SHA-512', enc.encode(secret));
    const digestHex = toHex(digestBuf);
    const hmacKey = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(digestHex),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuf = await window.crypto.subtle.sign('HMAC', hmacKey, enc.encode(challenge));
    return { proof: toHex(sigBuf) };
  }

  async function api(path, method = 'GET', body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (csrfToken && method === 'POST') {
      headers['x-csrf-token'] = csrfToken;
    }
    const res = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers,
      body: body ? JSON.stringify(body) : null
    });
    return { status: res.status, data: await res.json() };
  }

  function makeCell(text, isCode = false) {
    const td = document.createElement('td');
    if (isCode) {
      const code = document.createElement('code');
      code.textContent = text;
      td.appendChild(code);
    } else {
      td.textContent = text;
    }
    return td;
  }

  function makePillCell(text, variant = '') {
    const td = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `pill ${variant}`.trim();
    pill.textContent = text;
    td.appendChild(pill);
    return td;
  }

  function makeActionBtn(label, className, onClick) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    if (className) btn.className = className;
    btn.addEventListener('click', onClick);
    return btn;
  }

  function setLoggedInUi(loggedIn) {
    dashboard.style.display = loggedIn ? 'flex' : 'none';
    [autoRefreshBtn, exportJsonBtn, logoutAdminBtn].forEach((el) =>
      el.classList.toggle('hidden', !loggedIn)
    );
    [secretInput, connectBtn].forEach((el) => el.classList.toggle('hidden', loggedIn));
    if (!loggedIn) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    } else {
      startAutoRefresh();
    }
  }

  function startAutoRefresh() {
    clearInterval(refreshTimer);
    if (autoRefresh) {
      refreshTimer = setInterval(refresh, 5000);
    }
  }

  function renderTables(data) {
    lastSnapshot = data;
    document.getElementById('sKeys').textContent = `${data.stats.totalLicenses} / ${data.stats.activeLicenses}`;
    document.getElementById('sSessions').textContent = data.stats.activeSessions;
    document.getElementById('sLaunches').textContent = data.stats.totalLaunches;
    document.getElementById('sRpm').textContent = data.stats.rpm;
    document.getElementById('sLatency').textContent = `${data.stats.avgLatencyMs} ms`;
    document.getElementById('sAlerts').textContent = `${data.stats.securityAlerts} / ${data.stats.bannedCount}`;

    // 1. Licenses
    const lBody = document.getElementById('licensesBody');
    lBody.innerHTML = '';
    for (const lic of data.licenses) {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(lic.key, true));
      tr.appendChild(makeCell(lic.username));
      tr.appendChild(makeCell(lic.tier));
      tr.appendChild(makeCell(lic.hwid ? `${lic.hwid.slice(0, 10)}…` : 'Unbound', true));
      tr.appendChild(makeCell(String(lic.launchCount)));
      tr.appendChild(makePillCell(lic.revoked ? 'Revoked' : 'Active', lic.revoked ? 'red' : 'green'));

      const actTd = document.createElement('td');
      actTd.className = 'actions';
      actTd.appendChild(makeActionBtn('Copy', '', () => navigator.clipboard.writeText(lic.key)));
      actTd.appendChild(makeActionBtn('Reset HWID', '', () => postAction('/api/v1/admin/keys', { action: 'reset-hwid', key: lic.key })));
      actTd.appendChild(
        makeActionBtn(lic.revoked ? 'Restore' : 'Revoke', '', () =>
          postAction('/api/v1/admin/keys', { action: lic.revoked ? 'unrevoke' : 'revoke', key: lic.key })
        )
      );
      actTd.appendChild(makeActionBtn('Delete', 'danger', () => postAction('/api/v1/admin/keys', { action: 'delete', key: lic.key })));
      tr.appendChild(actTd);
      lBody.appendChild(tr);
    }

    // 2. Traffic Logs
    const tFilter = document.getElementById('trafficFilter').value;
    const tBody = document.getElementById('trafficBody');
    tBody.innerHTML = '';
    for (const log of data.trafficLogs || []) {
      if (tFilter === '2xx' && (log.status_code < 200 || log.status_code >= 300)) continue;
      if (tFilter === '4xx' && log.status_code < 400) continue;
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(new Date(log.created_at).toLocaleTimeString()));
      tr.appendChild(makeCell(log.method, true));
      tr.appendChild(makeCell(log.path, true));
      tr.appendChild(makeCell(log.ip, true));
      const statusVariant = log.status_code >= 400 ? 'red' : 'green';
      tr.appendChild(makePillCell(String(log.status_code), statusVariant));
      tr.appendChild(makeCell(`${log.latency_ms} ms`));
      tr.appendChild(makeCell((log.user_agent || '—').slice(0, 32)));
      const act = document.createElement('td');
      act.className = 'actions';
      act.appendChild(makeActionBtn('Ban IP', 'danger', () => postAction('/api/v1/admin/ips', { action: 'ban', ip: log.ip, reason: `Flagged on ${log.path}` })));
      tr.appendChild(act);
      tBody.appendChild(tr);
    }

    // 3. Active Sessions & Banned IPs
    const sBody = document.getElementById('sessionsBody');
    sBody.innerHTML = '';
    for (const sess of data.activeSessions || []) {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(`${sess.session_id.slice(0, 12)}…`, true));
      tr.appendChild(makeCell(sess.license_key, true));
      tr.appendChild(makeCell(`${sess.hwid.slice(0, 10)}…`, true));
      tr.appendChild(makeCell(sess.ip || '—', true));
      tr.appendChild(makeCell(new Date(sess.expires_at).toLocaleTimeString()));
      const act = document.createElement('td');
      act.className = 'actions';
      act.appendChild(makeActionBtn('Kick', 'danger', () => postAction('/api/v1/admin/sessions/kick', { sessionId: sess.session_id })));
      tr.appendChild(act);
      sBody.appendChild(tr);
    }

    const bBody = document.getElementById('bansBody');
    bBody.innerHTML = '';
    for (const b of data.bannedIps || []) {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(b.ip, true));
      tr.appendChild(makeCell(b.reason || '—'));
      tr.appendChild(makeCell(new Date(b.blocked_at).toLocaleString()));
      const act = document.createElement('td');
      act.className = 'actions';
      act.appendChild(makeActionBtn('Unban', '', () => postAction('/api/v1/admin/ips', { action: 'unban', ip: b.ip })));
      tr.appendChild(act);
      bBody.appendChild(tr);
    }

    // 4. Security & Events
    const eFilter = document.getElementById('eventFilter').value;
    const eBody = document.getElementById('eventsBody');
    eBody.innerHTML = '';
    const alertTypes = new Set(['anti_tamper_alert', 'hwid_mismatch', 'replay_detected', 'admin_bruteforce_blocked', 'banned_ip_blocked', 'admin_session_hijack_blocked']);
    for (const ev of data.recentEvents || []) {
      const isAlert = alertTypes.has(ev.event_type);
      if (eFilter === 'alerts' && !isAlert) continue;
      if (eFilter === 'launches' && ev.event_type !== 'launch_authorized') continue;
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(new Date(ev.created_at).toLocaleTimeString()));
      tr.appendChild(makePillCell(ev.event_type, isAlert ? 'red' : ev.event_type === 'launch_authorized' ? 'green' : ''));
      tr.appendChild(makeCell(ev.license_key || '—', true));
      tr.appendChild(makeCell(ev.ip || '—', true));
      tr.appendChild(makeCell(ev.product_id ? `${ev.product_id} / ${ev.branch || ''}` : '—'));
      tr.appendChild(makeCell(ev.details || ''));
      eBody.appendChild(tr);
    }
  }

  async function refresh() {
    errBox.textContent = '';
    const { status, data } = await api('/api/v1/admin/analytics');
    if (status === 401 || !data.ok) {
      csrfToken = '';
      setLoggedInUi(false);
      errBox.textContent = data.error || 'Session expired. Sign in again.';
      return;
    }
    renderTables(data);
  }

  async function postAction(endpoint, payload) {
    const { data } = await api(endpoint, 'POST', payload);
    if (!data.ok && data.error) errBox.textContent = data.error;
    await refresh();
  }

  // Challenge-Response Admin Login
  connectBtn.addEventListener('click', async () => {
    errBox.textContent = '';
    const secret = secretInput.value.trim();
    if (!secret) {
      errBox.textContent = 'Enter ADMIN_SECRET from api-server/.env';
      return;
    }

    const ch = await api('/api/v1/admin/challenge');
    if (!ch.data.ok || !ch.data.challenge) {
      errBox.textContent = ch.data.error || 'Failed to obtain auth challenge';
      return;
    }

    const proofObj = await computeChallengeProof(secret, ch.data.challenge);
    const body = proofObj.proof
      ? { challenge: ch.data.challenge, proof: proofObj.proof }
      : { secret: proofObj.fallbackSecret };

    const login = await api('/api/v1/admin/login', 'POST', body);
    if (!login.data.ok || !login.data.csrfToken) {
      errBox.textContent = login.data.error || 'Authentication failed';
      return;
    }

    csrfToken = login.data.csrfToken;
    secretInput.value = '';
    setLoggedInUi(true);
    await refresh();
  });

  logoutAdminBtn.addEventListener('click', async () => {
    await api('/api/v1/admin/logout', 'POST');
    csrfToken = '';
    setLoggedInUi(false);
  });

  autoRefreshBtn.addEventListener('click', () => {
    autoRefresh = !autoRefresh;
    autoRefreshBtn.textContent = autoRefresh ? 'Live: ON (5s)' : 'Live: OFF';
    startAutoRefresh();
  });

  exportJsonBtn.addEventListener('click', () => {
    if (!lastSnapshot) return;
    const blob = new Blob([JSON.stringify(lastSnapshot, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `noname-analytics-${Date.now()}.json`;
    a.click();
  });

  document.getElementById('refreshNowBtn').addEventListener('click', refresh);
  document.getElementById('clearLogsBtn').addEventListener('click', () => postAction('/api/v1/admin/logs/clear', {}));
  document.getElementById('trafficFilter').addEventListener('change', () => lastSnapshot && renderTables(lastSnapshot));
  document.getElementById('eventFilter').addEventListener('change', () => lastSnapshot && renderTables(lastSnapshot));

  document.getElementById('banIpBtn').addEventListener('click', () => {
    const ip = document.getElementById('banIpInput').value.trim();
    const reason = document.getElementById('banReasonInput').value.trim();
    if (!ip) return;
    postAction('/api/v1/admin/ips', { action: 'ban', ip, reason });
    document.getElementById('banIpInput').value = '';
  });

  document.getElementById('createKeyBtn').addEventListener('click', () => {
    const products = [...document.querySelectorAll('.prod-chk:checked')].map((c) => c.value);
    const branches = [...document.querySelectorAll('.br-chk:checked')].map((c) => c.value);
    postAction('/api/v1/admin/keys', {
      action: 'create',
      username: document.getElementById('newUser').value || 'Customer',
      tier: document.getElementById('newTier').value,
      days: document.getElementById('newDays').value,
      products,
      branches
    });
  });

  document.querySelectorAll('.admin-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.admin-tab').forEach((b) => b.classList.remove('active-tab'));
      document.querySelectorAll('.subview').forEach((v) => v.classList.remove('active'));
      btn.classList.add('active-tab');
      document.getElementById(`sub-${btn.dataset.sub}`).classList.add('active');
    });
  });
})();
