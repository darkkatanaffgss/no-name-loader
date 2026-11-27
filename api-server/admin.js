(function () {
  const secretInput = document.getElementById('adminSecret');
  const connectBtn = document.getElementById('connectBtn');
  const logoutAdminBtn = document.getElementById('logoutAdminBtn');
  const dashboard = document.getElementById('dashboard');
  const errBox = document.getElementById('errBox');
  let bearerToken = '';

  async function api(path, method = 'GET', body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (bearerToken) {
      headers.Authorization = `Bearer ${bearerToken}`;
    }
    const res = await fetch(path, {
      method,
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

  function makeActionBtn(label, className, onClick) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    if (className) btn.className = className;
    btn.addEventListener('click', onClick);
    return btn;
  }

  async function refresh() {
    if (!bearerToken) return;
    errBox.textContent = '';

    const { status, data } = await api('/api/v1/admin/analytics');
    if (status === 401 || !data.ok) {
      bearerToken = '';
      dashboard.style.display = 'none';
      logoutAdminBtn.classList.add('hidden');
      connectBtn.classList.remove('hidden');
      secretInput.classList.remove('hidden');
      errBox.textContent = data.error || 'Session expired. Sign in again.';
      return;
    }

    dashboard.style.display = 'flex';
    document.getElementById('sTotal').textContent = data.stats.totalLicenses;
    document.getElementById('sActive').textContent = data.stats.activeLicenses;
    document.getElementById('sSessions').textContent = data.stats.activeSessions;
    document.getElementById('sLaunches').textContent = data.stats.totalLaunches;
    document.getElementById('sAlerts').textContent = data.stats.securityAlerts;

    const lBody = document.getElementById('licensesBody');
    lBody.innerHTML = '';
    for (const lic of data.licenses) {
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(lic.key, true));
      tr.appendChild(makeCell(lic.username));
      tr.appendChild(makeCell(lic.tier));
      tr.appendChild(makeCell(lic.hwid ? `${lic.hwid.slice(0, 10)}…` : 'Unbound', true));
      tr.appendChild(makeCell(String(lic.launchCount)));

      const statusTd = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = `pill ${lic.revoked ? 'red' : 'green'}`;
      pill.textContent = lic.revoked ? 'Revoked' : 'Active';
      statusTd.appendChild(pill);
      tr.appendChild(statusTd);

      const actTd = document.createElement('td');
      actTd.className = 'actions';
      actTd.appendChild(makeActionBtn('Copy', '', () => navigator.clipboard.writeText(lic.key)));
      actTd.appendChild(makeActionBtn('Reset HWID', '', () => keyAction('reset-hwid', lic.key)));
      actTd.appendChild(
        makeActionBtn(lic.revoked ? 'Restore' : 'Revoke', '', () =>
          keyAction(lic.revoked ? 'unrevoke' : 'revoke', lic.key)
        )
      );
      actTd.appendChild(makeActionBtn('Delete', 'danger', () => keyAction('delete', lic.key)));
      tr.appendChild(actTd);
      lBody.appendChild(tr);
    }

    const eBody = document.getElementById('eventsBody');
    eBody.innerHTML = '';
    for (const ev of data.recentEvents) {
      const isAlert = ['anti_tamper_alert', 'hwid_mismatch', 'replay_detected', 'admin_bruteforce_blocked'].includes(
        ev.event_type
      );
      const tr = document.createElement('tr');
      tr.appendChild(makeCell(new Date(ev.created_at).toLocaleTimeString()));

      const evTd = document.createElement('td');
      const evPill = document.createElement('span');
      evPill.className = `pill ${isAlert ? 'red' : ''}`;
      evPill.textContent = ev.event_type;
      evTd.appendChild(evPill);
      tr.appendChild(evTd);

      tr.appendChild(makeCell(ev.license_key || '—', true));
      tr.appendChild(makeCell(ev.product_id ? `${ev.product_id} / ${ev.branch || ''}` : '—'));
      tr.appendChild(makeCell(ev.details || ''));
      eBody.appendChild(tr);
    }
  }

  async function keyAction(action, key) {
    await api('/api/v1/admin/keys', 'POST', { action, key });
    await refresh();
  }

  connectBtn.addEventListener('click', async () => {
    errBox.textContent = '';
    const secret = secretInput.value.trim();
    if (!secret) {
      errBox.textContent = 'Enter ADMIN_SECRET from api-server/.env';
      return;
    }

    const { data } = await api('/api/v1/admin/login', 'POST', { secret });
    if (!data.ok || !data.token) {
      errBox.textContent = data.error || 'Authentication failed';
      return;
    }

    bearerToken = data.token;
    secretInput.value = '';
    secretInput.classList.add('hidden');
    connectBtn.classList.add('hidden');
    logoutAdminBtn.classList.remove('hidden');
    await refresh();
  });

  logoutAdminBtn.addEventListener('click', async () => {
    await api('/api/v1/admin/logout', 'POST');
    bearerToken = '';
    dashboard.style.display = 'none';
    logoutAdminBtn.classList.add('hidden');
    connectBtn.classList.remove('hidden');
    secretInput.classList.remove('hidden');
  });

  document.getElementById('createKeyBtn').addEventListener('click', async () => {
    const products = [...document.querySelectorAll('.prod-chk:checked')].map((c) => c.value);
    const branches = [...document.querySelectorAll('.br-chk:checked')].map((c) => c.value);
    await api('/api/v1/admin/keys', 'POST', {
      action: 'create',
      username: document.getElementById('newUser').value || 'Customer',
      tier: document.getElementById('newTier').value,
      days: document.getElementById('newDays').value,
      products,
      branches
    });
    await refresh();
  });
})();
