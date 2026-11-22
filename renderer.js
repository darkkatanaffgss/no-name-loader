(function () {
  const isElectron = Boolean(window.electronAPI && window.electronAPI.isElectron);
  if (isElectron) {
    document.body.classList.add('is-electron');
  }

  const authGate = document.getElementById('authGate');
  const workspace = document.getElementById('workspace');
  const licenseInput = document.getElementById('licenseInput');
  const authError = document.getElementById('authError');
  const authSubmitBtn = document.getElementById('authSubmitBtn');
  const authBtnText = document.getElementById('authBtnText');

  const navItems = document.querySelectorAll('.nav-item');
  const userBtn = document.getElementById('userBtn');
  const topLinksHome = document.getElementById('topLinksHome');
  const topLinksSoftware = document.getElementById('topLinksSoftware');

  const views = {
    home: document.getElementById('view-home'),
    software: document.getElementById('view-software'),
    user: document.getElementById('view-user')
  };

  const branches = ['Nightly', 'Beta', 'Stable'];

  const softwareData = {
    cs2: {
      title: 'Counter-Strike 2',
      subtitle: 'Source 2 Engine • x64 Profile',
      icon: 'assets/cs2.png',
      banner: 'assets/banner-cs2.jpg',
      updated: 'Nov 13 2026 (16:15 PM)',
      lastLaunch: 'Last Month',
      branchIdx: 0,
      changelog: [
        'Updated UI layout with rounded game banner',
        'Integrated HMAC-signed subscription verification',
        'Improved branch switcher and session status'
      ]
    },
    csgo: {
      title: 'Counter-Strike: Global Offensive',
      subtitle: 'Legacy Build • DirectX 9 Profile',
      icon: 'assets/csgo.png',
      banner: 'assets/banner-csgo.jpg',
      updated: 'Nov 10 2026 (12:40 PM)',
      lastLaunch: '2 Weeks Ago',
      branchIdx: 2,
      changelog: [
        'Added dark tactical banner artwork',
        'Added HWID-locked session validation',
        'Updated branch selector controls'
      ]
    },
    minecraft: {
      title: 'Minecraft',
      subtitle: 'Java / Client Profile • 1.21+',
      icon: 'assets/minecraft.png',
      banner: 'assets/banner-minecraft.jpg',
      updated: 'Nov 18 2026 (19:05 PM)',
      lastLaunch: 'Yesterday',
      branchIdx: 1,
      changelog: [
        'Added custom voxel night banner artwork',
        'Added release channel switcher (Nightly / Beta / Stable)',
        'Connected license entitlement checks'
      ]
    }
  };

  const articles = {
    'update-1': {
      date: 'Build v2.1',
      title: 'no name Loader — Glass & Rounded Design',
      paragraphs: [
        'Refined 20px rounded window shell with zero corner artifacts, darker translucent sidebar, hidden scrollbars, and atmospheric game banners.',
        'Topbar navigation uses clean non-draggable button elements so hovering or dragging never shows file paths.'
      ]
    },
    'update-2': {
      date: 'Open-Source',
      title: 'License API, HWID Lock & Developer SDK',
      paragraphs: [
        'The repository ships with a complete Node.js license server (api-server/server.js) supporting HWID locking, expiration dates, branch entitlements, and HMAC-SHA256 signed responses.',
        'Developers can customize sdk/loader-sdk.js to integrate their own backend URL and authorized launch workflow.'
      ]
    }
  };

  const i18n = {
    en: {
      authTitle: 'License Activation',
      authSub: 'Enter your subscription key bound to this device',
      signIn: 'Sign In',
      signOut: 'Sign Out',
      about: 'ABOUT',
      home: 'Home',
      software: 'SOFTWARE',
      details: 'Details',
      market: 'Market',
      apiDocs: 'API Documentation',
      upToDate: 'The software is up to date',
      updated: 'Updated',
      subscription: 'Subscription',
      lastLaunch: 'Last Launch',
      branch: 'Branch',
      launch: 'Launch'
    },
    ru: {
      authTitle: 'Активация лицензии',
      authSub: 'Введите ключ подписки, привязанный к устройству',
      signIn: 'Войти',
      signOut: 'Выйти',
      about: 'ОБЗОР',
      home: 'Главная',
      software: 'ПРОГРАММЫ',
      details: 'Подробнее',
      market: 'Маркет',
      apiDocs: 'API Документация',
      upToDate: 'ПО обновлено до актуальной версии',
      updated: 'Обновлено',
      subscription: 'Подписка',
      lastLaunch: 'Последний запуск',
      branch: 'Ветка',
      launch: 'Запустить'
    }
  };

  let currentSoftwareKey = 'cs2';
  let currentLang = 'en';
  let activeSession = null;

  function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('show'), 2100);
  }

  function formatExpiry(iso) {
    if (!iso || iso === 'Lifetime') return 'Lifetime';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    });
  }

  async function initDeviceInfo() {
    if (isElectron) {
      const info = await window.electronAPI.getDeviceInfo();
      document.getElementById('authHwidPreview').textContent = `${info.hwid.slice(0, 10)}…`;
    } else {
      document.getElementById('authHwidPreview').textContent = 'BROWSER-PREVIEW';
      document.getElementById('authApiMode').textContent = 'Preview Mode';
    }
  }
  initDeviceInfo();

  function enterWorkspace(session) {
    activeSession = session;
    authGate.classList.add('hidden');
    workspace.classList.remove('hidden');

    document.getElementById('sidebarUsername').textContent = session.username || 'User';
    document.getElementById('userLicenseTitle').textContent = `${session.username} (${session.tier})`;
    document.getElementById('userLicenseMeta').textContent = `Expires: ${formatExpiry(session.expiresAt)} • Mode: ${session.mode}`;
    document.getElementById('userKeyBadge').textContent = `Key: ${session.key.slice(0, 7)}••••${session.key.slice(-4)}`;
    document.getElementById('userHwidBadge').textContent = `HWID: ${session.hwid.slice(0, 12)}…`;

    switchView('home');
  }

  async function handleSignIn() {
    const key = licenseInput.value.trim().toUpperCase();
    authError.textContent = '';

    if (!key) {
      authError.textContent = 'Enter a license key (or click Demo)';
      return;
    }

    authSubmitBtn.disabled = true;
    authBtnText.textContent = 'Checking...';

    try {
      if (isElectron) {
        const res = await window.electronAPI.verifyLicense(key);
        if (!res.ok) {
          authError.textContent = res.error || 'Verification failed';
        } else {
          enterWorkspace(res.session);
          showToast(`Welcome, ${res.session.username}`);
        }
      } else {
        if (key === 'NN-DEMO-2026-OPEN' || key === 'NN-PRO-30D-8492') {
          enterWorkspace({
            valid: true,
            key,
            username: key === 'NN-DEMO-2026-OPEN' ? 'Developer' : 'User',
            tier: key === 'NN-DEMO-2026-OPEN' ? 'Enterprise' : 'Pro',
            expiresAt: '2035-05-09T03:00:00.000Z',
            products: ['cs2', 'csgo', 'minecraft'],
            branches: ['Stable', 'Beta', 'Nightly'],
            hwid: 'BROWSER-PREVIEW-HWID',
            mode: 'browser-preview'
          });
        } else {
          authError.textContent = 'Preview mode: click "Demo" to use NN-DEMO-2026-OPEN';
        }
      }
    } finally {
      authSubmitBtn.disabled = false;
      authBtnText.textContent = i18n[currentLang].signIn;
    }
  }

  document.getElementById('demoFillBtn').addEventListener('click', () => {
    licenseInput.value = 'NN-DEMO-2026-OPEN';
    authError.textContent = '';
  });

  authSubmitBtn.addEventListener('click', handleSignIn);
  licenseInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSignIn();
  });

  document.getElementById('logoutBtn').addEventListener('click', async () => {
    if (isElectron) await window.electronAPI.logout();
    activeSession = null;
    workspace.classList.add('hidden');
    authGate.classList.remove('hidden');
    authError.textContent = '';
    showToast('Signed out');
  });

  function resetLaunchState() {
    const btn = document.getElementById('launchBtn');
    const txt = document.getElementById('launchBtnText');
    const banner = document.getElementById('swBannerText');
    btn.disabled = false;
    txt.textContent = i18n[currentLang].launch;
    banner.textContent = i18n[currentLang].upToDate;
  }

  function switchView(target) {
    Object.values(views).forEach((v) => v.classList.remove('active'));
    navItems.forEach((btn) => btn.classList.remove('active'));
    userBtn.classList.remove('active');

    if (target === 'home') {
      topLinksHome.classList.remove('hidden');
      topLinksSoftware.classList.add('hidden');
      views.home.classList.add('active');
      document.querySelector('[data-tab="home"]').classList.add('active');
    } else if (target === 'user') {
      topLinksHome.classList.remove('hidden');
      topLinksSoftware.classList.add('hidden');
      views.user.classList.add('active');
      userBtn.classList.add('active');
    } else if (softwareData[target]) {
      currentSoftwareKey = target;
      const data = softwareData[target];
      const clickedBtn = document.querySelector(`[data-tab="${target}"]`);
      clickedBtn.classList.add('active');

      topLinksHome.classList.add('hidden');
      topLinksSoftware.classList.remove('hidden');

      document.getElementById('swTitle').textContent = data.title;
      document.getElementById('swSubtitle').textContent = data.subtitle;
      document.getElementById('swIcon').src = data.icon;
      document.getElementById('swBannerImg').src = data.banner;
      document.getElementById('swUpdated').textContent = data.updated;
      document.getElementById('swSub').textContent = activeSession ? formatExpiry(activeSession.expiresAt) : '—';
      document.getElementById('swLastLaunch').textContent = data.lastLaunch;
      document.getElementById('branchName').textContent = branches[data.branchIdx];

      resetLaunchState();
      views.software.classList.add('active');
    }
  }

  navItems.forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.tab));
  });

  userBtn.addEventListener('click', () => switchView('user'));

  document.querySelectorAll('.top-link').forEach((link) => {
    if (link.id === 'openApiDocsHome' || link.id === 'openApiDocsSw') return;
    link.addEventListener('click', () => {
      const url = link.dataset.url;
      if (isElectron) {
        window.electronAPI.openExternal(url);
      } else {
        showToast(`${link.textContent} (${url})`);
      }
    });
  });

  function minimizeWindow() {
    if (isElectron) {
      window.electronAPI.minimize();
    } else {
      const shell = document.getElementById('appShell');
      shell.classList.toggle('minimized');
      setTimeout(() => shell.classList.remove('minimized'), 650);
    }
  }

  function closeWindow() {
    if (isElectron) {
      window.electronAPI.close();
    } else {
      showToast('Close works natively in Electron');
    }
  }

  document.getElementById('minBtn').addEventListener('click', minimizeWindow);
  document.getElementById('authMinBtn').addEventListener('click', minimizeWindow);
  document.getElementById('closeBtn').addEventListener('click', closeWindow);
  document.getElementById('authCloseBtn').addEventListener('click', closeWindow);

  const modal = document.getElementById('articleModal');
  function openModal(dateText, titleText, lines, codeBlock) {
    document.getElementById('modalDate').textContent = dateText;
    document.getElementById('modalTitle').textContent = titleText;
    const body = document.getElementById('modalBody');
    body.innerHTML = '';
    lines.forEach((text) => {
      const p = document.createElement('p');
      p.textContent = text;
      body.appendChild(p);
    });
    if (codeBlock) {
      const pre = document.createElement('pre');
      pre.className = 'modal-code';
      pre.textContent = codeBlock;
      body.appendChild(pre);
    }
    modal.classList.add('open');
  }

  function openApiDocsModal() {
    openModal(
      'Open-Source API',
      'License Verification & SDK Reference',
      [
        '1. Start the bundled license server: npm run server (port 3840).',
        '2. Issue keys via POST /api/v1/admin/keys with x-admin-secret.',
        '3. Client sends key + hardware ID + nonce; server returns an HMAC-SHA256 signed session payload.'
      ],
      'POST /api/v1/auth/verify\n{ "key": "NN-DEMO-2026-OPEN", "hwid": "...", "nonce": "..." }\n\nSDK Hook -> sdk/loader-sdk.js: executeLaunchHook({ productId, branch, session })'
    );
  }

  document.getElementById('openApiDocsHome').addEventListener('click', openApiDocsModal);
  document.getElementById('openApiDocsSw').addEventListener('click', openApiDocsModal);

  document.querySelectorAll('.read-more-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const art = articles[btn.dataset.article];
      if (art) openModal(art.date, art.title, art.paragraphs);
    });
  });

  document.getElementById('historyBtn').addEventListener('click', () => {
    const data = softwareData[currentSoftwareKey];
    openModal(data.updated, `${data.title} — Changelog`, data.changelog.map((c) => `• ${c}`));
  });

  document.getElementById('modalClose').addEventListener('click', () => modal.classList.remove('open'));
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('open');
  });

  document.getElementById('branchCycleBtn').addEventListener('click', () => {
    const data = softwareData[currentSoftwareKey];
    data.branchIdx = (data.branchIdx + 1) % branches.length;
    const nextBranch = branches[data.branchIdx];
    document.getElementById('branchName').textContent = nextBranch;
    showToast(`Branch: ${nextBranch}`);
  });

  document.getElementById('shareBtn').addEventListener('click', () => {
    showToast('Session & branch config copied');
  });

  document.getElementById('optionsBtn').addEventListener('click', () => {
    showToast('SDK launch hook: sdk/loader-sdk.js');
  });

  document.getElementById('presetBtn').addEventListener('click', () => {
    showToast('Display preset toggled');
  });

  const launchOverlay = document.getElementById('launchOverlay');
  const launchOverlayIcon = document.getElementById('launchOverlayIcon');
  const launchOverlayTitle = document.getElementById('launchOverlayTitle');
  const launchOverlayFill = document.getElementById('launchOverlayFill');
  const launchOverlayStatus = document.getElementById('launchOverlayStatus');

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  document.getElementById('launchBtn').addEventListener('click', async () => {
    const btn = document.getElementById('launchBtn');
    const banner = document.getElementById('swBannerText');
    const data = softwareData[currentSoftwareKey];
    const selectedBranch = branches[data.branchIdx];

    btn.disabled = true;
    launchOverlayIcon.src = data.icon;
    launchOverlayTitle.textContent = data.title;
    launchOverlayFill.style.width = '0%';
    launchOverlayStatus.textContent = currentLang === 'ru' ? 'Проверка лицензии...' : 'Verifying license...';
    launchOverlay.classList.add('open');

    await sleep(160);
    launchOverlayFill.style.width = '28%';

    if (isElectron) {
      const res = await window.electronAPI.launchSoftware({
        productId: currentSoftwareKey,
        branch: selectedBranch
      });
      if (!res.ok) {
        launchOverlayFill.style.width = '0%';
        launchOverlayStatus.textContent = res.error || 'Access denied';
        banner.textContent = res.error || 'Access denied';
        showToast(res.error || 'Access denied');
        await sleep(1200);
        launchOverlay.classList.remove('open');
        resetLaunchState();
        return;
      }
      banner.textContent = res.message;
    }

    await sleep(320);
    launchOverlayFill.style.width = '64%';
    launchOverlayStatus.textContent = currentLang === 'ru'
      ? `Подготовка профиля (${selectedBranch})...`
      : `Preparing ${selectedBranch} profile...`;

    await sleep(480);
    launchOverlayFill.style.width = '100%';
    launchOverlayStatus.textContent = currentLang === 'ru' ? 'Готово!' : 'Ready!';

    await sleep(650);
    launchOverlay.classList.remove('open');
    showToast(`${data.title} (${selectedBranch}) ready`);
    setTimeout(() => {
      launchOverlayFill.style.width = '0%';
      resetLaunchState();
    }, 300);
  });

  const blurSlider = document.getElementById('blurSlider');
  const opacitySlider = document.getElementById('opacitySlider');

  blurSlider.addEventListener('input', () => {
    const val = `${blurSlider.value}px`;
    document.documentElement.style.setProperty('--blur-amount', val);
    document.getElementById('blurVal').textContent = val;
  });

  opacitySlider.addEventListener('input', () => {
    const alpha = (Number(opacitySlider.value) / 100).toFixed(2);
    document.documentElement.style.setProperty('--sidebar-alpha', alpha);
    document.getElementById('opacityVal').textContent = `${opacitySlider.value}%`;
  });

  document.querySelectorAll('#langPills .branch-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#langPills .branch-pill').forEach((p) => p.classList.remove('active'));
      pill.classList.add('active');
      currentLang = pill.dataset.lang;
      const dict = i18n[currentLang];
      document.querySelectorAll('[data-i18n]').forEach((el) => {
        const key = el.dataset.i18n;
        if (dict[key]) el.textContent = dict[key];
      });
      showToast(currentLang === 'ru' ? 'Язык: Русский' : 'Language: English');
    });
  });
})();
