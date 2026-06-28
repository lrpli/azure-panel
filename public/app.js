const els = {
  loginForm: document.getElementById('loginForm'),
  authStatus: document.getElementById('authStatus'),
  logoutBtn: document.getElementById('logoutBtn'),
  appMain: document.getElementById('appMain'),
  configForm: document.getElementById('configForm'),
  refreshAllBtn: document.getElementById('refreshAllBtn'),
  subscriptionSelect: document.getElementById('subscriptionSelect'),
  locationSelect: document.getElementById('locationSelect'),
  sizeSelect: document.getElementById('sizeSelect'),
  loadLocationsBtn: document.getElementById('loadLocationsBtn'),
  loadSizesBtn: document.getElementById('loadSizesBtn'),
  loadVmsBtn: document.getElementById('loadVmsBtn'),
  vmTableBody: document.getElementById('vmTableBody'),
  createVmForm: document.getElementById('createVmForm'),
  logPanel: document.getElementById('logPanel'),
  imageSelect: document.getElementById('imageSelect'),
  authTypeSelect: document.getElementById('authTypeSelect'),
  networkModeSelect: document.getElementById('networkModeSelect'),
  passwordLabel: document.getElementById('passwordLabel'),
  sshLabel: document.getElementById('sshLabel'),
  nicLabel: document.getElementById('nicLabel'),
  loadAuditBtn: document.getElementById('loadAuditBtn'),
  auditTableBody: document.getElementById('auditTableBody')
};

const state = {
  authenticated: false,
  username: '',
  images: []
};

boot().catch((err) => log(err.message || String(err), true));

async function boot() {
  bindEvents();
  toggleAuthFields();
  toggleNetworkFields();

  await checkAuthState();
  if (state.authenticated) {
    await initializeAppAfterLogin();
  } else {
    log('请先登录再进行 Azure 资源操作。');
  }
}

function bindEvents() {
  els.loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(els.loginForm);
    const payload = Object.fromEntries(fd.entries());

    await withBusy(e.submitter, async () => {
      const result = await api('/api/auth/login', {
        method: 'POST',
        body: payload,
        allowUnauthorized: true
      });
      setAuthenticated(true, result.username || payload.username);
      log(`登录成功: ${result.username || payload.username}`);
      await initializeAppAfterLogin();
      els.loginForm.reset();
    });
  });

  els.logoutBtn.addEventListener('click', async (e) => {
    await withBusy(e.currentTarget, async () => {
      await api('/api/auth/logout', {
        method: 'POST',
        allowUnauthorized: true
      });
      setAuthenticated(false, '');
      clearAppData();
      log('已退出登录。');
    });
  });

  els.configForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!ensureAuthenticated()) {
      return;
    }

    const fd = new FormData(els.configForm);
    const payload = Object.fromEntries(fd.entries());

    await withBusy(e.submitter, async () => {
      await api('/api/config', {
        method: 'POST',
        body: payload
      });
      log('Azure 凭据已保存。');
      await refreshSubscriptions();
      await loadLocations();
      await loadSizes();
      await loadVms();
      await loadAudit();
    });
  });

  els.refreshAllBtn.addEventListener('click', async (e) => {
    if (!ensureAuthenticated()) {
      return;
    }

    await withBusy(e.currentTarget, async () => {
      await refreshSubscriptions();
      await loadLocations();
      await loadSizes();
      await loadVms();
      await loadAudit();
    });
  });

  els.loadLocationsBtn.addEventListener('click', async (e) => {
    if (!ensureAuthenticated()) {
      return;
    }
    await withBusy(e.currentTarget, loadLocations);
  });

  els.loadSizesBtn.addEventListener('click', async (e) => {
    if (!ensureAuthenticated()) {
      return;
    }
    await withBusy(e.currentTarget, loadSizes);
  });

  els.loadVmsBtn.addEventListener('click', async (e) => {
    if (!ensureAuthenticated()) {
      return;
    }
    await withBusy(e.currentTarget, loadVms);
  });

  els.loadAuditBtn.addEventListener('click', async (e) => {
    if (!ensureAuthenticated()) {
      return;
    }
    await withBusy(e.currentTarget, loadAudit);
  });

  els.subscriptionSelect.addEventListener('change', async () => {
    if (!ensureAuthenticated()) {
      return;
    }
    await loadLocations();
    await loadSizes();
    await loadVms();
  });

  els.locationSelect.addEventListener('change', async () => {
    if (!ensureAuthenticated()) {
      return;
    }
    await loadSizes();
  });

  els.authTypeSelect.addEventListener('change', toggleAuthFields);
  els.networkModeSelect.addEventListener('change', toggleNetworkFields);

  els.createVmForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!ensureAuthenticated()) {
      return;
    }

    const fd = new FormData(els.createVmForm);
    const payload = Object.fromEntries(fd.entries());

    payload.subscriptionId = currentSubscription();
    payload.location = els.locationSelect.value;
    payload.vmSize = els.sizeSelect.value;

    await withBusy(e.submitter, async () => {
      const result = await api('/api/vm/create', {
        method: 'POST',
        body: payload
      });
      log(`创建成功: ${result.vm?.name || payload.name}`);
      await loadVms();
      await loadAudit();
    });
  });
}

async function checkAuthState() {
  const me = await api('/api/auth/me', { allowUnauthorized: true });
  if (me.authenticated) {
    setAuthenticated(true, me.username || 'admin');
  } else {
    setAuthenticated(false, '');
  }
}

async function initializeAppAfterLogin() {
  await loadImages();

  const config = await api('/api/config');
  if (config.configured) {
    log('检测到服务端已配置 Azure 凭据，正在加载资源数据...');
    await refreshSubscriptions();
    await loadLocations();
    await loadSizes();
    await loadVms();
  } else {
    log('请先填写 Tenant ID / Client ID / Client Secret。');
    clearVmTable('请先配置 Azure 凭据。');
  }

  await loadAudit();
}

function ensureAuthenticated() {
  if (state.authenticated) {
    return true;
  }
  log('未登录或会话过期，请先登录。', true);
  return false;
}

function setAuthenticated(authenticated, username) {
  state.authenticated = Boolean(authenticated);
  state.username = authenticated ? String(username || '') : '';

  els.appMain.classList.toggle('hidden', !state.authenticated);
  els.logoutBtn.disabled = !state.authenticated;
  els.refreshAllBtn.disabled = !state.authenticated;
  els.authStatus.textContent = state.authenticated ? `已登录: ${state.username}` : '未登录';
}

function clearAppData() {
  fillSelect(els.subscriptionSelect, []);
  fillSelect(els.locationSelect, []);
  fillSelect(els.sizeSelect, []);
  fillSelect(els.imageSelect, []);
  clearVmTable('请先登录。');
  clearAuditTable('请先登录。');
}

function toggleAuthFields() {
  const authType = els.authTypeSelect.value;
  els.passwordLabel.classList.toggle('hidden', authType !== 'password');
  els.sshLabel.classList.toggle('hidden', authType !== 'ssh');
}

function toggleNetworkFields() {
  const mode = els.networkModeSelect.value;
  els.nicLabel.classList.toggle('hidden', mode !== 'existing-nic');
}

async function refreshSubscriptions() {
  const data = await api('/api/subscriptions');
  fillSelect(
    els.subscriptionSelect,
    data.subscriptions.map((s) => ({ value: s.id, label: `${s.displayName} (${s.id})` }))
  );

  if (!data.subscriptions.length) {
    log('未找到可用订阅，请检查服务主体权限。', true);
    return;
  }

  log(`订阅加载完成，共 ${data.subscriptions.length} 个。`);
}

async function loadLocations() {
  const subscriptionId = currentSubscription();
  if (!subscriptionId) {
    return;
  }

  const data = await api(`/api/locations?subscriptionId=${encodeURIComponent(subscriptionId)}`);
  fillSelect(
    els.locationSelect,
    data.locations.map((x) => ({ value: x, label: x }))
  );

  log(`地区加载完成，共 ${data.locations.length} 个。`);
}

async function loadSizes() {
  const subscriptionId = currentSubscription();
  const location = els.locationSelect.value;
  if (!subscriptionId || !location) {
    return;
  }

  const data = await api(
    `/api/vm-sizes?subscriptionId=${encodeURIComponent(subscriptionId)}&location=${encodeURIComponent(location)}`
  );

  fillSelect(
    els.sizeSelect,
    data.sizes.map((s) => ({
      value: s.name,
      label: `${s.name} | ${s.numberOfCores} vCPU | ${(s.memoryInMB / 1024).toFixed(1)} GB`
    }))
  );

  log(`规格加载完成，共 ${data.sizes.length} 个。`);
}

async function loadImages() {
  const data = await api('/api/images');
  state.images = data.images || [];
  fillSelect(
    els.imageSelect,
    state.images.map((img) => ({ value: img.id, label: img.label }))
  );
}

async function loadVms() {
  const subscriptionId = currentSubscription();
  if (!subscriptionId) {
    clearVmTable('请先选择订阅。');
    return;
  }

  const data = await api(`/api/vms?subscriptionId=${encodeURIComponent(subscriptionId)}`);
  const rows = data.vms || [];
  els.vmTableBody.innerHTML = '';

  if (!rows.length) {
    clearVmTable('该订阅暂无虚拟机。');
    return;
  }

  for (const vm of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(vm.name)}</td>
      <td>${escapeHtml(vm.resourceGroup || '-')}</td>
      <td>${escapeHtml(vm.location || '-')}</td>
      <td>${escapeHtml(vm.vmSize || '-')}</td>
      <td>${escapeHtml(vm.powerState || '-')}</td>
      <td>${escapeHtml(vm.provisioningState || '-')}</td>
      <td>
        <div class="cell-actions">
          <button data-action="start">开机</button>
          <button data-action="powerOff">关机</button>
          <button data-action="restart">重启</button>
          <button data-action="deallocate">释放</button>
          <button data-action="delete" class="danger">删除</button>
        </div>
      </td>
    `;

    tr.querySelectorAll('button[data-action]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const action = btn.getAttribute('data-action');
        if (action === 'delete') {
          const ok = window.confirm(`确定删除虚拟机 ${vm.name} ?`);
          if (!ok) {
            return;
          }
        }

        await withBusy(btn, async () => {
          await api('/api/vm/action', {
            method: 'POST',
            body: {
              subscriptionId,
              resourceGroup: vm.resourceGroup,
              name: vm.name,
              action
            }
          });
          log(`操作成功: ${vm.name} -> ${action}`);
          await loadVms();
          await loadAudit();
        });
      });
    });

    els.vmTableBody.appendChild(tr);
  }

  log(`虚拟机加载完成，共 ${rows.length} 台。`);
}

async function loadAudit() {
  const data = await api('/api/audit?limit=120');
  const rows = data.entries || [];
  els.auditTableBody.innerHTML = '';

  if (!rows.length) {
    clearAuditTable('暂无审计记录。');
    return;
  }

  for (const row of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(formatDate(row.time))}</td>
      <td>${escapeHtml(row.actor || '-')}</td>
      <td>${escapeHtml(row.ip || '-')}</td>
      <td>${escapeHtml(row.action || '-')}</td>
      <td>${row.success ? '成功' : '失败'}</td>
      <td>${escapeHtml(formatDetails(row.details))}</td>
    `;
    els.auditTableBody.appendChild(tr);
  }
}

function clearVmTable(message) {
  els.vmTableBody.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `<td colspan="7">${escapeHtml(message)}</td>`;
  els.vmTableBody.appendChild(tr);
}

function clearAuditTable(message) {
  els.auditTableBody.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `<td colspan="6">${escapeHtml(message)}</td>`;
  els.auditTableBody.appendChild(tr);
}

function formatDetails(details) {
  if (!details) {
    return '-';
  }
  const raw = JSON.stringify(details);
  return raw.length > 180 ? `${raw.slice(0, 180)}...` : raw;
}

function formatDate(value) {
  if (!value) {
    return '-';
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    return value;
  }
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function currentSubscription() {
  return els.subscriptionSelect.value || '';
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json'
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && !options.allowUnauthorized) {
      setAuthenticated(false, '');
      clearAppData();
    }

    const message = data.error || `请求失败: ${response.status}`;
    log(message, true);
    throw new Error(message);
  }
  return data;
}

function fillSelect(select, options) {
  select.innerHTML = '';
  if (!options.length) {
    const empty = document.createElement('option');
    empty.value = '';
    empty.textContent = '-';
    select.appendChild(empty);
    return;
  }

  for (const item of options) {
    const opt = document.createElement('option');
    opt.value = item.value;
    opt.textContent = item.label;
    select.appendChild(opt);
  }
}

function escapeHtml(input) {
  return String(input)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function log(text, isError = false) {
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const line = `[${stamp}] ${isError ? 'ERROR' : 'INFO '} ${text}`;
  els.logPanel.textContent = `${line}\n${els.logPanel.textContent}`.slice(0, 16000);
}

async function withBusy(buttonEl, fn) {
  if (!buttonEl) {
    return fn();
  }
  const original = buttonEl.textContent;
  buttonEl.disabled = true;
  buttonEl.textContent = '处理中...';
  try {
    return await fn();
  } finally {
    buttonEl.disabled = false;
    buttonEl.textContent = original;
  }
}
