const els = {
  authBlock: document.getElementById('auth-block'),
  loginForm: document.getElementById('loginForm'),
  authStatus: document.getElementById('authStatus'),
  navAuthStatus: document.getElementById('navAuthStatus'),
  logoutBtn: document.getElementById('logoutBtn'),
  refreshAllBtn: document.getElementById('refreshAllBtn'),
  appMain: document.getElementById('appMain'),

  topSubscriptionChip: document.getElementById('topSubscriptionChip'),
  topLocationChip: document.getElementById('topLocationChip'),
  topVmCountChip: document.getElementById('topVmCountChip'),

  configForm: document.getElementById('configForm'),
  subscriptionSelect: document.getElementById('subscriptionSelect'),
  locationSelect: document.getElementById('locationSelect'),
  locationSelectionHint: document.getElementById('locationSelectionHint'),
  sizeSelect: document.getElementById('sizeSelect'),
  createVmSizeSelect: document.getElementById('createVmSizeSelect'),
  vmSizeManualInput: document.getElementById('vmSizeManualInput'),
  loadLocationsBtn: document.getElementById('loadLocationsBtn'),
  loadSizesBtn: document.getElementById('loadSizesBtn'),
  loadVmsBtn: document.getElementById('loadVmsBtn'),

  vmTableBody: document.getElementById('vmTableBody'),
  createVmForm: document.getElementById('createVmForm'),
  imageSelect: document.getElementById('imageSelect'),
  authTypeSelect: document.getElementById('authTypeSelect'),
  networkModeSelect: document.getElementById('networkModeSelect'),
  passwordLabel: document.getElementById('passwordLabel'),
  sshLabel: document.getElementById('sshLabel'),
  nicLabel: document.getElementById('nicLabel'),

  toggleFiltersBtn: document.getElementById('toggleFiltersBtn'),
  vmFiltersPanel: document.getElementById('vmFiltersPanel'),
  vmFilterKeyword: document.getElementById('vmFilterKeyword'),
  vmFilterPower: document.getElementById('vmFilterPower'),
  vmFilterResourceGroup: document.getElementById('vmFilterResourceGroup'),
  applyVmFilterBtn: document.getElementById('applyVmFilterBtn'),
  resetVmFilterBtn: document.getElementById('resetVmFilterBtn'),

  loadAuditBtn: document.getElementById('loadAuditBtn'),
  auditTableBody: document.getElementById('auditTableBody'),
  sizeSourceBadge: document.getElementById('sizeSourceBadge'),
  sizeCountBadge: document.getElementById('sizeCountBadge'),
  requestFeed: document.getElementById('requestFeed'),
  eventFeed: document.getElementById('eventFeed')
};

const state = {
  authenticated: false,
  username: '',
  images: [],
  vmSizesByLocation: {},
  allVms: [],
  requestFeed: [],
  eventFeed: []
};

const FEED_LIMIT = 80;

boot().catch((err) => log(err.message || String(err), true));

async function boot() {
  bindEvents();
  toggleAuthFields();
  toggleNetworkFields();
  updateSizeMeta('-', 0);
  updateTopChips('-', '-', 0, 0);
  updateLocationSelectionHint('');
  renderRequestFeed();
  renderEventFeed();

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
      state.vmSizesByLocation = {};
      log('Azure 凭据已保存。');

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

    state.vmSizesByLocation = {};
    updateTopChips(currentSubscription(), els.locationSelect.value || '-', state.allVms.length, state.allVms.length);
    await loadLocations();
    await loadSizes();
    await loadVms();
  });

  els.locationSelect.addEventListener('change', async () => {
    if (!ensureAuthenticated()) {
      return;
    }

    const location = els.locationSelect.value || '';
    updateLocationSelectionHint(location);
    updateTopChips(currentSubscription(), location || '-', state.allVms.length, state.allVms.length);
    if (location) {
      log(`已切换地区: ${location}。后续规格查询与创建将按该地区执行。`);
    } else {
      log('地区未选择，部分操作将不可用。', true);
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
    payload.vmSize = String(payload.vmSizeManual || '').trim() ||
      els.createVmSizeSelect.value ||
      els.sizeSelect.value;

    delete payload.vmSizeManual;
    delete payload.vmSizeSelect;

    if (!payload.subscriptionId) {
      log('请先选择订阅。', true);
      return;
    }
    if (!payload.location) {
      log('请先选择地区。', true);
      return;
    }
    if (!payload.vmSize) {
      log('请先选择创建规格，或手动输入规格（例如 Standard_B1s）。', true);
      return;
    }

    await withBusy(e.submitter, async () => {
      const result = await api('/api/vm/create', {
        method: 'POST',
        body: payload
      });
      log(`创建成功: ${(result.vm && result.vm.name) || payload.name}`);
      await loadVms();
      await loadAudit();
    });
  });

  els.toggleFiltersBtn.addEventListener('click', () => {
    const hidden = els.vmFiltersPanel.classList.toggle('collapsed');
    els.toggleFiltersBtn.textContent = hidden ? '筛选面板' : '收起筛选';
  });

  els.applyVmFilterBtn.addEventListener('click', applyVmFiltersAndRender);

  els.resetVmFilterBtn.addEventListener('click', () => {
    els.vmFilterKeyword.value = '';
    els.vmFilterPower.value = '';
    els.vmFilterResourceGroup.value = '';
    applyVmFiltersAndRender();
  });

  els.vmFilterKeyword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      applyVmFiltersAndRender();
    }
  });

  els.vmFilterPower.addEventListener('change', applyVmFiltersAndRender);
  els.vmFilterResourceGroup.addEventListener('change', applyVmFiltersAndRender);
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
    clearVmTable('请先配置 Azure 凭据。');
    log('请先填写 Tenant ID / Client ID / Client Secret。', true);
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

  if (els.authBlock) {
    els.authBlock.classList.toggle('hidden', state.authenticated);
  }

  els.appMain.classList.toggle('hidden', !state.authenticated);
  els.logoutBtn.disabled = !state.authenticated;
  els.refreshAllBtn.disabled = !state.authenticated;

  const statusText = state.authenticated ? `已登录: ${state.username}` : '未登录';
  els.authStatus.textContent = statusText;
  if (els.navAuthStatus) {
    els.navAuthStatus.textContent = statusText;
  }
}

function clearAppData() {
  fillSelect(els.subscriptionSelect, []);
  fillSelect(els.locationSelect, []);
  fillSelect(els.sizeSelect, []);
  fillSelect(els.createVmSizeSelect, []);
  fillSelect(els.imageSelect, []);

  state.vmSizesByLocation = {};
  state.allVms = [];

  els.vmFilterKeyword.value = '';
  els.vmFilterPower.value = '';
  els.vmFilterResourceGroup.innerHTML = '<option value="">全部资源组</option>';

  updateSizeMeta('-', 0);
  updateTopChips('-', '-', 0, 0);
  updateLocationSelectionHint('');
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
  const subscriptions = data.subscriptions || [];

  fillSelect(
    els.subscriptionSelect,
    subscriptions.map((s) => ({ value: s.id, label: `${s.displayName} (${s.id})` }))
  );

  if (!subscriptions.length) {
    log('未找到可用订阅，请检查服务主体权限。', true);
    return;
  }

  updateTopChips(currentSubscription(), els.locationSelect.value || '-', state.allVms.length, state.allVms.length);
  log(`订阅加载完成，共 ${subscriptions.length} 个。`);
}

async function loadLocations() {
  const subscriptionId = currentSubscription();
  if (!subscriptionId) {
    return;
  }

  const data = await api(`/api/locations?subscriptionId=${encodeURIComponent(subscriptionId)}`);
  const locations = data.locations || [];

  fillSelect(
    els.locationSelect,
    locations.map((x) => ({ value: x, label: x }))
  );

  const selectedLocation = els.locationSelect.value || '';
  updateLocationSelectionHint(selectedLocation);
  updateTopChips(subscriptionId, selectedLocation || '-', state.allVms.length, state.allVms.length);
  if (selectedLocation) {
    log(`地区加载完成，共 ${locations.length} 个。当前地区: ${selectedLocation}。`);
  } else {
    log(`地区加载完成，共 ${locations.length} 个。请选择地区。`, true);
  }
}

async function loadSizes() {
  const subscriptionId = currentSubscription();
  const location = els.locationSelect.value;
  if (!subscriptionId || !location) {
    return;
  }

  const result = await getVmSizeOptionsForLocation(subscriptionId, location, { force: true });

  fillSelect(
    els.sizeSelect,
    result.sizes.map((s) => ({
      value: s.name,
      label: formatSizeLabel(s)
    }))
  );

  fillSelect(
    els.createVmSizeSelect,
    result.sizes.map((s) => ({
      value: s.name,
      label: formatSizeLabel(s)
    }))
  );

  updateSizeMeta(result.source, result.sizes.length);
  updateTopChips(subscriptionId, location, state.allVms.length, state.allVms.length);
  log(`规格加载完成，共 ${result.sizes.length} 个（来源: ${result.source}）。`);
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
    updateTopChips('-', els.locationSelect.value || '-', 0, 0);
    return;
  }

  const data = await api(`/api/vms?subscriptionId=${encodeURIComponent(subscriptionId)}`);
  const rows = data.vms || [];
  state.allVms = rows;

  populateResourceGroupFilter(rows);
  await prefetchSizesForVmRows(subscriptionId, rows);
  applyVmFiltersAndRender();

  log(`虚拟机加载完成，共 ${rows.length} 台。`);
}

function applyVmFiltersAndRender() {
  const keyword = String(els.vmFilterKeyword.value || '').trim().toLowerCase();
  const power = String(els.vmFilterPower.value || '').trim().toLowerCase();
  const rg = String(els.vmFilterResourceGroup.value || '').trim();

  const filtered = state.allVms.filter((vm) => {
    const name = String(vm.name || '').toLowerCase();
    const powerState = String(vm.powerState || '').toLowerCase();
    const resourceGroup = String(vm.resourceGroup || '');

    if (keyword && name.indexOf(keyword) < 0) {
      return false;
    }
    if (power && powerState.indexOf(power) < 0) {
      return false;
    }
    if (rg && resourceGroup !== rg) {
      return false;
    }

    return true;
  });

  renderVmRows(filtered);
  updateTopChips(
    currentSubscription(),
    els.locationSelect.value || '-',
    filtered.length,
    state.allVms.length
  );
}

async function prefetchSizesForVmRows(subscriptionId, rows) {
  const unique = {};

  for (const vm of rows) {
    const key = normalizeLocationKey(vm.location);
    if (!key || unique[key]) {
      continue;
    }
    unique[key] = vm.location;
  }

  const locations = Object.keys(unique).map((key) => unique[key]);
  for (const location of locations) {
    try {
      await getVmSizeOptionsForLocation(subscriptionId, location);
    } catch (err) {
      log(`地区 ${location} 规格预加载失败: ${err.message || String(err)}`, true);
    }
  }
}

function renderVmRows(rows) {
  els.vmTableBody.innerHTML = '';

  if (!rows.length) {
    clearVmTable('没有匹配的虚拟机。');
    return;
  }

  const subscriptionId = currentSubscription();

  for (const vm of rows) {
    const tr = document.createElement('tr');
    appendCell(tr, vm.name);
    appendCell(tr, vm.resourceGroup || '-');
    appendCell(tr, vm.location || '-');
    appendCell(tr, vm.vmSize || '-');
    appendStatusCell(tr, vm.powerState || '-', 'power');
    appendStatusCell(tr, vm.provisioningState || '-', 'provision');

    const targetSizeTd = document.createElement('td');
    const sizeSelect = buildVmTargetSizeSelect(vm);
    targetSizeTd.appendChild(sizeSelect);
    tr.appendChild(targetSizeTd);

    const actionTd = document.createElement('td');
    const actionWrap = document.createElement('div');
    actionWrap.className = 'cell-actions';

    const buttons = [
      { label: '改规格', action: 'resize', className: 'ghost' },
      { label: '开机', action: 'start' },
      { label: '关机', action: 'powerOff' },
      { label: '重启', action: 'restart' },
      { label: '释放', action: 'deallocate' },
      { label: '删除', action: 'delete', className: 'danger' }
    ];

    for (const item of buttons) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = item.label;
      btn.setAttribute('data-action', item.action);
      if (item.className) {
        btn.classList.add(item.className);
      }

      btn.addEventListener('click', async () => {
        const action = item.action;
        const targetVmSize = normalizeTargetVmSize(sizeSelect.value);

        if (action === 'delete') {
          const ok = window.confirm(`确定删除虚拟机 ${vm.name} ?`);
          if (!ok) {
            return;
          }
        }

        if (action === 'resize' && !targetVmSize) {
          log(`请先为 ${vm.name} 选择目标规格。`, true);
          return;
        }

        await withBusy(btn, async () => {
          const payload = {
            subscriptionId,
            resourceGroup: vm.resourceGroup,
            name: vm.name,
            action
          };

          if ((action === 'start' || action === 'resize') && targetVmSize) {
            payload.vmSize = targetVmSize;
          }

          await api('/api/vm/action', {
            method: 'POST',
            body: payload
          });

          const suffix = payload.vmSize ? ` (${payload.vmSize})` : '';
          log(`操作成功: ${vm.name} -> ${action}${suffix}`);
          await loadVms();
          await loadAudit();
        });
      });

      actionWrap.appendChild(btn);
    }

    actionTd.appendChild(actionWrap);
    tr.appendChild(actionTd);
    els.vmTableBody.appendChild(tr);
  }
}

function populateResourceGroupFilter(rows) {
  const current = String(els.vmFilterResourceGroup.value || '').trim();
  const seen = {};
  const list = [];

  for (const vm of rows) {
    const rg = String(vm.resourceGroup || '').trim();
    if (!rg || seen[rg]) {
      continue;
    }
    seen[rg] = true;
    list.push(rg);
  }

  list.sort();

  els.vmFilterResourceGroup.innerHTML = '<option value="">全部资源组</option>';
  for (const rg of list) {
    const opt = document.createElement('option');
    opt.value = rg;
    opt.textContent = rg;
    if (rg === current) {
      opt.selected = true;
    }
    els.vmFilterResourceGroup.appendChild(opt);
  }
}

function buildVmTargetSizeSelect(vm) {
  const select = document.createElement('select');
  select.className = 'inline-size-select';

  const key = normalizeLocationKey(vm.location);
  const cached = state.vmSizesByLocation[key] || [];
  const currentSize = String(vm.vmSize || '').trim();

  const options = [];
  const seen = {};

  if (currentSize && currentSize !== '-') {
    options.push({
      name: currentSize,
      numberOfCores: 0,
      memoryInMB: 0,
      maxDataDiskCount: 0,
      synthetic: true
    });
    seen[currentSize] = true;
  }

  for (const item of cached) {
    if (!item || !item.name || seen[item.name]) {
      continue;
    }
    seen[item.name] = true;
    options.push(item);
  }

  if (!options.length) {
    const empty = document.createElement('option');
    empty.value = '';
    empty.textContent = '无可用规格';
    select.appendChild(empty);
    return select;
  }

  for (const item of options) {
    const opt = document.createElement('option');
    opt.value = item.name;
    opt.textContent = item.synthetic ? `${item.name} (当前)` : formatSizeLabel(item);
    if (item.name === currentSize) {
      opt.selected = true;
    }
    select.appendChild(opt);
  }

  return select;
}

async function getVmSizeOptionsForLocation(subscriptionId, location, options = {}) {
  const force = Boolean(options.force);
  const key = normalizeLocationKey(location);
  if (!key) {
    return { sizes: [], source: '-' };
  }

  if (!force && state.vmSizesByLocation[key] && state.vmSizesByLocation[key].length) {
    return { sizes: state.vmSizesByLocation[key], source: 'cache' };
  }

  const data = await api(
    `/api/vm-sizes?subscriptionId=${encodeURIComponent(subscriptionId)}&location=${encodeURIComponent(location)}`
  );

  const sizes = Array.isArray(data.sizes) ? data.sizes : [];
  if (sizes.length) {
    state.vmSizesByLocation[key] = sizes;
  } else {
    delete state.vmSizesByLocation[key];
  }

  return {
    sizes,
    source: data.source || 'unknown'
  };
}

function updateTopChips(subscriptionId, location, filteredCount, totalCount) {
  const sub = subscriptionId && subscriptionId !== '-' ? subscriptionId : '-';
  const loc = location && location !== '-' ? location : '-';
  const filtered = Number(filteredCount || 0);
  const total = Number(totalCount || 0);

  els.topSubscriptionChip.textContent = `订阅: ${sub === '-' ? '-' : shortText(sub, 22)}`;
  els.topLocationChip.textContent = `地区: ${loc}`;
  els.topVmCountChip.textContent = total > 0 ? `VM: ${filtered}/${total}` : 'VM: 0';
  els.topSubscriptionChip.classList.toggle('active', sub !== '-');
  els.topLocationChip.classList.toggle('active', loc !== '-');
  els.topVmCountChip.classList.toggle('active', total > 0);
}

function updateSizeMeta(source, count) {
  els.sizeSourceBadge.textContent = `规格来源: ${source || '-'}`;
  els.sizeCountBadge.textContent = `数量: ${count || 0}`;
}

function updateLocationSelectionHint(location) {
  if (!els.locationSelectionHint || !els.locationSelect) {
    return;
  }

  const text = String(location || '').trim();
  if (!text) {
    els.locationSelectionHint.textContent = '当前地区: 未选择';
    els.locationSelectionHint.classList.remove('active');
    els.locationSelect.classList.remove('field-active');
    return;
  }

  els.locationSelectionHint.textContent = `当前地区: ${text}（规格查询、创建 VM 均按此地区）`;
  els.locationSelectionHint.classList.add('active');
  els.locationSelect.classList.add('field-active');
}

function normalizeLocationKey(location) {
  return String(location || '').trim().toLowerCase();
}

function normalizeTargetVmSize(value) {
  const out = String(value || '').trim();
  if (!out || out === '-') {
    return '';
  }
  return out;
}

function formatSizeLabel(size) {
  const cores = Number(size.numberOfCores || 0);
  const memoryGb = Number(size.memoryInMB || 0) / 1024;
  const disk = Number(size.maxDataDiskCount || 0);

  return `${size.name || '-'} | ${cores || 0} vCPU | ${memoryGb ? memoryGb.toFixed(1) : '0.0'} GB | ${disk || 0} Disk`;
}

function appendCell(tr, value) {
  const td = document.createElement('td');
  td.textContent = String(value == null ? '-' : value);
  tr.appendChild(td);
}

function appendStatusCell(tr, value, kind) {
  const td = document.createElement('td');
  const span = document.createElement('span');
  span.className = `pill ${pillClass(value, kind)}`;
  span.textContent = String(value == null ? '-' : value);
  td.appendChild(span);
  tr.appendChild(td);
}

function pillClass(value, kind) {
  const v = String(value || '').toLowerCase();

  if (kind === 'power') {
    if (v.indexOf('running') >= 0 || v.indexOf('start') >= 0) {
      return 'pill-ok';
    }
    if (v.indexOf('deallocated') >= 0 || v.indexOf('stopped') >= 0 || v.indexOf('off') >= 0) {
      return 'pill-warn';
    }
  }

  if (kind === 'provision') {
    if (v.indexOf('succeeded') >= 0) {
      return 'pill-ok';
    }
    if (v.indexOf('failed') >= 0 || v.indexOf('error') >= 0) {
      return 'pill-danger';
    }
  }

  return 'pill-muted';
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
  tr.innerHTML = `<td colspan="8">${escapeHtml(message)}</td>`;
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

function formatStamp(value = Date.now()) {
  return formatDate(new Date(value).toISOString());
}

function toRequestPath(url) {
  try {
    const u = new URL(url, window.location.origin);
    return `${u.pathname}${u.search || ''}`;
  } catch (err) {
    return String(url || '-');
  }
}

function recordRequest({ method, url, status, durationMs, ok, message }) {
  const methodText = String(method || 'GET').toUpperCase();
  const statusCode = Number(status || 0);
  const duration = Number(durationMs || 0);

  state.requestFeed.unshift({
    method: methodText,
    path: toRequestPath(url),
    statusText: statusCode > 0 ? String(statusCode) : 'ERR',
    durationText: `${duration}ms`,
    stamp: formatStamp(),
    ok: Boolean(ok),
    message: String(message || '')
  });

  state.requestFeed = state.requestFeed.slice(0, FEED_LIMIT);
  renderRequestFeed();
}

function renderRequestFeed() {
  if (!els.requestFeed) {
    return;
  }

  els.requestFeed.innerHTML = '';

  if (!state.requestFeed.length) {
    const li = document.createElement('li');
    li.className = 'feed-empty';
    li.textContent = '暂无请求记录。';
    els.requestFeed.appendChild(li);
    return;
  }

  for (const item of state.requestFeed) {
    const li = document.createElement('li');
    li.className = `feed-item request-item ${item.ok ? 'ok' : 'error'}`;
    li.innerHTML = `
      <span class="feed-badge">${escapeHtml(item.method)}</span>
      <span class="feed-main">
        <strong>${escapeHtml(item.path)}</strong>
        <small>${escapeHtml(item.stamp)}${item.message ? ` · ${escapeHtml(item.message)}` : ''}</small>
      </span>
      <span class="feed-tail">${escapeHtml(item.statusText)} · ${escapeHtml(item.durationText)}</span>
    `;
    els.requestFeed.appendChild(li);
  }
}

function renderEventFeed() {
  if (!els.eventFeed) {
    return;
  }

  els.eventFeed.innerHTML = '';

  if (!state.eventFeed.length) {
    const li = document.createElement('li');
    li.className = 'feed-empty';
    li.textContent = '暂无系统消息。';
    els.eventFeed.appendChild(li);
    return;
  }

  for (const item of state.eventFeed) {
    const li = document.createElement('li');
    li.className = `feed-item event-item ${item.isError ? 'error' : 'ok'}`;
    li.innerHTML = `
      <span class="feed-level">${item.isError ? 'ERROR' : 'INFO'}</span>
      <span class="feed-main">
        <strong>${escapeHtml(item.text)}</strong>
        <small>${escapeHtml(item.stamp)}</small>
      </span>
    `;
    els.eventFeed.appendChild(li);
  }
}

function shortText(text, maxLen) {
  const s = String(text || '');
  if (s.length <= maxLen) {
    return s;
  }
  return `${s.slice(0, maxLen)}...`;
}

function currentSubscription() {
  return els.subscriptionSelect.value || '';
}

async function api(url, options = {}) {
  const method = options.method || 'GET';
  const start = Date.now();
  let response;
  let data;

  try {
    response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json'
      },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    data = await response.json().catch(() => ({}));
  } catch (err) {
    const message = err && err.message ? err.message : '网络请求失败';
    recordRequest({
      method,
      url,
      status: 0,
      durationMs: Date.now() - start,
      ok: false,
      message
    });
    log(message, true);
    throw err;
  }

  if (!response.ok) {
    if (response.status === 401 && !options.allowUnauthorized) {
      setAuthenticated(false, '');
      clearAppData();
    }

    const message = data.error || `请求失败: ${response.status}`;
    recordRequest({
      method,
      url,
      status: response.status,
      durationMs: Date.now() - start,
      ok: false,
      message
    });
    log(message, true);
    throw new Error(message);
  }

  recordRequest({
    method,
    url,
    status: response.status,
    durationMs: Date.now() - start,
    ok: true
  });

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
  state.eventFeed.unshift({
    stamp: formatStamp(),
    text: String(text || ''),
    isError: Boolean(isError)
  });
  state.eventFeed = state.eventFeed.slice(0, FEED_LIMIT);
  renderEventFeed();
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
