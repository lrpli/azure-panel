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
  subscriptionTableBody: document.getElementById('subscriptionTableBody'),
  subPagePrevBtn: document.getElementById('subPagePrevBtn'),
  subPageNextBtn: document.getElementById('subPageNextBtn'),
  subPageInfo: document.getElementById('subPageInfo'),

  vmTableBody: document.getElementById('vmTableBody'),
  createVmForm: document.getElementById('createVmForm'),
  createVmSubmitBtn: document.getElementById('createVmSubmitBtn'),
  imageSelect: document.getElementById('imageSelect'),
  authTypeSelect: document.getElementById('authTypeSelect'),
  networkModeSelect: document.getElementById('networkModeSelect'),
  passwordLabel: document.getElementById('passwordLabel'),
  sshLabel: document.getElementById('sshLabel'),
  keychainSelectLabel: document.getElementById('keychainSelectLabel'),
  keychainSelect: document.getElementById('keychainSelect'),
  applyKeychainBtn: document.getElementById('applyKeychainBtn'),
  refreshKeychainBtn: document.getElementById('refreshKeychainBtn'),
  keychainNameInput: document.getElementById('keychainNameInput'),
  keychainValueInput: document.getElementById('keychainValueInput'),
  addKeychainBtn: document.getElementById('addKeychainBtn'),
  loadKeychainBtn: document.getElementById('loadKeychainBtn'),
  keychainTableBody: document.getElementById('keychainTableBody'),
  nicLabel: document.getElementById('nicLabel'),

  toggleFiltersBtn: document.getElementById('toggleFiltersBtn'),
  vmFiltersPanel: document.getElementById('vmFiltersPanel'),
  vmFilterKeyword: document.getElementById('vmFilterKeyword'),
  vmFilterPower: document.getElementById('vmFilterPower'),
  vmFilterResourceGroup: document.getElementById('vmFilterResourceGroup'),
  applyVmFilterBtn: document.getElementById('applyVmFilterBtn'),
  resetVmFilterBtn: document.getElementById('resetVmFilterBtn'),
  vmPagePrevBtn: document.getElementById('vmPagePrevBtn'),
  vmPageNextBtn: document.getElementById('vmPageNextBtn'),
  vmPageInfo: document.getElementById('vmPageInfo'),
  vmPageSizeSelect: document.getElementById('vmPageSizeSelect'),

  loadAuditBtn: document.getElementById('loadAuditBtn'),
  auditTableBody: document.getElementById('auditTableBody'),
  auditPagePrevBtn: document.getElementById('auditPagePrevBtn'),
  auditPageNextBtn: document.getElementById('auditPageNextBtn'),
  auditPageInfo: document.getElementById('auditPageInfo'),
  auditPageSizeSelect: document.getElementById('auditPageSizeSelect'),
  telegramConfigForm: document.getElementById('telegramConfigForm'),
  loadTelegramConfigBtn: document.getElementById('loadTelegramConfigBtn'),
  telegramBotTokenInput: document.getElementById('telegramBotTokenInput'),
  telegramEnabledSelect: document.getElementById('telegramEnabledSelect'),
  telegramAllowedChatIdsInput: document.getElementById('telegramAllowedChatIdsInput'),
  saveTelegramConfigBtn: document.getElementById('saveTelegramConfigBtn'),
  telegramStatusHint: document.getElementById('telegramStatusHint'),
  telegramChatsTableBody: document.getElementById('telegramChatsTableBody'),
  sizeSourceBadge: document.getElementById('sizeSourceBadge'),
  sizeCountBadge: document.getElementById('sizeCountBadge'),
  readinessList: document.getElementById('readinessList'),
  readinessHint: document.getElementById('readinessHint'),
  resourceActionHint: document.getElementById('resourceActionHint'),
  createActionHint: document.getElementById('createActionHint'),
  requestFeed: document.getElementById('requestFeed'),
  eventFeed: document.getElementById('eventFeed')
};

const state = {
  authenticated: false,
  configured: false,
  username: '',
  subscriptions: [],
  telegramConfigured: false,
  telegramEnabled: false,
  telegramPolling: false,
  telegramTokenPreview: '',
  telegramLastError: '',
  telegramAllowedChatIds: [],
  telegramKnownChats: [],
  keychainEntries: [],
  images: [],
  vmSizesByLocation: {},
  allVms: [],
  filteredVms: [],
  auditRows: [],
  subPage: 1,
  subPageSize: 8,
  vmPage: 1,
  vmPageSize: 20,
  auditPage: 1,
  auditPageSize: 20,
  requestFeed: [],
  eventFeed: []
};

const FEED_LIMIT = 80;
const SIZE_PREFETCH_CONCURRENCY = 3;

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
  renderSubscriptionRows();
  renderKeychainRows();
  refreshKeychainSelectOptions();
  renderTelegramChatsRows();
  renderTelegramStatusHint();
  renderAuditRows();
  updateActionAvailability();

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
      await loadSizes({ force: true });
      await loadKeychainEntries();
      await loadTelegramConfig();
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
      state.configured = true;
      state.vmSizesByLocation = {};
      log('Azure 凭据已保存。');

      await refreshSubscriptions();
      await loadLocations();
      await loadSizes();
      await loadKeychainEntries();
      await loadTelegramConfig();
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
    await withBusy(e.currentTarget, () => loadSizes({ force: true }));
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

  if (els.loadTelegramConfigBtn) {
    els.loadTelegramConfigBtn.addEventListener('click', async (e) => {
      if (!ensureAuthenticated()) {
        return;
      }
      await withBusy(e.currentTarget, loadTelegramConfig);
    });
  }

  if (els.telegramConfigForm) {
    els.telegramConfigForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!ensureAuthenticated()) {
        return;
      }

      const payload = {
        enabled: String((els.telegramEnabledSelect && els.telegramEnabledSelect.value) || 'false') === 'true',
        allowedChatIds: parseChatIdsText((els.telegramAllowedChatIdsInput && els.telegramAllowedChatIdsInput.value) || '')
      };

      const tokenText = String((els.telegramBotTokenInput && els.telegramBotTokenInput.value) || '').trim();
      if (tokenText) {
        payload.botToken = tokenText;
      }

      await withBusy(e.submitter, async () => {
        await api('/api/telegram/config', {
          method: 'POST',
          body: payload
        });

        if (els.telegramBotTokenInput) {
          els.telegramBotTokenInput.value = '';
        }
        await loadTelegramConfig();
        await loadAudit();
        log('Telegram 配置已保存。');
      });
    });
  }

  els.subscriptionSelect.addEventListener('change', async () => {
    if (!ensureAuthenticated()) {
      return;
    }

    state.vmSizesByLocation = {};
    updateTopChips(currentSubscription(), els.locationSelect.value || '-', state.allVms.length, state.allVms.length);
    renderSubscriptionRows();
    updateActionAvailability();
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
    updateActionAvailability();
    await loadSizes();
  });

  els.authTypeSelect.addEventListener('change', toggleAuthFields);
  els.networkModeSelect.addEventListener('change', toggleNetworkFields);
  if (els.applyKeychainBtn) {
    els.applyKeychainBtn.addEventListener('click', applySelectedKeychainToSshField);
  }
  if (els.keychainSelect) {
    els.keychainSelect.addEventListener('change', () => {
      const selectedId = String(els.keychainSelect.value || '').trim();
      if (selectedId) {
        applySelectedKeychainToSshField();
      }
    });
  }
  if (els.refreshKeychainBtn) {
    els.refreshKeychainBtn.addEventListener('click', async (e) => {
      if (!ensureAuthenticated()) {
        return;
      }
      await withBusy(e.currentTarget, loadKeychainEntries);
    });
  }
  if (els.loadKeychainBtn) {
    els.loadKeychainBtn.addEventListener('click', async (e) => {
      if (!ensureAuthenticated()) {
        return;
      }
      await withBusy(e.currentTarget, loadKeychainEntries);
    });
  }
  if (els.addKeychainBtn) {
    els.addKeychainBtn.addEventListener('click', async (e) => {
      if (!ensureAuthenticated()) {
        return;
      }

      const name = String((els.keychainNameInput && els.keychainNameInput.value) || '').trim();
      const value = String((els.keychainValueInput && els.keychainValueInput.value) || '').trim();
      if (!name || !value) {
        log('请填写 Key 名称和 SSH 公钥。', true);
        return;
      }

      await withBusy(e.currentTarget, async () => {
        await api('/api/keychain', {
          method: 'POST',
          body: {
            type: 'ssh-public-key',
            name,
            value
          }
        });
        if (els.keychainNameInput) {
          els.keychainNameInput.value = '';
        }
        if (els.keychainValueInput) {
          els.keychainValueInput.value = '';
        }
        await loadKeychainEntries();
        log(`已新增 Keychain 条目: ${name}`);
      });
    });
  }

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

    payload.authType = payload.authType === 'ssh' ? 'ssh' : 'password';
    payload.keychainId = String(payload.keychainId || '').trim();
    payload.sshPublicKey = String(payload.sshPublicKey || '').trim();

    if (payload.authType === 'ssh' && !payload.sshPublicKey && payload.keychainId) {
      const selected = findKeychainEntryById(payload.keychainId);
      if (selected) {
        payload.sshPublicKey = selected.value;
      }
    }

    if (payload.authType !== 'ssh') {
      delete payload.keychainId;
      delete payload.sshPublicKey;
    }

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
    if (payload.authType === 'ssh' && !payload.sshPublicKey && !payload.keychainId) {
      log('SSH 模式下请填写公钥或选择 Keychain。', true);
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

  if (els.subPagePrevBtn) {
    els.subPagePrevBtn.addEventListener('click', () => {
      state.subPage = Math.max(1, state.subPage - 1);
      renderSubscriptionRows();
    });
  }
  if (els.subPageNextBtn) {
    els.subPageNextBtn.addEventListener('click', () => {
      state.subPage += 1;
      renderSubscriptionRows();
    });
  }

  if (els.vmPagePrevBtn) {
    els.vmPagePrevBtn.addEventListener('click', () => {
      state.vmPage = Math.max(1, state.vmPage - 1);
      applyVmFiltersAndRender({ keepPage: true });
    });
  }
  if (els.vmPageNextBtn) {
    els.vmPageNextBtn.addEventListener('click', () => {
      state.vmPage += 1;
      applyVmFiltersAndRender({ keepPage: true });
    });
  }
  if (els.vmPageSizeSelect) {
    els.vmPageSizeSelect.addEventListener('change', () => {
      state.vmPageSize = normalizePageSize(els.vmPageSizeSelect.value, 20);
      state.vmPage = 1;
      applyVmFiltersAndRender({ keepPage: true });
    });
    state.vmPageSize = normalizePageSize(els.vmPageSizeSelect.value, 20);
  }

  if (els.auditPagePrevBtn) {
    els.auditPagePrevBtn.addEventListener('click', () => {
      state.auditPage = Math.max(1, state.auditPage - 1);
      renderAuditRows();
    });
  }
  if (els.auditPageNextBtn) {
    els.auditPageNextBtn.addEventListener('click', () => {
      state.auditPage += 1;
      renderAuditRows();
    });
  }
  if (els.auditPageSizeSelect) {
    els.auditPageSizeSelect.addEventListener('change', () => {
      state.auditPageSize = normalizePageSize(els.auditPageSizeSelect.value, 20);
      state.auditPage = 1;
      renderAuditRows();
    });
    state.auditPageSize = normalizePageSize(els.auditPageSizeSelect.value, 20);
  }
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
  await loadKeychainEntries();
  await loadTelegramConfig();

  const config = await api('/api/config');
  state.configured = Boolean(config.configured);
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
  updateActionAvailability();
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
  if (!state.authenticated) {
    state.configured = false;
  }

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

  updateActionAvailability();
}

function clearAppData() {
  fillSelect(els.subscriptionSelect, []);
  fillSelect(els.locationSelect, []);
  fillSelect(els.sizeSelect, []);
  fillSelect(els.createVmSizeSelect, []);
  fillSelect(els.keychainSelect, [{ value: '', label: '手动输入公钥' }]);
  fillSelect(els.imageSelect, []);

  state.vmSizesByLocation = {};
  state.allVms = [];
  state.configured = false;
  state.subscriptions = [];
  state.telegramConfigured = false;
  state.telegramEnabled = false;
  state.telegramPolling = false;
  state.telegramAllowedChatIds = [];
  state.telegramKnownChats = [];
  state.keychainEntries = [];
  state.filteredVms = [];
  state.auditRows = [];
  state.subPage = 1;
  state.vmPage = 1;
  state.auditPage = 1;

  els.vmFilterKeyword.value = '';
  els.vmFilterPower.value = '';
  els.vmFilterResourceGroup.innerHTML = '<option value="">全部资源组</option>';
  if (els.telegramAllowedChatIdsInput) {
    els.telegramAllowedChatIdsInput.value = '';
  }
  if (els.telegramEnabledSelect) {
    els.telegramEnabledSelect.value = 'false';
  }
  if (els.telegramBotTokenInput) {
    els.telegramBotTokenInput.value = '';
  }

  updateSizeMeta('-', 0);
  updateTopChips('-', '-', 0, 0);
  updateLocationSelectionHint('');
  renderSubscriptionRows();
  renderKeychainRows();
  renderTelegramChatsRows();
  renderTelegramStatusHint();
  clearVmTable('请先登录。');
  clearAuditTable('请先登录。');
  updateActionAvailability();
}

function toggleAuthFields() {
  const authType = els.authTypeSelect.value;
  els.passwordLabel.classList.toggle('hidden', authType !== 'password');
  els.sshLabel.classList.toggle('hidden', authType !== 'ssh');
  if (els.keychainSelectLabel) {
    els.keychainSelectLabel.classList.toggle('hidden', authType !== 'ssh');
  }
  updateActionAvailability();
}

function toggleNetworkFields() {
  const mode = els.networkModeSelect.value;
  els.nicLabel.classList.toggle('hidden', mode !== 'existing-nic');
  updateActionAvailability();
}

async function refreshSubscriptions() {
  const data = await api('/api/subscriptions');
  const subscriptions = data.subscriptions || [];
  state.subscriptions = subscriptions;
  state.subPage = 1;

  fillSelect(
    els.subscriptionSelect,
    subscriptions.map((s) => ({ value: s.id, label: `${s.displayName} (${s.id})` }))
  );
  renderSubscriptionRows();

  if (!subscriptions.length) {
    log('未找到可用订阅，请检查服务主体权限。', true);
    updateActionAvailability();
    return;
  }

  updateTopChips(currentSubscription(), els.locationSelect.value || '-', state.allVms.length, state.allVms.length);
  log(`订阅加载完成，共 ${subscriptions.length} 个。`);
  updateActionAvailability();
}

async function loadLocations() {
  const subscriptionId = currentSubscription();
  if (!subscriptionId) {
    updateActionAvailability();
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
  updateActionAvailability();
}

function renderSubscriptionRows() {
  if (!els.subscriptionTableBody) {
    return;
  }

  const page = paginateItems(state.subscriptions, state.subPage, state.subPageSize);
  state.subPage = page.page;

  els.subscriptionTableBody.innerHTML = '';
  if (!page.totalCount) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="4">暂无订阅数据。</td>';
    els.subscriptionTableBody.appendChild(tr);
    updatePager({
      prevBtn: els.subPagePrevBtn,
      nextBtn: els.subPageNextBtn,
      infoEl: els.subPageInfo,
      page: 1,
      totalPages: 1,
      totalCount: 0
    });
    return;
  }

  const current = currentSubscription();
  for (const sub of page.items) {
    const tr = document.createElement('tr');
    const isCurrent = sub.id && sub.id === current;
    tr.innerHTML = `
      <td>${escapeHtml(sub.displayName || '-')}</td>
      <td>${escapeHtml(shortText(sub.id || '-', 36))}</td>
      <td>${escapeHtml(formatSubscriptionState(sub.state))}</td>
      <td>${isCurrent ? '是' : '-'}</td>
    `;
    els.subscriptionTableBody.appendChild(tr);
  }

  updatePager({
    prevBtn: els.subPagePrevBtn,
    nextBtn: els.subPageNextBtn,
    infoEl: els.subPageInfo,
    page: page.page,
    totalPages: page.totalPages,
    totalCount: page.totalCount
  });
}

async function loadKeychainEntries() {
  const data = await api('/api/keychain');
  state.keychainEntries = Array.isArray(data.entries) ? data.entries : [];
  renderKeychainRows();
  refreshKeychainSelectOptions();
  updateActionAvailability();
}

function renderKeychainRows() {
  if (!els.keychainTableBody) {
    return;
  }

  els.keychainTableBody.innerHTML = '';
  if (!state.keychainEntries.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="4">暂无 Keychain 条目。</td>';
    els.keychainTableBody.appendChild(tr);
    return;
  }

  for (const item of state.keychainEntries) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(item.name || '-')}</td>
      <td>${escapeHtml(item.type || '-')}</td>
      <td>${escapeHtml(formatDate(item.createdAt))}</td>
      <td class="row-actions">
        <button type="button" data-keychain-action="use" data-keychain-id="${escapeHtml(item.id || '')}">使用</button>
        <button type="button" class="danger" data-keychain-action="delete" data-keychain-id="${escapeHtml(item.id || '')}">删除</button>
      </td>
    `;

    const useBtn = tr.querySelector('button[data-keychain-action="use"]');
    const delBtn = tr.querySelector('button[data-keychain-action="delete"]');
    if (useBtn) {
      useBtn.addEventListener('click', () => {
        if (els.keychainSelect) {
          els.keychainSelect.value = item.id || '';
        }
        applySelectedKeychainToSshField();
      });
    }
    if (delBtn) {
      delBtn.addEventListener('click', async () => {
        if (!ensureAuthenticated()) {
          return;
        }
        const ok = window.confirm(`确定删除 Key「${item.name || item.id}」？`);
        if (!ok) {
          return;
        }

        await withBusy(delBtn, async () => {
          await api('/api/keychain', {
            method: 'DELETE',
            body: { id: item.id }
          });
          await loadKeychainEntries();
          log(`已删除 Keychain 条目: ${item.name || item.id}`);
        });
      });
    }

    els.keychainTableBody.appendChild(tr);
  }
}

function refreshKeychainSelectOptions() {
  if (!els.keychainSelect) {
    return;
  }

  const current = String(els.keychainSelect.value || '');
  const options = [{ value: '', label: '手动输入公钥' }];
  for (const item of state.keychainEntries) {
    options.push({
      value: item.id,
      label: `${item.name} (${item.type || 'key'})`
    });
  }

  fillSelect(els.keychainSelect, options);
  if (current && options.some((x) => x.value === current)) {
    els.keychainSelect.value = current;
  } else if (current) {
    els.keychainSelect.value = '';
  }
}

function applySelectedKeychainToSshField() {
  const id = String((els.keychainSelect && els.keychainSelect.value) || '').trim();
  if (!id) {
    return;
  }

  const selected = findKeychainEntryById(id);
  if (!selected) {
    log('所选 Keychain 条目不存在，已刷新列表。', true);
    return;
  }

  const sshInput = getSshPublicKeyInput();
  if (!sshInput) {
    return;
  }
  sshInput.value = selected.value || '';
  log(`已填充 SSH 公钥: ${selected.name || selected.id}`);
}

function findKeychainEntryById(id) {
  const target = String(id || '').trim();
  if (!target) {
    return null;
  }
  return state.keychainEntries.find((x) => x && x.id === target) || null;
}

function getSshPublicKeyInput() {
  if (!els.sshLabel) {
    return null;
  }
  return els.sshLabel.querySelector('textarea[name="sshPublicKey"]');
}

async function loadTelegramConfig() {
  const data = await api('/api/telegram/config');
  state.telegramConfigured = Boolean(data.configured);
  state.telegramEnabled = Boolean(data.enabled);
  state.telegramPolling = Boolean(data.polling);
  state.telegramTokenPreview = String(data.tokenPreview || '');
  state.telegramLastError = String(data.lastError || '');
  state.telegramAllowedChatIds = normalizeChatIdList(data.allowedChatIds || []);
  state.telegramKnownChats = Array.isArray(data.knownChats) ? data.knownChats : [];

  if (els.telegramEnabledSelect) {
    els.telegramEnabledSelect.value = state.telegramEnabled ? 'true' : 'false';
  }
  if (els.telegramAllowedChatIdsInput) {
    els.telegramAllowedChatIdsInput.value = state.telegramAllowedChatIds.join(',');
  }

  renderTelegramChatsRows();
  renderTelegramStatusHint();
  updateActionAvailability();
}

function renderTelegramStatusHint() {
  if (!els.telegramStatusHint) {
    return;
  }

  const configuredText = state.telegramConfigured
    ? `已配置 Token (${state.telegramTokenPreview || '***'})`
    : '未配置 Token';
  const enabledText = state.telegramEnabled ? '开启' : '关闭';
  const pollingText = state.telegramPolling ? '运行中' : '未运行';
  const errorText = state.telegramLastError ? `；最近错误: ${state.telegramLastError}` : '';

  els.telegramStatusHint.textContent =
    `状态: ${configuredText}；控制: ${enabledText}；Polling: ${pollingText}；允许 chat: ${state.telegramAllowedChatIds.length}${errorText}`;
}

function renderTelegramChatsRows() {
  if (!els.telegramChatsTableBody) {
    return;
  }

  els.telegramChatsTableBody.innerHTML = '';
  if (!state.telegramKnownChats.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="6">暂无聊天记录。先给 Bot 发送 /start，再刷新配置。</td>';
    els.telegramChatsTableBody.appendChild(tr);
    return;
  }

  const allowedMap = {};
  for (const id of state.telegramAllowedChatIds) {
    allowedMap[id] = true;
  }

  for (const chat of state.telegramKnownChats) {
    const id = String(chat.id || '');
    const authorized = Boolean(allowedMap[id]);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(id || '-')}</td>
      <td>${escapeHtml(chat.title || '-')}</td>
      <td>${escapeHtml(chat.type || '-')}</td>
      <td>${escapeHtml(formatDate(chat.lastSeenAt))}</td>
      <td>${authorized ? '已授权' : '未授权'}</td>
      <td class="row-actions">
        <button type="button" data-telegram-chat-id="${escapeHtml(id)}" data-telegram-op="toggle">${authorized ? '移除授权' : '加入授权'}</button>
      </td>
    `;

    const btn = tr.querySelector('button[data-telegram-op="toggle"]');
    if (btn) {
      btn.addEventListener('click', () => {
        toggleTelegramAllowedChatId(id);
      });
    }

    els.telegramChatsTableBody.appendChild(tr);
  }
}

function toggleTelegramAllowedChatId(chatId) {
  const id = String(chatId || '').trim();
  if (!id) {
    return;
  }

  const set = {};
  for (const item of state.telegramAllowedChatIds) {
    set[item] = true;
  }

  if (set[id]) {
    delete set[id];
  } else {
    set[id] = true;
  }

  state.telegramAllowedChatIds = Object.keys(set).sort();
  if (els.telegramAllowedChatIdsInput) {
    els.telegramAllowedChatIdsInput.value = state.telegramAllowedChatIds.join(',');
  }
  renderTelegramChatsRows();
  renderTelegramStatusHint();
}

function parseChatIdsText(text) {
  return normalizeChatIdList(String(text || '').split(','));
}

function normalizeChatIdList(items) {
  const out = [];
  const seen = {};
  const list = Array.isArray(items) ? items : [items];

  for (const raw of list) {
    const id = String(raw || '').trim();
    if (!id || !/^-?\d+$/.test(id) || seen[id]) {
      continue;
    }
    seen[id] = true;
    out.push(id);
  }
  return out;
}

async function loadSizes(options = {}) {
  const force = Boolean(options.force);
  const subscriptionId = currentSubscription();
  const location = els.locationSelect.value;
  if (!subscriptionId || !location) {
    return;
  }

  const result = await getVmSizeOptionsForLocation(subscriptionId, location, { force });

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
  updateActionAvailability();
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
    updateActionAvailability();
    return;
  }

  const data = await api(`/api/vms?subscriptionId=${encodeURIComponent(subscriptionId)}`);
  const rows = data.vms || [];
  state.allVms = rows;
  state.vmPage = 1;

  populateResourceGroupFilter(rows);
  await prefetchSizesForVmRows(subscriptionId, rows);
  applyVmFiltersAndRender();

  log(`虚拟机加载完成，共 ${rows.length} 台。`);
  updateActionAvailability();
}

function applyVmFiltersAndRender(options = {}) {
  const keepPage = Boolean(options.keepPage);
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

  state.filteredVms = filtered;
  if (!keepPage) {
    state.vmPage = 1;
  }
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
  await mapWithConcurrency(locations, SIZE_PREFETCH_CONCURRENCY, async (location) => {
    try {
      await getVmSizeOptionsForLocation(subscriptionId, location);
    } catch (err) {
      log(`地区 ${location} 规格预加载失败: ${err.message || String(err)}`, true);
    }
  });
}

function renderVmRows(rows) {
  const page = paginateItems(rows, state.vmPage, state.vmPageSize);
  state.vmPage = page.page;

  els.vmTableBody.innerHTML = '';

  if (!page.totalCount) {
    clearVmTable('没有匹配的虚拟机。');
    return;
  }

  const subscriptionId = currentSubscription();

  for (const vm of page.items) {
    const tr = document.createElement('tr');
    appendCell(tr, vm.name);
    appendCell(tr, vm.resourceGroup || '-');
    appendCell(tr, vm.location || '-');
    appendCell(tr, vm.vmSize || '-');
    appendStatusCell(tr, formatPowerStateLabel(vm.powerState), 'power', vm.powerState || '-');
    appendStatusCell(tr, formatProvisionStateLabel(vm.provisioningState), 'provision', vm.provisioningState || '-');

    const targetSizeTd = document.createElement('td');
    const sizeSelect = buildVmTargetSizeSelect(vm);
    targetSizeTd.appendChild(sizeSelect);
    tr.appendChild(targetSizeTd);

    const actionTd = document.createElement('td');
    const actionWrap = document.createElement('div');
    actionWrap.className = 'cell-actions';

    const buttons = [
      { label: '改规格', action: 'resize', className: 'ghost', title: '仅修改 VM 规格，不执行开关机。' },
      { label: '开机', action: 'start', title: '启动虚拟机。若选择了目标规格，可先改规格再开机。' },
      { label: '关机', action: 'powerOff', title: '执行关机动作。' },
      { label: '重启', action: 'restart', title: '重启虚拟机。' },
      { label: '释放', action: 'deallocate', className: 'ghost', title: '释放计算资源，通常用于停止计费。' },
      { label: '删除', action: 'delete', className: 'danger', title: '永久删除虚拟机，请谨慎操作。' }
    ];

    for (const item of buttons) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = item.label;
      btn.setAttribute('data-action', item.action);
      btn.title = item.title || '';
      if (item.className) {
        btn.classList.add(item.className);
      }

      btn.addEventListener('click', async () => {
        const action = item.action;
        const targetVmSize = normalizeTargetVmSize(sizeSelect.value);

        if (action === 'resize' && !targetVmSize) {
          log(`请先为 ${vm.name} 选择目标规格。`, true);
          return;
        }

        if (action === 'resize' && targetVmSize === String(vm.vmSize || '').trim()) {
          log(`${vm.name} 当前已是 ${targetVmSize}，无需改规格。`, true);
          return;
        }

        if (!confirmVmAction(action, vm.name)) {
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
          log(`操作成功: ${vm.name} -> ${actionLabel(action)}${suffix}`);
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

  updatePager({
    prevBtn: els.vmPagePrevBtn,
    nextBtn: els.vmPageNextBtn,
    infoEl: els.vmPageInfo,
    page: page.page,
    totalPages: page.totalPages,
    totalCount: page.totalCount
  });
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

function deriveUiReadiness() {
  const hasSubscription = Boolean(currentSubscription());
  const hasLocation = Boolean(String(els.locationSelect.value || '').trim());
  const hasConfig = Boolean(state.authenticated && state.configured);

  return {
    authenticated: Boolean(state.authenticated),
    configured: hasConfig,
    hasSubscription,
    hasLocation,
    canLoadLocations: Boolean(state.authenticated && hasConfig && hasSubscription),
    canLoadSizes: Boolean(state.authenticated && hasConfig && hasSubscription && hasLocation),
    canLoadVms: Boolean(state.authenticated && hasConfig && hasSubscription),
    canCreateVm: Boolean(state.authenticated && hasConfig && hasSubscription && hasLocation)
  };
}

function updateActionAvailability() {
  const ready = deriveUiReadiness();

  els.refreshAllBtn.disabled = !ready.authenticated;
  els.loadAuditBtn.disabled = !ready.authenticated;
  els.subscriptionSelect.disabled = !ready.authenticated || !ready.configured;
  els.locationSelect.disabled = !ready.authenticated || !ready.configured || !ready.hasSubscription;
  els.sizeSelect.disabled = !ready.canLoadSizes;
  els.createVmSizeSelect.disabled = !ready.canLoadSizes;
  els.loadLocationsBtn.disabled = !ready.canLoadLocations;
  els.loadSizesBtn.disabled = !ready.canLoadSizes;
  els.loadVmsBtn.disabled = !ready.canLoadVms;
  const sshMode = els.authTypeSelect && els.authTypeSelect.value === 'ssh';
  if (els.keychainSelect) {
    els.keychainSelect.disabled = !ready.authenticated || !sshMode;
  }
  if (els.applyKeychainBtn) {
    els.applyKeychainBtn.disabled = !ready.authenticated || !sshMode;
  }
  if (els.refreshKeychainBtn) {
    els.refreshKeychainBtn.disabled = !ready.authenticated || !sshMode;
  }
  if (els.addKeychainBtn) {
    els.addKeychainBtn.disabled = !ready.authenticated;
  }
  if (els.loadKeychainBtn) {
    els.loadKeychainBtn.disabled = !ready.authenticated;
  }
  if (els.keychainNameInput) {
    els.keychainNameInput.disabled = !ready.authenticated;
  }
  if (els.keychainValueInput) {
    els.keychainValueInput.disabled = !ready.authenticated;
  }
  if (els.vmPageSizeSelect) {
    els.vmPageSizeSelect.disabled = !ready.authenticated;
  }
  if (els.auditPageSizeSelect) {
    els.auditPageSizeSelect.disabled = !ready.authenticated;
  }
  if (els.loadTelegramConfigBtn) {
    els.loadTelegramConfigBtn.disabled = !ready.authenticated;
  }
  if (els.telegramBotTokenInput) {
    els.telegramBotTokenInput.disabled = !ready.authenticated;
  }
  if (els.telegramEnabledSelect) {
    els.telegramEnabledSelect.disabled = !ready.authenticated;
  }
  if (els.telegramAllowedChatIdsInput) {
    els.telegramAllowedChatIdsInput.disabled = !ready.authenticated;
  }
  if (els.saveTelegramConfigBtn) {
    els.saveTelegramConfigBtn.disabled = !ready.authenticated;
  }
  if (els.createVmSubmitBtn) {
    els.createVmSubmitBtn.disabled = !ready.canCreateVm;
  }

  renderReadinessStatus(ready);
  updateActionHints(ready);
}

function renderReadinessStatus(ready) {
  if (!els.readinessList) {
    return;
  }

  const steps = [
    { label: '登录面板', done: ready.authenticated },
    { label: '配置 Azure 凭据', done: ready.configured },
    { label: '选择订阅', done: ready.hasSubscription },
    { label: '选择地区', done: ready.hasLocation }
  ];

  const items = Array.from(els.readinessList.querySelectorAll('.check-item'));
  steps.forEach((step, idx) => {
    const li = items[idx];
    if (!li) {
      return;
    }
    li.classList.toggle('done', step.done);
    li.textContent = `${step.done ? '已完成' : '待完成'} · ${step.label}`;
  });

  if (!els.readinessHint) {
    return;
  }

  const missing = steps.find((x) => !x.done);
  if (missing) {
    els.readinessHint.textContent = `当前状态: 请先完成「${missing.label}」。`;
  } else {
    els.readinessHint.textContent = '当前状态: 已就绪，可进行创建和运维操作。';
  }
}

function updateActionHints(ready) {
  if (els.resourceActionHint) {
    if (!ready.authenticated) {
      els.resourceActionHint.textContent = '请先登录后再加载地区、规格和虚拟机。';
    } else if (!ready.configured) {
      els.resourceActionHint.textContent = '请先在步骤 1 保存 Azure 凭据。';
    } else if (!ready.hasSubscription) {
      els.resourceActionHint.textContent = '请先选择订阅，再加载地区和虚拟机。';
    } else if (!ready.hasLocation) {
      els.resourceActionHint.textContent = '请选择地区后再加载规格。';
    } else {
      els.resourceActionHint.textContent = '已就绪: 可以刷新地区、规格和虚拟机列表。';
    }
  }

  if (els.createActionHint) {
    const authTip = els.authTypeSelect.value === 'ssh'
      ? '认证方式: SSH 公钥（可直接选 Keychain）。'
      : '认证方式: 密码（至少 12 位）。';
    const networkTip = els.networkModeSelect.value === 'existing-nic'
      ? '网络模式: 使用现有 NIC（需填写完整资源 ID）。'
      : '网络模式: 自动创建 VNet/Subnet/Public IP/NIC。';

    if (!ready.canCreateVm) {
      if (!ready.authenticated) {
        els.createActionHint.textContent = `未就绪: 请先登录。${authTip} ${networkTip}`;
      } else if (!ready.configured) {
        els.createActionHint.textContent = `未就绪: 请先保存 Azure 凭据。${authTip} ${networkTip}`;
      } else if (!ready.hasSubscription) {
        els.createActionHint.textContent = `未就绪: 请先选择订阅。${authTip} ${networkTip}`;
      } else {
        els.createActionHint.textContent = `未就绪: 请先选择地区。${authTip} ${networkTip}`;
      }
    } else {
      els.createActionHint.textContent = `已就绪: 可以创建虚拟机。${authTip} ${networkTip}`;
    }
  }
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

function appendStatusCell(tr, value, kind, rawValue = value) {
  const td = document.createElement('td');
  const span = document.createElement('span');
  span.className = `pill ${pillClass(rawValue, kind)}`;
  span.textContent = String(value == null ? '-' : value);
  td.appendChild(span);
  tr.appendChild(td);
}

function formatPowerStateLabel(value) {
  const v = String(value || '').toLowerCase();
  if (!v || v === '-') {
    return '-';
  }
  if (v.indexOf('running') >= 0) {
    return '运行中';
  }
  if (v.indexOf('deallocated') >= 0) {
    return '已释放';
  }
  if (v.indexOf('stopped') >= 0 || v.indexOf('off') >= 0) {
    return '已关机';
  }
  if (v.indexOf('starting') >= 0) {
    return '启动中';
  }
  if (v.indexOf('stopping') >= 0) {
    return '停止中';
  }
  if (v.indexOf('deallocating') >= 0) {
    return '释放中';
  }
  return String(value);
}

function formatProvisionStateLabel(value) {
  const v = String(value || '').toLowerCase();
  if (!v || v === '-') {
    return '-';
  }
  if (v.indexOf('succeeded') >= 0) {
    return '成功';
  }
  if (v.indexOf('failed') >= 0) {
    return '失败';
  }
  if (v.indexOf('creating') >= 0) {
    return '创建中';
  }
  if (v.indexOf('updating') >= 0) {
    return '更新中';
  }
  if (v.indexOf('deleting') >= 0) {
    return '删除中';
  }
  return String(value);
}

function formatSubscriptionState(value) {
  const v = String(value || '').toLowerCase();
  if (!v || v === '-') {
    return '-';
  }
  if (v === 'enabled') {
    return '已启用';
  }
  if (v === 'disabled') {
    return '已禁用';
  }
  if (v === 'warned') {
    return '告警';
  }
  if (v === 'pastdue') {
    return '欠费';
  }
  return String(value);
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

function actionLabel(action) {
  const map = {
    start: '开机',
    powerOff: '关机',
    restart: '重启',
    deallocate: '释放',
    delete: '删除',
    resize: '改规格'
  };
  return map[action] || action;
}

function confirmVmAction(action, vmName) {
  if (action === 'delete') {
    return window.confirm(`确定删除虚拟机 ${vmName}？该操作不可恢复。`);
  }
  if (action === 'deallocate') {
    return window.confirm(`确定释放虚拟机 ${vmName}？释放后将停止运行。`);
  }
  return true;
}

async function loadAudit() {
  const data = await api('/api/audit?limit=500');
  state.auditRows = data.entries || [];
  state.auditPage = 1;
  renderAuditRows();
}

function renderAuditRows() {
  const page = paginateItems(state.auditRows, state.auditPage, state.auditPageSize);
  state.auditPage = page.page;

  els.auditTableBody.innerHTML = '';
  if (!page.totalCount) {
    clearAuditTable('暂无审计记录。');
    return;
  }

  for (const row of page.items) {
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

  updatePager({
    prevBtn: els.auditPagePrevBtn,
    nextBtn: els.auditPageNextBtn,
    infoEl: els.auditPageInfo,
    page: page.page,
    totalPages: page.totalPages,
    totalCount: page.totalCount
  });
}

function clearVmTable(message) {
  els.vmTableBody.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `<td colspan="8">${escapeHtml(message)}</td>`;
  els.vmTableBody.appendChild(tr);
  updatePager({
    prevBtn: els.vmPagePrevBtn,
    nextBtn: els.vmPageNextBtn,
    infoEl: els.vmPageInfo,
    page: 1,
    totalPages: 1,
    totalCount: 0
  });
}

function clearAuditTable(message) {
  els.auditTableBody.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `<td colspan="6">${escapeHtml(message)}</td>`;
  els.auditTableBody.appendChild(tr);
  updatePager({
    prevBtn: els.auditPagePrevBtn,
    nextBtn: els.auditPageNextBtn,
    infoEl: els.auditPageInfo,
    page: 1,
    totalPages: 1,
    totalCount: 0
  });
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

function normalizePageSize(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    return fallback;
  }
  return Math.floor(n);
}

function paginateItems(items, page, pageSize) {
  const totalCount = Array.isArray(items) ? items.length : 0;
  const size = Math.max(1, normalizePageSize(pageSize, 20));
  const totalPages = Math.max(1, Math.ceil(totalCount / size));
  const safePage = Math.min(Math.max(1, Number(page || 1)), totalPages);
  const start = (safePage - 1) * size;
  const pageItems = totalCount ? items.slice(start, start + size) : [];

  return {
    items: pageItems,
    page: safePage,
    pageSize: size,
    totalPages,
    totalCount
  };
}

function updatePager({ prevBtn, nextBtn, infoEl, page, totalPages, totalCount }) {
  if (infoEl) {
    infoEl.textContent = `第 ${page} / ${totalPages} 页 · 共 ${totalCount} 条`;
  }
  if (prevBtn) {
    prevBtn.disabled = page <= 1 || totalCount <= 0;
  }
  if (nextBtn) {
    nextBtn.disabled = page >= totalPages || totalCount <= 0;
  }
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

async function mapWithConcurrency(items, concurrency, mapper) {
  if (!items.length) {
    return [];
  }

  const out = new Array(items.length);
  let nextIndex = 0;

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const current = nextIndex;
      nextIndex += 1;
      if (current >= items.length) {
        return;
      }
      out[current] = await mapper(items[current], current);
    }
  });

  await Promise.all(workers);
  return out;
}
