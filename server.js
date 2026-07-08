const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

loadEnv(path.join(__dirname, '.env'));

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 18080);
const PUBLIC_DIR = path.join(__dirname, 'public');
const PANEL_ADMIN_USERNAME = process.env.PANEL_ADMIN_USERNAME || 'admin';
const PANEL_ADMIN_PASSWORD = process.env.PANEL_ADMIN_PASSWORD || 'admin123456';
const SESSION_TTL_MS = Math.max(1, Number(process.env.SESSION_TTL_HOURS || 8)) * 60 * 60 * 1000;
const MAX_JSON_BODY_BYTES = Math.max(1024, Number(process.env.MAX_JSON_BODY_BYTES || 1024 * 1024));
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || path.join(__dirname, 'audit.log');
const AZURE_RUNTIME_CONFIG_PATH = process.env.AZURE_RUNTIME_CONFIG_PATH || path.join(__dirname, '.azure-runtime-config.json');
const PERSIST_AZURE_CONFIG = String(process.env.PERSIST_AZURE_CONFIG || 'true').toLowerCase() !== 'false';
const KEYCHAIN_PATH = process.env.KEYCHAIN_PATH || path.join(__dirname, '.keychain.json');
const PERSIST_KEYCHAIN = String(process.env.PERSIST_KEYCHAIN || 'true').toLowerCase() !== 'false';
const TELEGRAM_RUNTIME_CONFIG_PATH = process.env.TELEGRAM_RUNTIME_CONFIG_PATH || path.join(__dirname, '.telegram-runtime-config.json');
const PERSIST_TELEGRAM_CONFIG = String(process.env.PERSIST_TELEGRAM_CONFIG || 'true').toLowerCase() !== 'false';
const POWER_STATE_CACHE_TTL_MS = Math.max(0, Number(process.env.POWER_STATE_CACHE_TTL_MS || 15_000));
const fetchImpl = typeof global.fetch === 'function' ? global.fetch.bind(global) : createCompatFetch();

const runtimeConfig = {
  tenantId: process.env.AZURE_TENANT_ID || '',
  clientId: process.env.AZURE_CLIENT_ID || '',
  clientSecret: process.env.AZURE_CLIENT_SECRET || ''
};

let tokenCache = {
  value: '',
  expiresAtMs: 0
};

const telegramRuntimeConfig = {
  botToken: String(process.env.TELEGRAM_BOT_TOKEN || '').trim(),
  enabled: String(process.env.TELEGRAM_ENABLED || 'false').toLowerCase() === 'true',
  allowedChatIds: parseTelegramAllowedChatIds(process.env.TELEGRAM_ALLOWED_CHAT_IDS || '')
};

const telegramState = {
  knownChats: [],
  lastUpdateId: 0,
  pollerVersion: 0,
  pollerRunning: false,
  lastError: ''
};

const sessions = new Map();
const auditEntries = [];
const keychainEntries = [];
const vmPowerStateCache = new Map();
const MAX_AUDIT_ENTRIES = 1000;
const MAX_KEYCHAIN_ENTRIES = 300;

const IMAGE_OPTIONS = [
  {
    id: 'ubuntu-2204',
    label: 'Ubuntu 22.04 LTS',
    publisher: 'Canonical',
    offer: '0001-com-ubuntu-server-jammy',
    sku: '22_04-lts-gen2',
    version: 'latest'
  },
  {
    id: 'ubuntu-2404',
    label: 'Ubuntu 24.04 LTS',
    publisher: 'Canonical',
    offer: 'ubuntu-24_04-lts',
    sku: 'server',
    version: 'latest'
  },
  {
    id: 'windows-2022',
    label: 'Windows Server 2022 Datacenter',
    publisher: 'MicrosoftWindowsServer',
    offer: 'WindowsServer',
    sku: '2022-datacenter-azure-edition',
    version: 'latest'
  }
];

const DEFAULT_REGIONS = [
  'eastus',
  'eastus2',
  'westus3',
  'centralus',
  'northcentralus',
  'southcentralus',
  'westeurope',
  'northeurope',
  'southeastasia',
  'eastasia',
  'japaneast'
];

loadRuntimeConfigFromDisk();
loadAuditEntries();
loadKeychainFromDisk();
loadTelegramConfigFromDisk();
restartTelegramPoller();

const server = http.createServer(async (req, res) => {
  let url = null;
  let actor = 'anonymous';
  let ip = '';
  try {
    pruneExpiredSessions();
    pruneVmPowerStateCache();
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    ip = getClientIp(req);
    const session = getSession(req);
    actor = session ? session.username : 'anonymous';

    if (req.method === 'POST' && url.pathname === '/api/auth/login') {
      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      if (username !== PANEL_ADMIN_USERNAME || password !== PANEL_ADMIN_PASSWORD) {
        recordAudit({
          action: 'auth.login',
          success: false,
          actor: username || 'unknown',
          ip,
          details: { reason: 'invalid_credentials' }
        });
        return sendJson(res, 401, { error: '用户名或密码错误。' });
      }

      const newSessionId = createSession(username);
      recordAudit({
        action: 'auth.login',
        success: true,
        actor: username,
        ip
      });

      return sendJson(
        res,
        200,
        {
          ok: true,
          username
        },
        { 'Set-Cookie': serializeSessionCookie(newSessionId) }
      );
    }

    if (req.method === 'GET' && url.pathname === '/api/auth/me') {
      if (!session) {
        return sendJson(res, 200, { authenticated: false });
      }
      return sendJson(res, 200, { authenticated: true, username: session.username });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/logout') {
      const sessionId = getSessionIdFromCookie(req);
      if (sessionId) {
        const existingSession = sessions.get(sessionId);
        sessions.delete(sessionId);
        if (existingSession) {
          recordAudit({
            action: 'auth.logout',
            success: true,
            actor: existingSession.username,
            ip
          });
        }
      }
      return sendJson(
        res,
        200,
        { ok: true },
        { 'Set-Cookie': serializeExpiredSessionCookie() }
      );
    }

    if (url.pathname.startsWith('/api/') && !isPublicApi(url.pathname) && !session) {
      recordAudit({
        action: 'auth.denied',
        success: false,
        actor: 'anonymous',
        ip,
        details: { method: req.method, path: url.pathname }
      });
      return sendJson(res, 401, { error: '未登录或会话已过期，请先登录。' });
    }

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, now: new Date().toISOString() });
    }

    if (req.method === 'GET' && url.pathname === '/api/config') {
      return sendJson(res, 200, {
        configured: hasRuntimeConfig(),
        persisted: PERSIST_AZURE_CONFIG
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/config') {
      const body = await readJsonBody(req);
      runtimeConfig.tenantId = String(body.tenantId || '').trim();
      runtimeConfig.clientId = String(body.clientId || '').trim();
      runtimeConfig.clientSecret = String(body.clientSecret || '').trim();
      tokenCache = { value: '', expiresAtMs: 0 };

      const valid = Boolean(runtimeConfig.tenantId && runtimeConfig.clientId && runtimeConfig.clientSecret);
      if (!valid) {
        recordAudit({
          action: 'azure.config.update',
          success: false,
          actor,
          ip,
          details: { reason: 'missing_credentials' }
        });
        return sendJson(res, 400, { error: 'tenantId/clientId/clientSecret are required.' });
      }

      recordAudit({
        action: 'azure.config.update',
        success: true,
        actor,
        ip
      });
      persistRuntimeConfigToDisk();
      return sendJson(res, 200, { ok: true, persisted: PERSIST_AZURE_CONFIG });
    }

    if (req.method === 'GET' && url.pathname === '/api/images') {
      return sendJson(res, 200, { images: IMAGE_OPTIONS });
    }

    if (req.method === 'GET' && url.pathname === '/api/keychain') {
      return sendJson(res, 200, {
        entries: keychainEntries.map(toClientKeychainEntry)
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/keychain') {
      const body = await readJsonBody(req);
      const type = normalizeKeychainType(body.type);
      const name = required(body.name, 'name');
      const value = required(body.value, 'value');

      validateKeychainValue(type, value);

      if (keychainEntries.length >= MAX_KEYCHAIN_ENTRIES) {
        return sendJson(res, 400, { error: `Keychain capacity exceeded. Max ${MAX_KEYCHAIN_ENTRIES} entries.` });
      }

      const nowIso = new Date().toISOString();
      const entry = {
        id: createEntityId(),
        type,
        name: sanitizeKeychainName(name),
        value: String(value).trim(),
        createdAt: nowIso,
        updatedAt: nowIso
      };
      keychainEntries.unshift(entry);
      persistKeychainToDisk();

      recordAudit({
        action: 'keychain.create',
        success: true,
        actor,
        ip,
        details: {
          keychainId: entry.id,
          type: entry.type,
          name: entry.name
        }
      });

      return sendJson(res, 200, { ok: true, entry: toClientKeychainEntry(entry) });
    }

    if (req.method === 'DELETE' && url.pathname === '/api/keychain') {
      const body = await readJsonBody(req);
      const id = required(body.id, 'id');
      const idx = keychainEntries.findIndex((x) => x && x.id === id);
      if (idx < 0) {
        return sendJson(res, 404, { error: 'Keychain entry not found.' });
      }

      const removed = keychainEntries.splice(idx, 1)[0];
      persistKeychainToDisk();

      recordAudit({
        action: 'keychain.delete',
        success: true,
        actor,
        ip,
        details: {
          keychainId: removed.id,
          type: removed.type,
          name: removed.name
        }
      });

      return sendJson(res, 200, { ok: true, id: removed.id });
    }

    if (req.method === 'GET' && url.pathname === '/api/telegram/config') {
      return sendJson(res, 200, buildTelegramConfigResponse());
    }

    if (req.method === 'GET' && url.pathname === '/api/telegram/chats') {
      return sendJson(res, 200, {
        chats: telegramState.knownChats.map(toClientTelegramChat),
        allowedChatIds: [...telegramRuntimeConfig.allowedChatIds]
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/telegram/config') {
      const body = await readJsonBody(req);
      let nextBotToken = telegramRuntimeConfig.botToken;
      let nextAllowedChatIds = telegramRuntimeConfig.allowedChatIds;
      let nextEnabled = telegramRuntimeConfig.enabled;

      if (Object.prototype.hasOwnProperty.call(body, 'botToken')) {
        nextBotToken = String(body.botToken || '').trim();
      }

      if (Object.prototype.hasOwnProperty.call(body, 'allowedChatIds')) {
        nextAllowedChatIds = normalizeTelegramAllowedChatIds(body.allowedChatIds);
      }

      if (Object.prototype.hasOwnProperty.call(body, 'enabled')) {
        nextEnabled = Boolean(body.enabled);
      }

      if (nextEnabled && !nextBotToken) {
        return sendJson(res, 400, { error: 'botToken is required when telegram bot is enabled.' });
      }

      telegramRuntimeConfig.botToken = nextBotToken;
      telegramRuntimeConfig.allowedChatIds = nextAllowedChatIds;
      telegramRuntimeConfig.enabled = nextEnabled;

      persistTelegramConfigToDisk();
      restartTelegramPoller();

      recordAudit({
        action: 'telegram.config.update',
        success: true,
        actor,
        ip,
        details: {
          enabled: telegramRuntimeConfig.enabled,
          hasToken: Boolean(telegramRuntimeConfig.botToken),
          allowedChatCount: telegramRuntimeConfig.allowedChatIds.length
        }
      });

      return sendJson(res, 200, buildTelegramConfigResponse());
    }

    if (req.method === 'GET' && url.pathname === '/api/audit') {
      const limitRaw = Number(url.searchParams.get('limit') || 100);
      const limit = Math.max(1, Math.min(Number.isFinite(limitRaw) ? limitRaw : 100, 500));
      return sendJson(res, 200, { entries: auditEntries.slice(0, limit) });
    }

    if (req.method === 'GET' && url.pathname === '/api/subscriptions') {
      const payload = await azureRequest({
        method: 'GET',
        url: 'https://management.azure.com/subscriptions?api-version=2022-12-01'
      });

      return sendJson(res, 200, {
        subscriptions: (payload.value || []).map((s) => ({
          id: s.subscriptionId,
          displayName: s.displayName,
          state: s.state
        }))
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/locations') {
      const subscriptionId = mustQuery(url, 'subscriptionId');
      const payload = await azureRequest({
        method: 'GET',
        url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/locations?api-version=2022-12-01`
      });

      const locations = (payload.value || []).map((x) => x.name).filter(Boolean).sort();
      return sendJson(res, 200, { locations: locations.length ? locations : DEFAULT_REGIONS });
    }

    if (req.method === 'GET' && url.pathname === '/api/vm-sizes') {
      const subscriptionId = mustQuery(url, 'subscriptionId');
      const location = mustQuery(url, 'location');

      const sizeResult = await getVmSizes(subscriptionId, location);
      return sendJson(res, 200, {
        sizes: sizeResult.sizes,
        source: sizeResult.source
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/vms') {
      const subscriptionId = mustQuery(url, 'subscriptionId');

      const list = await azureRequest({
        method: 'GET',
        url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01`
      });

      const vms = await mapWithConcurrency(list.value || [], 5, async (vm) => {
        const parts = parseResourceId(vm.id || '');
        const powerState = await resolveVmPowerState(subscriptionId, vm, parts);

        return {
          id: vm.id,
          name: vm.name,
          resourceGroup: parts.resourceGroup,
          location: vm.location,
          vmSize: (vm.properties && vm.properties.hardwareProfile && vm.properties.hardwareProfile.vmSize) || '-',
          provisioningState: (vm.properties && vm.properties.provisioningState) || '-',
          powerState
        };
      });

      return sendJson(res, 200, { vms });
    }

    if (req.method === 'POST' && url.pathname === '/api/vm/action') {
      const body = await readJsonBody(req);
      const subscriptionId = required(body.subscriptionId, 'subscriptionId');
      const resourceGroup = required(body.resourceGroup, 'resourceGroup');
      const name = required(body.name, 'name');
      const action = required(body.action, 'action');
      const requestedVmSize = String(body.vmSize || '').trim();

      const baseUrl = `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(resourceGroup)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(name)}`;
      const vmUrl = `${baseUrl}?api-version=2024-03-01`;

      if (action === 'delete') {
        const op = await azureLroRequest({
          method: 'DELETE',
          url: `${baseUrl}?api-version=2024-03-01`
        });
        recordAudit({
          action: 'vm.delete',
          success: true,
          actor,
          ip,
          details: { subscriptionId, resourceGroup, name }
        });
        return sendJson(res, 200, { ok: true, action, operation: op });
      }

      if (action === 'resize') {
        const vmSize = required(requestedVmSize, 'vmSize');
        const vmInfo = await azureRequest({
          method: 'GET',
          url: vmUrl
        });
        const oldVmSize = readVmSize(vmInfo);

        const op = await azureLroRequest({
          method: 'PATCH',
          url: vmUrl,
          body: {
            properties: {
              hardwareProfile: {
                vmSize
              }
            }
          }
        });

        recordAudit({
          action: 'vm.resize',
          success: true,
          actor,
          ip,
          details: { subscriptionId, resourceGroup, name, oldVmSize, newVmSize: vmSize }
        });

        return sendJson(res, 200, {
          ok: true,
          action,
          operation: op,
          oldVmSize,
          newVmSize: vmSize
        });
      }

      const allowed = new Set(['start', 'powerOff', 'deallocate', 'restart', 'resize']);
      if (!allowed.has(action)) {
        recordAudit({
          action: 'vm.action',
          success: false,
          actor,
          ip,
          details: { subscriptionId, resourceGroup, name, action, reason: 'unsupported_action' }
        });
        return sendJson(res, 400, { error: 'Unsupported action.' });
      }

      let resizedBeforeStart = false;
      let oldVmSize = '';
      let newVmSize = '';

      if (action === 'start' && requestedVmSize) {
        const vmInfo = await azureRequest({
          method: 'GET',
          url: vmUrl
        });
        oldVmSize = readVmSize(vmInfo);
        newVmSize = requestedVmSize;

        if (oldVmSize && oldVmSize !== newVmSize) {
          await azureLroRequest({
            method: 'PATCH',
            url: vmUrl,
            body: {
              properties: {
                hardwareProfile: {
                  vmSize: newVmSize
                }
              }
            }
          });
          resizedBeforeStart = true;
        }
      }

      const op = await azureLroRequest({
        method: 'POST',
        url: `${baseUrl}/${action}?api-version=2024-03-01`,
        body: {}
      });

      recordAudit({
        action: `vm.${action}`,
        success: true,
        actor,
        ip,
        details: {
          subscriptionId,
          resourceGroup,
          name,
          requestedVmSize: requestedVmSize || '',
          resizedBeforeStart,
          oldVmSize,
          newVmSize
        }
      });
      return sendJson(res, 200, { ok: true, action, operation: op });
    }

    if (req.method === 'POST' && url.pathname === '/api/vm/create') {
      const body = await readJsonBody(req);

      const subscriptionId = required(body.subscriptionId, 'subscriptionId');
      const resourceGroup = required(body.resourceGroup, 'resourceGroup');
      const name = required(body.name, 'name');
      const location = required(body.location, 'location');
      const vmSize = required(body.vmSize, 'vmSize');
      const adminUsername = required(body.adminUsername, 'adminUsername');
      const imageId = required(body.imageId, 'imageId');

      const image = IMAGE_OPTIONS.find((x) => x.id === imageId);
      if (!image) {
        return sendJson(res, 400, { error: 'Unsupported imageId.' });
      }

      const authType = body.authType === 'ssh' ? 'ssh' : 'password';
      const adminPassword = String(body.adminPassword || '');
      const keychainId = String(body.keychainId || '').trim();
      let sshPublicKey = String(body.sshPublicKey || '').trim();

      if (authType === 'ssh' && !sshPublicKey && keychainId) {
        const keychainEntry = findKeychainEntryById(keychainId);
        if (!keychainEntry) {
          return sendJson(res, 400, { error: 'keychainId not found.' });
        }
        if (keychainEntry.type !== 'ssh-public-key') {
          return sendJson(res, 400, { error: 'keychainId type is not ssh-public-key.' });
        }
        sshPublicKey = keychainEntry.value;
      }

      if (authType === 'password' && adminPassword.length < 12) {
        return sendJson(res, 400, { error: 'adminPassword must be at least 12 characters when using password auth.' });
      }

      if (authType === 'ssh' && sshPublicKey.length < 40) {
        return sendJson(res, 400, { error: 'sshPublicKey looks invalid.' });
      }

      const networkMode = body.networkMode === 'existing-nic' ? 'existing-nic' : 'auto';
      const existingNicId = String(body.existingNicId || '').trim();

      let nicId = existingNicId;
      let createdNetwork = null;

      await azureLroRequest({
        method: 'PUT',
        url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourcegroups/${encodeURIComponent(resourceGroup)}?api-version=2021-04-01`,
        body: { location }
      });

      if (networkMode === 'auto') {
        const suffix = randomSuffix();
        const vnetName = sanitizeName(body.vnetName) || `vnet-${name}-${suffix}`;
        const subnetName = sanitizeName(body.subnetName) || 'default';
        const publicIpName = sanitizeName(body.publicIpName) || `pip-${name}-${suffix}`;
        const nicName = sanitizeName(body.nicName) || `nic-${name}-${suffix}`;
        const addressPrefix = String(body.addressPrefix || '10.20.0.0/16').trim();
        const subnetPrefix = String(body.subnetPrefix || '10.20.1.0/24').trim();

        const vnet = await azureLroRequest({
          method: 'PUT',
          url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(resourceGroup)}/providers/Microsoft.Network/virtualNetworks/${encodeURIComponent(vnetName)}?api-version=2023-09-01`,
          body: {
            location,
            properties: {
              addressSpace: {
                addressPrefixes: [addressPrefix]
              },
              subnets: [
                {
                  name: subnetName,
                  properties: {
                    addressPrefix: subnetPrefix
                  }
                }
              ]
            }
          }
        });

        const pip = await azureLroRequest({
          method: 'PUT',
          url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(resourceGroup)}/providers/Microsoft.Network/publicIPAddresses/${encodeURIComponent(publicIpName)}?api-version=2023-09-01`,
          body: {
            location,
            sku: { name: 'Standard' },
            properties: {
              publicIPAllocationMethod: 'Static'
            }
          }
        });

        const subnetId = (
          vnet &&
          vnet.properties &&
          Array.isArray(vnet.properties.subnets) &&
          vnet.properties.subnets[0] &&
          vnet.properties.subnets[0].id
        ) ||
          `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Network/virtualNetworks/${vnetName}/subnets/${subnetName}`;

        const nic = await azureLroRequest({
          method: 'PUT',
          url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(resourceGroup)}/providers/Microsoft.Network/networkInterfaces/${encodeURIComponent(nicName)}?api-version=2023-09-01`,
          body: {
            location,
            properties: {
              ipConfigurations: [
                {
                  name: 'ipconfig1',
                  properties: {
                    subnet: { id: subnetId },
                    privateIPAllocationMethod: 'Dynamic',
                    publicIPAddress: {
                      id: pip.id
                    }
                  }
                }
              ]
            }
          }
        });

        nicId = nic.id;
        createdNetwork = {
          vnetName,
          subnetName,
          publicIpName,
          nicName,
          nicId
        };
      }

      if (!nicId) {
        return sendJson(res, 400, { error: 'NIC is required. Provide existingNicId or use auto network mode.' });
      }

      const vmBody = {
        location,
        properties: {
          hardwareProfile: {
            vmSize
          },
          storageProfile: {
            imageReference: {
              publisher: image.publisher,
              offer: image.offer,
              sku: image.sku,
              version: image.version
            },
            osDisk: {
              createOption: 'FromImage',
              managedDisk: {
                storageAccountType: 'StandardSSD_LRS'
              }
            }
          },
          osProfile: {
            computerName: name,
            adminUsername
          },
          networkProfile: {
            networkInterfaces: [
              {
                id: nicId,
                properties: {
                  primary: true
                }
              }
            ]
          }
        }
      };

      if (image.id.startsWith('windows')) {
        if (!adminPassword) {
          return sendJson(res, 400, { error: 'Windows image requires adminPassword.' });
        }
        vmBody.properties.osProfile.adminPassword = adminPassword;
      } else if (authType === 'ssh') {
        vmBody.properties.osProfile.linuxConfiguration = {
          disablePasswordAuthentication: true,
          ssh: {
            publicKeys: [
              {
                path: `/home/${adminUsername}/.ssh/authorized_keys`,
                keyData: sshPublicKey
              }
            ]
          }
        };
      } else {
        vmBody.properties.osProfile.adminPassword = adminPassword;
        vmBody.properties.osProfile.linuxConfiguration = {
          disablePasswordAuthentication: false
        };
      }

      const vmResult = await azureLroRequest({
        method: 'PUT',
        url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(resourceGroup)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(name)}?api-version=2024-03-01`,
        body: vmBody
      });

      recordAudit({
        action: 'vm.create',
        success: true,
        actor,
        ip,
        details: { subscriptionId, resourceGroup, name, location, vmSize, imageId, networkMode, authType, keychainId: keychainId || '' }
      });
      return sendJson(res, 200, {
        ok: true,
        vm: {
          id: vmResult.id,
          name: vmResult.name,
          location: vmResult.location,
          resourceGroup,
          vmSize
        },
        network: createdNetwork
      });
    }

    if (req.method === 'GET') {
      return serveStatic(url.pathname, res);
    }

    return sendJson(res, 404, { error: 'Not found.' });
  } catch (err) {
    if (url && url.pathname.startsWith('/api/') && !isPublicApi(url.pathname)) {
      recordAudit({
        action: 'api.error',
        success: false,
        actor,
        ip,
        details: {
          method: req.method,
          path: url.pathname,
          message: err.message || 'Unexpected error.'
        }
      });
    }
    const status = Number(err.statusCode || 500);
    return sendJson(res, status, {
      error: err.message || 'Unexpected error.',
      details: err.details || undefined
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Azure VM panel running at http://${HOST}:${PORT}`);
});

function loadEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    if (!line || line.trim().startsWith('#')) {
      continue;
    }

    const idx = line.indexOf('=');
    if (idx <= 0) {
      continue;
    }

    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function hasRuntimeConfig() {
  return Boolean(runtimeConfig.tenantId && runtimeConfig.clientId && runtimeConfig.clientSecret);
}

function loadRuntimeConfigFromDisk() {
  if (!PERSIST_AZURE_CONFIG) {
    return;
  }

  if (hasRuntimeConfig()) {
    return;
  }

  if (!fs.existsSync(AZURE_RUNTIME_CONFIG_PATH)) {
    return;
  }

  try {
    const raw = fs.readFileSync(AZURE_RUNTIME_CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);

    runtimeConfig.tenantId = String(parsed.tenantId || '').trim();
    runtimeConfig.clientId = String(parsed.clientId || '').trim();
    runtimeConfig.clientSecret = String(parsed.clientSecret || '').trim();
  } catch {
    // Ignore broken persisted config files.
  }
}

function persistRuntimeConfigToDisk() {
  if (!PERSIST_AZURE_CONFIG) {
    return;
  }

  if (!hasRuntimeConfig()) {
    return;
  }

  const payload = {
    tenantId: runtimeConfig.tenantId,
    clientId: runtimeConfig.clientId,
    clientSecret: runtimeConfig.clientSecret
  };

  try {
    fs.writeFileSync(AZURE_RUNTIME_CONFIG_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    try {
      fs.chmodSync(AZURE_RUNTIME_CONFIG_PATH, 0o600);
    } catch {
      // Ignore chmod failures on limited filesystems.
    }
  } catch {
    // Persistence is best-effort and should not break API response flow.
  }
}

function loadKeychainFromDisk() {
  if (!PERSIST_KEYCHAIN) {
    return;
  }

  if (!fs.existsSync(KEYCHAIN_PATH)) {
    return;
  }

  try {
    const raw = fs.readFileSync(KEYCHAIN_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    const list = Array.isArray(parsed && parsed.entries) ? parsed.entries : [];
    const normalized = [];

    for (const item of list) {
      if (!item || typeof item !== 'object') {
        continue;
      }

      const type = normalizeKeychainType(item.type);
      const name = sanitizeKeychainName(item.name || '');
      const value = String(item.value || '').trim();
      if (!name || !value) {
        continue;
      }

      try {
        validateKeychainValue(type, value);
      } catch {
        continue;
      }

      normalized.push({
        id: String(item.id || createEntityId()),
        type,
        name,
        value,
        createdAt: String(item.createdAt || new Date().toISOString()),
        updatedAt: String(item.updatedAt || new Date().toISOString())
      });
    }

    keychainEntries.length = 0;
    for (const item of normalized.slice(0, MAX_KEYCHAIN_ENTRIES)) {
      keychainEntries.push(item);
    }
  } catch {
    // Ignore broken keychain files.
  }
}

function persistKeychainToDisk() {
  if (!PERSIST_KEYCHAIN) {
    return;
  }

  const payload = {
    entries: keychainEntries.map((item) => ({
      id: item.id,
      type: item.type,
      name: item.name,
      value: item.value,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt
    }))
  };

  try {
    fs.writeFileSync(KEYCHAIN_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    try {
      fs.chmodSync(KEYCHAIN_PATH, 0o600);
    } catch {
      // Ignore chmod failures on limited filesystems.
    }
  } catch {
    // Persistence is best-effort and should not break API response flow.
  }
}

function findKeychainEntryById(id) {
  const target = String(id || '').trim();
  if (!target) {
    return null;
  }

  for (const item of keychainEntries) {
    if (item && item.id === target) {
      return item;
    }
  }
  return null;
}

function toClientKeychainEntry(item) {
  return {
    id: item.id,
    type: item.type,
    name: item.name,
    value: item.value,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt
  };
}

function normalizeKeychainType(type) {
  const value = String(type || '').trim().toLowerCase();
  return value === 'ssh-public-key' ? value : 'ssh-public-key';
}

function sanitizeKeychainName(name) {
  const out = String(name || '').trim().replace(/\s+/g, ' ');
  return out.slice(0, 120);
}

function validateKeychainValue(type, value) {
  const trimmed = String(value || '').trim();
  if (!trimmed) {
    const err = new Error('value is required.');
    err.statusCode = 400;
    throw err;
  }

  if (type === 'ssh-public-key') {
    if (trimmed.length < 40 || !/^(ssh-|ecdsa-|sk-ssh-|sk-ecdsa-)/.test(trimmed)) {
      const err = new Error('Invalid ssh public key format.');
      err.statusCode = 400;
      throw err;
    }
  }
}

function parseTelegramAllowedChatIds(raw) {
  return normalizeTelegramAllowedChatIds(raw);
}

function normalizeTelegramAllowedChatIds(value) {
  const list = Array.isArray(value)
    ? value
    : String(value || '').split(',');

  const out = [];
  const seen = {};
  for (const item of list) {
    const id = String(item || '').trim();
    if (!id || !/^-?\d+$/.test(id)) {
      continue;
    }
    if (seen[id]) {
      continue;
    }
    seen[id] = true;
    out.push(id);
  }
  return out;
}

function loadTelegramConfigFromDisk() {
  if (!PERSIST_TELEGRAM_CONFIG) {
    return;
  }

  if (!fs.existsSync(TELEGRAM_RUNTIME_CONFIG_PATH)) {
    return;
  }

  try {
    const raw = fs.readFileSync(TELEGRAM_RUNTIME_CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);

    if (!telegramRuntimeConfig.botToken) {
      telegramRuntimeConfig.botToken = String(parsed.botToken || '').trim();
    }
    if (!telegramRuntimeConfig.allowedChatIds.length) {
      telegramRuntimeConfig.allowedChatIds = normalizeTelegramAllowedChatIds(parsed.allowedChatIds || []);
    }
    if (!telegramRuntimeConfig.enabled && parsed && typeof parsed.enabled === 'boolean') {
      telegramRuntimeConfig.enabled = Boolean(parsed.enabled);
    }

    const knownChats = Array.isArray(parsed && parsed.knownChats) ? parsed.knownChats : [];
    for (const chat of knownChats) {
      if (!chat || typeof chat !== 'object') {
        continue;
      }
      const chatId = String(chat.id || '').trim();
      if (!chatId || !/^-?\d+$/.test(chatId)) {
        continue;
      }
      telegramState.knownChats.push({
        id: chatId,
        type: String(chat.type || ''),
        title: String(chat.title || ''),
        username: String(chat.username || ''),
        firstSeenAt: String(chat.firstSeenAt || new Date().toISOString()),
        lastSeenAt: String(chat.lastSeenAt || new Date().toISOString())
      });
    }

    telegramState.lastUpdateId = Math.max(0, Number(parsed.lastUpdateId || 0));
  } catch {
    // Ignore broken telegram config files.
  }
}

function persistTelegramConfigToDisk() {
  if (!PERSIST_TELEGRAM_CONFIG) {
    return;
  }

  const payload = {
    botToken: telegramRuntimeConfig.botToken,
    enabled: telegramRuntimeConfig.enabled,
    allowedChatIds: [...telegramRuntimeConfig.allowedChatIds],
    knownChats: telegramState.knownChats.map((x) => ({
      id: x.id,
      type: x.type,
      title: x.title,
      username: x.username,
      firstSeenAt: x.firstSeenAt,
      lastSeenAt: x.lastSeenAt
    })),
    lastUpdateId: telegramState.lastUpdateId
  };

  try {
    fs.writeFileSync(TELEGRAM_RUNTIME_CONFIG_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    try {
      fs.chmodSync(TELEGRAM_RUNTIME_CONFIG_PATH, 0o600);
    } catch {
      // Ignore chmod failures on limited filesystems.
    }
  } catch {
    // Persistence is best-effort and should not break API response flow.
  }
}

function maskTelegramToken(token) {
  const text = String(token || '').trim();
  if (!text) {
    return '';
  }
  if (text.length <= 10) {
    return '******';
  }
  return `${text.slice(0, 6)}...${text.slice(-4)}`;
}

function buildTelegramConfigResponse() {
  return {
    configured: Boolean(telegramRuntimeConfig.botToken),
    hasToken: Boolean(telegramRuntimeConfig.botToken),
    tokenPreview: maskTelegramToken(telegramRuntimeConfig.botToken),
    enabled: Boolean(telegramRuntimeConfig.enabled),
    polling: Boolean(telegramState.pollerRunning),
    allowedChatIds: [...telegramRuntimeConfig.allowedChatIds],
    knownChats: telegramState.knownChats.map(toClientTelegramChat),
    persisted: PERSIST_TELEGRAM_CONFIG,
    lastError: telegramState.lastError || ''
  };
}

function toClientTelegramChat(chat) {
  return {
    id: chat.id,
    type: chat.type,
    title: chat.title,
    username: chat.username,
    firstSeenAt: chat.firstSeenAt,
    lastSeenAt: chat.lastSeenAt,
    authorized: isTelegramChatAllowed(chat.id)
  };
}

function isTelegramChatAllowed(chatId) {
  const target = String(chatId || '').trim();
  if (!target) {
    return false;
  }
  return telegramRuntimeConfig.allowedChatIds.includes(target);
}

function upsertTelegramKnownChat(chat) {
  const chatId = String(chat && chat.id ? chat.id : '').trim();
  if (!chatId) {
    return;
  }

  const nowIso = new Date().toISOString();
  const type = String(chat && chat.type ? chat.type : '');
  const username = String(chat && chat.username ? chat.username : '');
  const title =
    String(chat && chat.title ? chat.title : '') ||
    [String(chat && chat.first_name ? chat.first_name : ''), String(chat && chat.last_name ? chat.last_name : '')].join(' ').trim() ||
    username ||
    chatId;

  const existing = telegramState.knownChats.find((x) => x && x.id === chatId);
  if (existing) {
    existing.type = type;
    existing.username = username;
    existing.title = title;
    existing.lastSeenAt = nowIso;
    return;
  }

  telegramState.knownChats.unshift({
    id: chatId,
    type,
    title,
    username,
    firstSeenAt: nowIso,
    lastSeenAt: nowIso
  });

  if (telegramState.knownChats.length > 500) {
    telegramState.knownChats.length = 500;
  }
}

function restartTelegramPoller() {
  telegramState.pollerVersion += 1;
  telegramState.pollerRunning = false;

  if (!telegramRuntimeConfig.enabled || !telegramRuntimeConfig.botToken) {
    telegramState.lastError = '';
    return;
  }

  const version = telegramState.pollerVersion;
  runTelegramPoller(version).catch(() => {
    // Polling loop handles retries internally.
  });
}

async function runTelegramPoller(version) {
  if (!telegramRuntimeConfig.enabled || !telegramRuntimeConfig.botToken) {
    return;
  }

  telegramState.pollerRunning = true;
  telegramState.lastError = '';

  while (
    version === telegramState.pollerVersion &&
    telegramRuntimeConfig.enabled &&
    telegramRuntimeConfig.botToken
  ) {
    try {
      const updates = await telegramApiRequest('getUpdates', {
        timeout: 25,
        offset: telegramState.lastUpdateId + 1,
        allowed_updates: ['message']
      });

      for (const update of updates) {
        if (update && Number.isFinite(Number(update.update_id))) {
          telegramState.lastUpdateId = Math.max(telegramState.lastUpdateId, Number(update.update_id));
        }
        await handleTelegramUpdate(update);
      }

      if (updates.length) {
        persistTelegramConfigToDisk();
      }
    } catch (err) {
      telegramState.lastError = err && err.message ? err.message : 'Telegram polling failed.';
      await sleep(3000);
    }
  }

  if (version === telegramState.pollerVersion) {
    telegramState.pollerRunning = false;
  }
}

async function handleTelegramUpdate(update) {
  const message = update && update.message ? update.message : null;
  if (!message || !message.chat) {
    return;
  }

  upsertTelegramKnownChat(message.chat);

  const chatId = String(message.chat.id || '').trim();
  if (!chatId) {
    return;
  }

  const text = String(message.text || '').trim();
  if (!text.startsWith('/')) {
    return;
  }

  const command = parseTelegramCommand(text);
  const actor = `telegram:${chatId}`;

  if (command.name === '/start' || command.name === '/chatid') {
    await sendTelegramMessage(chatId, `chatId: ${chatId}\n请在面板 Telegram 配置中加入允许列表后再执行控制命令。`);
    return;
  }

  if (!isTelegramChatAllowed(chatId)) {
    await sendTelegramMessage(chatId, `未授权。\n请在面板中将 chatId ${chatId} 添加到允许列表。`);
    recordAudit({
      action: 'telegram.command.denied',
      success: false,
      actor,
      ip: '',
      details: { chatId, command: command.name }
    });
    return;
  }

  try {
    const resultText = await executeTelegramCommand({ chatId, command });
    if (resultText) {
      await sendTelegramMessage(chatId, resultText);
    }
  } catch (err) {
    const messageText = err && err.message ? err.message : 'Unknown error.';
    await sendTelegramMessage(chatId, `执行失败: ${messageText}`);
    recordAudit({
      action: 'telegram.command.error',
      success: false,
      actor,
      ip: '',
      details: { chatId, command: command.name, message: messageText }
    });
  } finally {
    persistTelegramConfigToDisk();
  }
}

function parseTelegramCommand(text) {
  const parts = String(text || '').trim().split(/\s+/);
  const rawName = String(parts[0] || '').toLowerCase();
  const name = rawName.split('@')[0];
  return {
    name,
    args: parts.slice(1)
  };
}

async function executeTelegramCommand({ chatId, command }) {
  const actor = `telegram:${chatId}`;
  const args = command.args || [];

  if (command.name === '/help') {
    return [
      '可用命令:',
      '/chatid',
      '/subscriptions',
      '/vms <subscriptionId> [keyword]',
      '/startvm <subscriptionId> <resourceGroup> <name>',
      '/stopvm <subscriptionId> <resourceGroup> <name>',
      '/restartvm <subscriptionId> <resourceGroup> <name>',
      '/deallocatevm <subscriptionId> <resourceGroup> <name>',
      '/resizevm <subscriptionId> <resourceGroup> <name> <vmSize>',
      '/deletevm <subscriptionId> <resourceGroup> <name> confirm',
      '/status'
    ].join('\n');
  }

  if (command.name === '/status') {
    return [
      `Bot: ${telegramRuntimeConfig.enabled ? 'enabled' : 'disabled'}`,
      `Polling: ${telegramState.pollerRunning ? 'running' : 'stopped'}`,
      `Allowed Chats: ${telegramRuntimeConfig.allowedChatIds.length}`,
      `Azure Configured: ${hasRuntimeConfig() ? 'yes' : 'no'}`
    ].join('\n');
  }

  if (command.name === '/subscriptions') {
    const payload = await azureRequest({
      method: 'GET',
      url: 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    });
    const items = Array.isArray(payload.value) ? payload.value : [];
    if (!items.length) {
      return '未查询到订阅。';
    }

    const lines = ['订阅列表:'];
    for (const item of items.slice(0, 30)) {
      lines.push(`- ${item.displayName || '-'} | ${item.subscriptionId || '-'} | ${item.state || '-'}`);
    }
    if (items.length > 30) {
      lines.push(`...共 ${items.length} 条，仅展示前 30 条`);
    }
    return lines.join('\n');
  }

  if (command.name === '/vms') {
    const subscriptionId = required(args[0], 'subscriptionId');
    const keyword = String(args[1] || '').trim().toLowerCase();

    const list = await azureRequest({
      method: 'GET',
      url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01`
    });

    let vms = Array.isArray(list.value) ? list.value : [];
    if (keyword) {
      vms = vms.filter((x) => String(x && x.name ? x.name : '').toLowerCase().includes(keyword));
    }
    if (!vms.length) {
      return '未查询到虚拟机。';
    }

    const selected = vms.slice(0, 20);
    const enriched = await mapWithConcurrency(selected, 4, async (vm) => {
      const parts = parseResourceId(vm.id || '');
      const powerState = await resolveVmPowerState(subscriptionId, vm, parts);
      return {
        name: vm.name || '-',
        resourceGroup: parts.resourceGroup || '-',
        vmSize: readVmSize(vm) || '-',
        location: vm.location || '-',
        powerState
      };
    });

    const lines = ['虚拟机列表:'];
    for (const vm of enriched) {
      lines.push(`- ${vm.name} | ${vm.resourceGroup} | ${vm.location} | ${vm.vmSize} | ${vm.powerState}`);
    }
    if (vms.length > selected.length) {
      lines.push(`...共 ${vms.length} 台，仅展示前 ${selected.length} 台`);
    }
    return lines.join('\n');
  }

  if (
    command.name === '/startvm' ||
    command.name === '/stopvm' ||
    command.name === '/restartvm' ||
    command.name === '/deallocatevm' ||
    command.name === '/deletevm' ||
    command.name === '/resizevm'
  ) {
    const subscriptionId = required(args[0], 'subscriptionId');
    const resourceGroup = required(args[1], 'resourceGroup');
    const name = required(args[2], 'name');

    if (command.name === '/deletevm') {
      const confirm = String(args[3] || '').trim().toLowerCase();
      if (confirm !== 'confirm') {
        return '删除命令需要确认: /deletevm <subscriptionId> <resourceGroup> <name> confirm';
      }
    }

    let action = 'start';
    let vmSize = '';
    if (command.name === '/startvm') {
      action = 'start';
    } else if (command.name === '/stopvm') {
      action = 'powerOff';
    } else if (command.name === '/restartvm') {
      action = 'restart';
    } else if (command.name === '/deallocatevm') {
      action = 'deallocate';
    } else if (command.name === '/deletevm') {
      action = 'delete';
    } else if (command.name === '/resizevm') {
      action = 'resize';
      vmSize = required(args[3], 'vmSize');
    }

    const result = await executeTelegramVmAction({
      subscriptionId,
      resourceGroup,
      name,
      action,
      vmSize,
      actor
    });
    return result;
  }

  return `不支持的命令: ${command.name}。\n发送 /help 查看可用命令。`;
}

async function executeTelegramVmAction({ subscriptionId, resourceGroup, name, action, vmSize, actor }) {
  const baseUrl = `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(resourceGroup)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(name)}`;
  const vmUrl = `${baseUrl}?api-version=2024-03-01`;

  if (action === 'delete') {
    await azureLroRequest({
      method: 'DELETE',
      url: vmUrl
    });
    recordAudit({
      action: 'vm.delete.telegram',
      success: true,
      actor,
      ip: '',
      details: { subscriptionId, resourceGroup, name }
    });
    return `删除任务已提交: ${name}`;
  }

  if (action === 'resize') {
    const targetSize = required(vmSize, 'vmSize');
    await azureLroRequest({
      method: 'PATCH',
      url: vmUrl,
      body: {
        properties: {
          hardwareProfile: {
            vmSize: targetSize
          }
        }
      }
    });
    recordAudit({
      action: 'vm.resize.telegram',
      success: true,
      actor,
      ip: '',
      details: { subscriptionId, resourceGroup, name, vmSize: targetSize }
    });
    return `改规格任务已提交: ${name} -> ${targetSize}`;
  }

  await azureLroRequest({
    method: 'POST',
    url: `${baseUrl}/${action}?api-version=2024-03-01`,
    body: {}
  });
  recordAudit({
    action: `vm.${action}.telegram`,
    success: true,
    actor,
    ip: '',
    details: { subscriptionId, resourceGroup, name }
  });
  return `操作已提交: ${name} -> ${action}`;
}

async function telegramApiRequest(method, payload = {}) {
  const botToken = String(telegramRuntimeConfig.botToken || '').trim();
  if (!botToken) {
    throw new Error('Telegram bot token is not configured.');
  }

  const response = await fetchImpl(`https://api.telegram.org/bot${botToken}/${method}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload || {})
  });

  const text = await response.text();
  const json = safeJsonParse(text);
  if (!response.ok) {
    const message = json && json.description ? json.description : `Telegram API failed with status ${response.status}.`;
    throw new Error(message);
  }

  if (!json || json.ok !== true) {
    const message = json && json.description ? json.description : 'Telegram API returned non-ok.';
    throw new Error(message);
  }

  return json.result;
}

async function sendTelegramMessage(chatId, text) {
  const chunks = splitTelegramText(text, 3500);
  for (const chunk of chunks) {
    await telegramApiRequest('sendMessage', {
      chat_id: chatId,
      text: chunk
    });
  }
}

function splitTelegramText(text, limit) {
  const out = [];
  const source = String(text || '');
  if (!source) {
    return [''];
  }

  let current = '';
  for (const line of source.split('\n')) {
    const candidate = current ? `${current}\n${line}` : line;
    if (candidate.length <= limit) {
      current = candidate;
      continue;
    }

    if (current) {
      out.push(current);
      current = '';
    }

    if (line.length <= limit) {
      current = line;
      continue;
    }

    for (let i = 0; i < line.length; i += limit) {
      out.push(line.slice(i, i + limit));
    }
  }

  if (current) {
    out.push(current);
  }
  return out.length ? out : [''];
}

function mustQuery(url, key) {
  const value = (url.searchParams.get(key) || '').trim();
  if (!value) {
    const err = new Error(`${key} is required.`);
    err.statusCode = 400;
    throw err;
  }
  return value;
}

function required(value, name) {
  const out = String(value || '').trim();
  if (!out) {
    const err = new Error(`${name} is required.`);
    err.statusCode = 400;
    throw err;
  }
  return out;
}

async function readJsonBody(req) {
  const contentLength = Number(req.headers['content-length'] || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BODY_BYTES) {
    const err = new Error(`JSON body is too large. Max ${MAX_JSON_BODY_BYTES} bytes.`);
    err.statusCode = 413;
    throw err;
  }

  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > MAX_JSON_BODY_BYTES) {
      const err = new Error(`JSON body is too large. Max ${MAX_JSON_BODY_BYTES} bytes.`);
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }

  const text = Buffer.concat(chunks).toString('utf8').trim();
  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    const err = new Error('Invalid JSON body.');
    err.statusCode = 400;
    throw err;
  }
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(JSON.stringify(payload));
}

function isPublicApi(pathname) {
  return pathname === '/api/health' ||
    pathname === '/api/auth/login' ||
    pathname === '/api/auth/logout' ||
    pathname === '/api/auth/me';
}

function getClientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').trim();
  if (fwd) {
    return fwd.split(',')[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || '';
}

function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  const out = {};
  for (const part of raw.split(';')) {
    const item = part.trim();
    if (!item) {
      continue;
    }
    const idx = item.indexOf('=');
    if (idx < 0) {
      continue;
    }
    const key = item.slice(0, idx).trim();
    const value = item.slice(idx + 1).trim();
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

function getSessionIdFromCookie(req) {
  const cookies = parseCookies(req);
  return cookies.sessionId || '';
}

function getSession(req) {
  const sessionId = getSessionIdFromCookie(req);
  if (!sessionId) {
    return null;
  }

  const session = sessions.get(sessionId);
  if (!session) {
    return null;
  }

  if (session.expiresAtMs <= Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  session.expiresAtMs = Date.now() + SESSION_TTL_MS;
  return session;
}

function createSession(username) {
  const sessionId = crypto.randomBytes(24).toString('hex');
  sessions.set(sessionId, {
    username,
    expiresAtMs: Date.now() + SESSION_TTL_MS
  });
  return sessionId;
}

function serializeSessionCookie(sessionId) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  return `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function serializeExpiredSessionCookie() {
  return 'sessionId=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0';
}

function pruneExpiredSessions() {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (session.expiresAtMs <= now) {
      sessions.delete(sessionId);
    }
  }
}

function loadAuditEntries() {
  if (!fs.existsSync(AUDIT_LOG_PATH)) {
    return;
  }

  try {
    const content = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
    const lines = content.split(/\r?\n/).filter(Boolean);
    const parsed = [];
    for (const line of lines) {
      try {
        const item = JSON.parse(line);
        if (item && typeof item === 'object') {
          parsed.push(item);
        }
      } catch {
        // Ignore malformed historical lines.
      }
    }
    for (const item of parsed.slice(-MAX_AUDIT_ENTRIES).reverse()) {
      auditEntries.push(item);
    }
  } catch {
    // Ignore audit preload errors.
  }
}

function recordAudit({ action, success, actor, ip, details }) {
  const entry = {
    id: createAuditId(),
    time: new Date().toISOString(),
    action: String(action || 'unknown'),
    success: Boolean(success),
    actor: String(actor || 'unknown'),
    ip: String(ip || ''),
    details: details || null
  };

  auditEntries.unshift(entry);
  if (auditEntries.length > MAX_AUDIT_ENTRIES) {
    auditEntries.pop();
  }

  fs.appendFile(AUDIT_LOG_PATH, `${JSON.stringify(entry)}\n`, () => {});
}

function createAuditId() {
  return createEntityId();
}

function createEntityId() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return crypto.randomBytes(16).toString('hex');
}

function readVmSize(vmInfo) {
  if (!vmInfo || !vmInfo.properties || !vmInfo.properties.hardwareProfile) {
    return '';
  }
  return String(vmInfo.properties.hardwareProfile.vmSize || '').trim();
}

async function resolveVmPowerState(subscriptionId, vm, parts) {
  const cacheKey = buildVmPowerStateCacheKey(subscriptionId, vm);
  const cached = getCachedVmPowerState(cacheKey);
  if (cached) {
    return cached;
  }

  if (!parts.resourceGroup || !parts.name) {
    return 'unknown';
  }

  try {
    const iv = await azureRequest({
      method: 'GET',
      url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(parts.resourceGroup)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(parts.name)}/instanceView?api-version=2024-03-01`
    });

    const status = (iv.statuses || []).find((s) => (s.code || '').startsWith('PowerState/'));
    const powerState = status && status.code ? status.code.replace('PowerState/', '') : 'unknown';
    setCachedVmPowerState(cacheKey, powerState);
    return powerState;
  } catch {
    return 'unknown';
  }
}

function buildVmPowerStateCacheKey(subscriptionId, vm) {
  const vmId = String(vm && vm.id ? vm.id : '').trim().toLowerCase();
  if (!subscriptionId || !vmId) {
    return '';
  }
  return `${String(subscriptionId).trim().toLowerCase()}::${vmId}`;
}

function getCachedVmPowerState(cacheKey) {
  if (!POWER_STATE_CACHE_TTL_MS || !cacheKey) {
    return '';
  }

  const item = vmPowerStateCache.get(cacheKey);
  if (!item) {
    return '';
  }

  if (item.expiresAtMs <= Date.now()) {
    vmPowerStateCache.delete(cacheKey);
    return '';
  }

  return item.value;
}

function setCachedVmPowerState(cacheKey, powerState) {
  if (!POWER_STATE_CACHE_TTL_MS || !cacheKey || !powerState) {
    return;
  }

  vmPowerStateCache.set(cacheKey, {
    value: String(powerState),
    expiresAtMs: Date.now() + POWER_STATE_CACHE_TTL_MS
  });
}

function pruneVmPowerStateCache() {
  if (!vmPowerStateCache.size) {
    return;
  }

  const now = Date.now();
  for (const [key, item] of vmPowerStateCache.entries()) {
    if (!item || item.expiresAtMs <= now) {
      vmPowerStateCache.delete(key);
    }
  }
}

async function getVmSizes(subscriptionId, location) {
  const normalizedLocation = String(location || '').toLowerCase();
  let legacyError = null;

  try {
    const payload = await azureRequest({
      method: 'GET',
      url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/locations/${encodeURIComponent(location)}/vmSizes?api-version=2021-07-01`
    });

    const legacySizes = normalizeLegacyVmSizes(payload.value || []);
    if (legacySizes.length) {
      return { sizes: legacySizes, source: 'vmSizes' };
    }
  } catch (err) {
    legacyError = err;
  }

  try {
    const skus = await azureListAll(
      `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/skus?api-version=2024-03-01`
    );
    const skuSizes = normalizeSkuVmSizes(skus, normalizedLocation);
    if (skuSizes.length) {
      return { sizes: skuSizes, source: 'skus' };
    }

    const discoveredSizes = await discoverVmSizesFromExistingVms(subscriptionId, normalizedLocation);
    if (discoveredSizes.length) {
      return { sizes: discoveredSizes, source: 'existing-vms' };
    }

    return { sizes: [], source: 'skus-empty' };
  } catch (skuError) {
    if (legacyError) {
      const err = new Error(`Failed to load VM sizes from both endpoints. legacy=${legacyError.message}; skus=${skuError.message}`);
      err.statusCode = Number(skuError.statusCode || legacyError.statusCode || 500);
      err.details = {
        legacy: legacyError.details || legacyError.message,
        skus: skuError.details || skuError.message
      };
      throw err;
    }
    throw skuError;
  }
}

function normalizeLegacyVmSizes(items) {
  const out = [];
  for (const item of items) {
    const name = String(item && item.name ? item.name : '').trim();
    if (!name) {
      continue;
    }
    out.push({
      name,
      numberOfCores: toNumber(item.numberOfCores),
      memoryInMB: toNumber(item.memoryInMB),
      maxDataDiskCount: toNumber(item.maxDataDiskCount)
    });
  }
  return sortVmSizes(dedupeVmSizes(out));
}

function normalizeSkuVmSizes(items, normalizedLocation) {
  const out = [];

  for (const sku of items) {
    const resourceType = String(sku && sku.resourceType ? sku.resourceType : '').toLowerCase();
    if (resourceType !== 'virtualmachines') {
      continue;
    }

    const skuName = String(sku && sku.name ? sku.name : '').trim();
    if (!skuName) {
      continue;
    }

    if (!isSkuInLocation(sku, normalizedLocation)) {
      continue;
    }

    if (isSkuRestrictedForSubscription(sku, normalizedLocation)) {
      continue;
    }

    const capabilities = Array.isArray(sku.capabilities) ? sku.capabilities : [];
    const cores = capabilityNumber(capabilities, 'vCPUs');
    const memoryGB = capabilityNumber(capabilities, 'MemoryGB');
    const maxDataDiskCount = capabilityNumber(capabilities, 'MaxDataDiskCount');

    out.push({
      name: skuName,
      numberOfCores: cores,
      memoryInMB: memoryGB > 0 ? Math.round(memoryGB * 1024) : 0,
      maxDataDiskCount
    });
  }

  return sortVmSizes(dedupeVmSizes(out));
}

function isSkuInLocation(sku, normalizedLocation) {
  if (!normalizedLocation) {
    return true;
  }

  const locations = Array.isArray(sku.locations) ? sku.locations : [];
  for (const loc of locations) {
    if (String(loc || '').toLowerCase() === normalizedLocation) {
      return true;
    }
  }

  const locationInfo = Array.isArray(sku.locationInfo) ? sku.locationInfo : [];
  for (const item of locationInfo) {
    const loc = String(item && item.location ? item.location : '').toLowerCase();
    if (loc === normalizedLocation) {
      return true;
    }
  }
  return false;
}

function isSkuRestrictedForSubscription(sku, normalizedLocation) {
  const restrictions = Array.isArray(sku.restrictions) ? sku.restrictions : [];
  for (const restriction of restrictions) {
    const reasonCode = String(restriction && restriction.reasonCode ? restriction.reasonCode : '').toLowerCase();
    const type = String(restriction && restriction.type ? restriction.type : '').toLowerCase();
    const values = Array.isArray(restriction && restriction.values) ? restriction.values : [];

    if (reasonCode !== 'notavailableforsubscription') {
      continue;
    }

    if (type !== 'location' && type !== 'locations') {
      continue;
    }

    if (!values.length) {
      return true;
    }

    for (const value of values) {
      if (String(value || '').toLowerCase() === normalizedLocation) {
        return true;
      }
    }
  }
  return false;
}

async function discoverVmSizesFromExistingVms(subscriptionId, normalizedLocation) {
  const payload = await azureRequest({
    method: 'GET',
    url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01`
  });

  const map = {};
  const items = Array.isArray(payload.value) ? payload.value : [];
  for (const vm of items) {
    const vmLocation = String(vm && vm.location ? vm.location : '').toLowerCase();
    if (normalizedLocation && vmLocation !== normalizedLocation) {
      continue;
    }

    const vmSize = readVmSize(vm);
    if (!vmSize) {
      continue;
    }

    map[vmSize] = {
      name: vmSize,
      numberOfCores: 0,
      memoryInMB: 0,
      maxDataDiskCount: 0
    };
  }

  return sortVmSizes(Object.keys(map).map((key) => map[key]));
}

function capabilityNumber(capabilities, capabilityName) {
  const target = String(capabilityName || '').toLowerCase();
  for (const capability of capabilities) {
    const name = String(capability && capability.name ? capability.name : '').toLowerCase();
    if (name !== target) {
      continue;
    }
    return toNumber(capability.value);
  }
  return 0;
}

function dedupeVmSizes(items) {
  const map = {};
  for (const item of items) {
    map[item.name] = item;
  }
  return Object.keys(map).map((key) => map[key]);
}

function sortVmSizes(items) {
  return items.sort((a, b) => {
    const ac = toNumber(a.numberOfCores);
    const bc = toNumber(b.numberOfCores);
    if (ac !== bc) {
      return ac - bc;
    }

    const am = toNumber(a.memoryInMB);
    const bm = toNumber(b.memoryInMB);
    if (am !== bm) {
      return am - bm;
    }

    return String(a.name).localeCompare(String(b.name));
  });
}

function toNumber(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return 0;
  }
  return num;
}

async function azureListAll(initialUrl) {
  let nextUrl = initialUrl;
  const all = [];
  let guard = 0;

  while (nextUrl && guard < 40) {
    guard += 1;
    const page = await azureRequest({
      method: 'GET',
      url: nextUrl
    });
    const values = Array.isArray(page.value) ? page.value : [];
    for (const item of values) {
      all.push(item);
    }

    nextUrl = page.nextLink || '';
  }

  return all;
}

function createCompatFetch() {
  return function compatFetch(url, options = {}) {
    return new Promise((resolve, reject) => {
      let parsedUrl;
      try {
        parsedUrl = new URL(url);
      } catch (err) {
        reject(err);
        return;
      }

      const isHttps = parsedUrl.protocol === 'https:';
      const client = isHttps ? https : http;
      const method = options.method || 'GET';
      const headers = options.headers || {};

      const req = client.request(
        parsedUrl,
        {
          method,
          headers
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const bodyBuffer = Buffer.concat(chunks);
            const bodyText = bodyBuffer.toString('utf8');
            const headerMap = {};

            for (const key in res.headers) {
              if (!Object.prototype.hasOwnProperty.call(res.headers, key)) {
                continue;
              }
              const value = res.headers[key];
              headerMap[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value || '');
            }

            resolve({
              status: Number(res.statusCode || 0),
              ok: Number(res.statusCode || 0) >= 200 && Number(res.statusCode || 0) < 300,
              headers: {
                get(name) {
                  return headerMap[String(name || '').toLowerCase()] || null;
                }
              },
              text: async () => bodyText
            });
          });
        }
      );

      req.on('error', reject);

      if (options.body !== undefined && options.body !== null) {
        req.write(options.body);
      }
      req.end();
    });
  };
}

async function azureRequest({ method, url, body, headers = {}, retry401 = true }) {
  const token = await getAccessToken();

  const response = await fetchImpl(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...headers
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (response.status === 401 && retry401) {
    tokenCache = { value: '', expiresAtMs: 0 };
    return azureRequest({ method, url, body, headers, retry401: false });
  }

  const text = await response.text();
  const json = safeJsonParse(text);

  if (!response.ok) {
    const err = new Error(
      (json && json.error && json.error.message) ||
      (json && json.message) ||
      `Azure API failed with status ${response.status}.`
    );
    err.statusCode = response.status;
    err.details = json || text;
    throw err;
  }

  return {
    ...(json && typeof json === 'object' ? json : {}),
    _headers: response.headers,
    _status: response.status,
    _raw: text
  };
}

async function azureLroRequest({ method, url, body }) {
  const token = await getAccessToken();

  let response = await fetchImpl(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (response.status === 401) {
    tokenCache = { value: '', expiresAtMs: 0 };
    const retryToken = await getAccessToken();
    response = await fetchImpl(url, {
      method,
      headers: {
        Authorization: `Bearer ${retryToken}`,
        'Content-Type': 'application/json'
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  }

  const initialText = await response.text();
  const initialJson = safeJsonParse(initialText);

  if (!response.ok && response.status !== 202 && response.status !== 201) {
    const err = new Error(
      (initialJson && initialJson.error && initialJson.error.message) ||
      (initialJson && initialJson.message) ||
      `Azure API failed with status ${response.status}.`
    );
    err.statusCode = response.status;
    err.details = initialJson || initialText;
    throw err;
  }

  const asyncUrl =
    response.headers.get('azure-asyncoperation') ||
    response.headers.get('operation-location') ||
    response.headers.get('location');

  if (!asyncUrl) {
    return initialJson || { status: response.status };
  }

  const deadline = Date.now() + 20 * 60 * 1000;

  while (Date.now() < deadline) {
    const retryAfterSec = Number(response.headers.get('retry-after') || 3);
    await sleep(Math.min(Math.max(retryAfterSec, 1), 15) * 1000);

    const poll = await azureRequest({ method: 'GET', url: asyncUrl });
    const pollProvisioningState = poll && poll.properties ? poll.properties.provisioningState : '';
    const status = String(poll.status || pollProvisioningState || '').toLowerCase();

    if (!status && (poll._status === 200 || poll._status === 204)) {
      return initialJson || poll;
    }

    if (status === 'succeeded' || status === 'success') {
      if (initialJson && initialJson.id) {
        const resourceUrl = initialJson.id.startsWith('http')
          ? initialJson.id
          : `https://management.azure.com${initialJson.id}`;
        const latest = await azureRequest({ method: 'GET', url: `${resourceUrl}?api-version=2024-03-01` });
        return latest;
      }
      return poll;
    }

    if (status === 'failed' || status === 'canceled' || status === 'cancelled') {
      const pollErrorMessage = poll && poll.error ? poll.error.message : '';
      const err = new Error(`Azure long-running operation failed: ${pollErrorMessage || status}`);
      err.statusCode = 500;
      err.details = poll;
      throw err;
    }
  }

  const err = new Error('Azure long-running operation timeout.');
  err.statusCode = 504;
  throw err;
}

async function getAccessToken() {
  const now = Date.now();
  if (tokenCache.value && tokenCache.expiresAtMs - 30_000 > now) {
    return tokenCache.value;
  }

  const tenantId = runtimeConfig.tenantId;
  const clientId = runtimeConfig.clientId;
  const clientSecret = runtimeConfig.clientSecret;

  if (!tenantId || !clientId || !clientSecret) {
    const err = new Error('Azure credentials are not configured. Set AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET or POST /api/config.');
    err.statusCode = 400;
    throw err;
  }

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'client_credentials',
    scope: 'https://management.azure.com/.default'
  });

  const response = await fetchImpl(`https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: body.toString()
  });

  const text = await response.text();
  const json = safeJsonParse(text);

  if (!response.ok) {
    const err = new Error((json && json.error_description) || 'Failed to get Azure AD token.');
    err.statusCode = response.status;
    err.details = json || text;
    throw err;
  }

  tokenCache = {
    value: json.access_token,
    expiresAtMs: Date.now() + Number(json.expires_in || 300) * 1000
  };

  return tokenCache.value;
}

function safeJsonParse(text) {
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseResourceId(id) {
  const out = { resourceGroup: '', name: '' };
  if (!id) {
    return out;
  }

  const rgMatch = id.match(/\/resourceGroups\/([^/]+)/i);
  const nameMatch = id.match(/\/virtualMachines\/([^/]+)/i);
  if (rgMatch) {
    out.resourceGroup = rgMatch[1];
  }
  if (nameMatch) {
    out.name = nameMatch[1];
  }
  return out;
}

function randomSuffix() {
  return Math.random().toString(36).slice(2, 8);
}

function sanitizeName(value) {
  const name = String(value || '').trim().toLowerCase();
  return name.replace(/[^a-z0-9-]/g, '').slice(0, 64);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function serveStatic(pathname, res) {
  let filePath = pathname === '/' ? 'index.html' : pathname;
  if (filePath.startsWith('/')) {
    filePath = filePath.slice(1);
  }

  const normalizedPath = path.normalize(filePath);
  const fullPath = path.join(PUBLIC_DIR, normalizedPath);
  const relativePath = path.relative(PUBLIC_DIR, fullPath);

  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    const ext = path.extname(fullPath).toLowerCase();
    const contentType =
      ext === '.html' ? 'text/html; charset=utf-8' :
      ext === '.css' ? 'text/css; charset=utf-8' :
      ext === '.js' ? 'application/javascript; charset=utf-8' :
      'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}
