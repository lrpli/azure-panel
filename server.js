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
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || path.join(__dirname, 'audit.log');
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

const sessions = new Map();
const auditEntries = [];
const MAX_AUDIT_ENTRIES = 1000;

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

loadAuditEntries();

const server = http.createServer(async (req, res) => {
  let url = null;
  let actor = 'anonymous';
  let ip = '';
  try {
    pruneExpiredSessions();
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
        configured: Boolean(runtimeConfig.tenantId && runtimeConfig.clientId && runtimeConfig.clientSecret)
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
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/api/images') {
      return sendJson(res, 200, { images: IMAGE_OPTIONS });
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
        let powerState = 'unknown';

        if (parts.resourceGroup && parts.name) {
          try {
            const iv = await azureRequest({
              method: 'GET',
              url: `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/resourceGroups/${encodeURIComponent(parts.resourceGroup)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(parts.name)}/instanceView?api-version=2024-03-01`
            });

            const status = (iv.statuses || []).find((s) => (s.code || '').startsWith('PowerState/'));
            if (status && status.code) {
              powerState = status.code.replace('PowerState/', '');
            }
          } catch (e) {
            powerState = 'unknown';
          }
        }

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
      const sshPublicKey = String(body.sshPublicKey || '');

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
        details: { subscriptionId, resourceGroup, name, location, vmSize, imageId, networkMode }
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
  const chunks = [];
  for await (const chunk of req) {
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
  res.end(JSON.stringify(payload, null, 2));
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
    out[key] = decodeURIComponent(value);
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
      `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/skus?$filter=location eq '${encodeURIComponent(location)}'&api-version=2024-03-01`
    );
    const skuSizes = normalizeSkuVmSizes(skus, normalizedLocation);
    return { sizes: skuSizes, source: 'skus' };
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

    if (type !== 'location') {
      return true;
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
