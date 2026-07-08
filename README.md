# Azure VM Control Panel

一个基于 Azure Management REST API 的轻量可视化面板，支持：

- 登录鉴权（Cookie Session）
- 审计日志（登录、鉴权失败、配置修改、VM 操作）
- 虚拟机列表查询
- 虚拟机创建（可选地区、规格、镜像、认证方式）
- SSH Keychain 管理（创建时可直接选择已保存公钥）
- Telegram Bot 控制（通过命令查询并执行 VM 操作）
- 虚拟机操作（开机、关机、重启、释放、删除）
- 自动创建网络资源（VNet/Subnet/Public IP/NIC）或使用现有 NIC

## 功能截图说明

- 登录后才能访问所有 `/api/*` 受保护接口
- 审计区可查看最近操作记录
- 创建 VM 时可以选择：
1. 订阅
2. 地区（Region）
3. 规格（VM Size）
4. 镜像（Ubuntu / Windows）

## 环境要求

- Node.js 18+
- 可访问 Azure Management API 的网络环境
- Azure Service Principal（服务主体）并具备目标订阅权限

建议最小角色（按资源范围授予）：

- `Virtual Machine Contributor`
- `Network Contributor`
- `Resource Group Contributor`（或更高）

## 快速开始

```bash
cp .env.example .env
# 修改管理后台登录账号密码（务必）
# PANEL_ADMIN_USERNAME=...
# PANEL_ADMIN_PASSWORD=...

npm start
```

默认启动地址：

- `http://127.0.0.1:18080`

## 配置说明

`.env.example` 关键变量：

- `PANEL_ADMIN_USERNAME`：面板登录用户名
- `PANEL_ADMIN_PASSWORD`：面板登录密码
- `SESSION_TTL_HOURS`：会话过期时间（小时）
- `AZURE_TENANT_ID`：Azure AD Tenant ID
- `AZURE_CLIENT_ID`：Service Principal Client ID
- `AZURE_CLIENT_SECRET`：Service Principal Secret
- `PERSIST_AZURE_CONFIG`：是否将 Azure 凭据写入本地文件（默认 `true`）
- `AZURE_RUNTIME_CONFIG_PATH`：本地凭据文件路径（默认 `./.azure-runtime-config.json`）
- `PERSIST_KEYCHAIN`：是否将 SSH Keychain 写入本地文件（默认 `true`）
- `KEYCHAIN_PATH`：本地 Keychain 文件路径（默认 `./.keychain.json`）
- `PERSIST_TELEGRAM_CONFIG`：是否将 Telegram 配置写入本地文件（默认 `true`）
- `TELEGRAM_RUNTIME_CONFIG_PATH`：本地 Telegram 配置文件路径（默认 `./.telegram-runtime-config.json`）
- `TELEGRAM_BOT_TOKEN`：Telegram Bot Token（可在 Web 面板设置）
- `TELEGRAM_ENABLED`：是否启用 Telegram 控制（默认 `false`）
- `TELEGRAM_ALLOWED_CHAT_IDS`：允许控制的 chat id（逗号分隔）
- `AUDIT_LOG_PATH`：审计日志文件（默认 `./audit.log`）
- `MAX_JSON_BODY_BYTES`：单个 JSON 请求体大小上限（默认 `1048576`）
- `POWER_STATE_CACHE_TTL_MS`：VM 电源状态短缓存 TTL 毫秒数（默认 `15000`）
- `HOST` / `PORT`：服务监听地址和端口

## 使用流程

1. 打开页面并登录。
2. 在“Azure 凭据”填入 Tenant/Client/Secret（若已在 `.env` 配置可跳过）。
3. 加载订阅、地区、规格。
4. 可在 Keychain 管理区维护 SSH 公钥，创建 VM 时直接选择使用。
5. 可在 Telegram 控制区保存 Bot Token、开启控制并可视化授权 chat id。
6. 创建 VM 或在列表中执行开关机/重启/删除操作。
7. 在审计日志查看动作与结果。

说明：如果你在页面里提交过 Azure 凭据，默认会持久化到本地文件，服务重启后无需重复输入。

## 审计日志

审计默认写入 JSON Lines 文件：`audit.log`。  
每条记录包含：

- `id`
- `time`
- `action`（如 `auth.login`、`vm.create`）
- `success`
- `actor`
- `ip`
- `details`

页面内可调用 `/api/audit?limit=120` 查看最近记录。

## 主要 API

公开接口：

- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

登录后接口：

- `GET /api/config`
- `POST /api/config`
- `GET /api/images`
- `GET /api/keychain`
- `POST /api/keychain`
- `DELETE /api/keychain`
- `GET /api/telegram/config`
- `POST /api/telegram/config`
- `GET /api/telegram/chats`
- `GET /api/subscriptions`
- `GET /api/locations?subscriptionId=...`
- `GET /api/vm-sizes?subscriptionId=...&location=...`
- `GET /api/vms?subscriptionId=...`
- `POST /api/vm/create`（SSH 模式支持传 `keychainId` 直接使用已保存公钥）
- `POST /api/vm/action`
- `GET /api/audit?limit=...`

## 安全建议（生产必读）

- 不要使用默认管理员账号密码。
- 仅在内网或受控入口暴露服务。
- 前置反向代理并启用 HTTPS。
- 使用最小权限的 Azure 服务主体。
- 将 `PANEL_ADMIN_PASSWORD` 和 Azure 密钥放入密钥管理系统（如 Key Vault）。
- 审计日志可转存到集中日志系统（ELK / Loki / SIEM）。

## 已知限制

- 当前为单管理员账号模型（非多用户 RBAC）。
- 审计日志为本地文件，不含防篡改签名。
- 大规模订阅下，VM 列表查询速度受 Azure API 限制影响。
