# KingMoat WAF REST API 参考

控制台 API（WebUI 与 `/api/*` 同源），由 all-in-one 模式（`kingmoatwaf -console-addr`）提供。

> 本文列核心端点；完整端点清单以控制台 `/openapi.json` 为准。

- Base URL：`http://<console-host>:<console-port>`（端口由 `-console-addr` 指定，一键部署默认 `8443`）
- 数据格式：请求/响应均为 JSON（UTF-8）
- 错误格式：`{"error": "<message>"}`，配合标准 HTTP 状态码

## 认证

未设置环境变量 `KINGMOAT_ADMIN_HASH`（argon2id 哈希，`kmwafctl hash-password` 生成，支持 `-stdin`）时，控制台认证**自动武装**：首次启动生成随机会话密钥并强制启用登录，使用内置引导账号 `kmadmin / KingMoat@2026`，首次登录强制改密。预设该变量用于把管理凭据锚定为自选强口令，跳过默认凭据窗口期（控制台绑定非回环地址前务必预设）。

两步验证：

- **全局（兼容）**：设置 `KINGMOAT_ADMIN_TOTP`（base32 密钥）后，所有账号登录必须携带 6 位动态码；
- **逐用户（推荐）**：管理员在「用户管理」为单个账号启用 TOTP（扫码 + 动态码确认），仅该账号登录需要动态码；账号自身 MFA 优先于全局密钥。

四种凭证方式：

| 方式 | 用法 | 适用 |
|---|---|---|
| Session Cookie | `POST /api/login` 获取 `km_session` Cookie（12h 有效，TLS 下带 Secure 标志） | Web 控制台 / 浏览器 |
| HTTP Basic | `Authorization: Basic base64(<user>:<password>)` | 脚本 / CI |
| API Key（Bearer） | `Authorization: Bearer kma1_<id>_<secret>`，继承所属账号角色，可在用户管理页生成/撤销 | 脚本 / Prometheus 采集 |

登出（吊销全部已签发会话并清 Cookie）：`POST /api/logout`。

> 开启逐用户或全局 TOTP 的账号经 HTTP Basic 访问会被拒绝（Basic 无动态码通道，失败计入防爆破锁定）；API Key（Bearer）是独立凭证，不受 MFA 影响。

未认证访问返回 `401`。`/metrics` 挂在控制台端口，与其他 API 一样受控制台认证保护；`metrics.enabled` 默认 `false`，关闭时该端点返回 404。

```bash
# 登录
curl -c cookies.txt -X POST http://127.0.0.1:8081/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<pw>","totp":"123456"}'

# 之后带 Cookie 调用
curl -b cookies.txt http://127.0.0.1:8081/api/status

# 或直接 Basic
curl -u admin:<pw> http://127.0.0.1:8081/api/status

# 或使用用户管理页签发的 API Key（继承账号角色）
curl -H 'Authorization: Bearer kma1_1a2b3c4d_xxxxxxxxxxxx' http://127.0.0.1:8081/api/status
```

## 端点总览

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 免 | 登录（password [+ totp]） |
| POST | `/api/logout` | 免 | 登出并吊销会话 |
| GET | `/api/status` | 是 | 版本 / revision / 站点数 / 时间 |
| GET | `/api/config` | 是 | 当前生效配置与 revision |
| POST | `/api/config/publish` | 是 | 发布新配置（校验通过即热生效） |
| GET | `/api/revisions` | 是 | 配置版本历史 |
| POST | `/api/revisions/{id}/rollback` | 是 | 回滚到指定 revision（生成新 revision） |
| GET | `/api/logs?limit=N` | 是 | 最近攻击/挑战/重定向事件（内存环，默认 100，上限 1000） |
| GET | `/api/stats` | 是 | 今日拦截/挑战/观察计数 |
| GET | `/api/certificates` | 是 | TLS 证书清单（来源/主体/到期时间） |
| GET | `/api/users` | admin | 控制台用户列表（RBAC，含 MFA/API Key 状态） |
| POST | `/api/users` | admin | 新增用户（username/password/role） |
| PATCH | `/api/users/{username}` | admin | 改角色/密码/禁用（最后一个启用管理员受保护） |
| DELETE | `/api/users/{username}` | admin | 删除用户 |
| POST | `/api/users/{username}/apikey` | admin | 生成（或轮换）API Key，明文仅返回一次 |
| DELETE | `/api/users/{username}/apikey` | admin | 撤销 API Key |
| POST | `/api/users/{username}/mfa/setup` | admin | 发起 TOTP 注册（返回密钥/otpauth URL/二维码） |
| POST | `/api/users/{username}/mfa/confirm` | admin | 动态码确认，激活该账号 MFA |
| DELETE | `/api/users/{username}/mfa` | admin | 关闭该账号 MFA |
| GET | `/api/me` | 是 | 当前账号身份与凭据状态（username/role/api_key_id/totp_enabled） |
| POST | `/api/me/apikey` | 是 | 自助签发（或轮换）自己的 API Key |
| DELETE | `/api/me/apikey` | 是 | 自助撤销自己的 API Key |
| POST | `/api/me/mfa/setup` | 是 | 自助发起自己的 MFA 注册（扫码+确认） |
| POST | `/api/me/mfa/confirm` | 是 | 自助确认激活自己的 MFA |
| DELETE | `/api/me/mfa` | 是 | 自助关闭自己的 MFA |
| GET | `/api/audit/changes?limit=N` | 是 | 控制台管理操作变更审计（谁/何时/做了什么，最多 500） |
| GET | `/api/policy/exceptions` | 是 | 误报加白例外列表 |
| POST | `/api/policy/exceptions` | operator | 新增加白例外（site/path/prefix/rule_id/comment），发布热生效 |
| DELETE | `/api/policy/exceptions/{index}` | operator | 撤销加白例外（发布热生效） |
| GET | `/api/policy/disable-state` | 是 | 当前各站点被禁用的检测模块/CRS 分类快照（微引擎 disable 规则命中后的实时状态，发布重置） |
| GET | `/api/ipgroups` | 是 | IP 组订阅列表（条目数/预览/最后错误） |
| POST | `/api/ipgroups/{name}/refresh` | operator | 手动刷新订阅组 |
| GET | `/metrics` | 是 | Prometheus 指标（挂在控制台端口、受控制台认证保护；`metrics.enabled` 默认关闭，关闭时 404） |
| GET | `/api/upgrade/status` | admin | 在线升级状态：当前版本 + 最新版本（60s 缓存，`?refresh=1` 跳过）+ 进行中任务 + 历史 |
| POST | `/api/upgrade/check` | admin | 强制版本检查（绕过缓存并以新结果回填） |
| POST | `/api/upgrade/start` | admin | 启动升级任务（空 `target_version` = 最新；409 任务进行中 / 429 失败冷却） |
| GET | `/api/upgrade/task?id=` | admin | 查询单个升级任务（404 未知 id） |

## 角色权限矩阵（RBAC）

| 操作 | admin | operator | auditor |
|---|---|---|---|
| 仪表盘/日志/资产/风险/证书查看 | ✓ | ✓ | ✓ |
| 配置发布 / 回滚 | ✓ | ✓ | ✗ |
| 风险扫描 / 状态处置 / 资产忽略 / AI 报告 | ✓ | ✓ | ✗ |
| 用户管理 | ✓ | ✗ | ✗ |

未认证访问返回 `401`；角色不足返回 `403`（`insufficient role`）。

---

## 在线升级（admin）

控制台在线升级（系统设置 → 版本与升级）提供 4 个端点，均要求 admin 角色，由升级管道服务支撑。

### GET /api/upgrade/status

设置页快照：

```json
{
  "version": "v0.7.8-beta",
  "latest": {"version": "v0.7.9-beta", "update_available": true, "notes": "...", "assets_url": "..."},
  "running_task": null,
  "history": []
}
```

- `version`：当前运行版本；`latest`：最近一次成功检查的结果（`null` 表示尚无成功检查），API 层 60s TTL 缓存，检查失败不缓存（下次调用自动重试）；`?refresh=1` 跳过缓存强制在线检查；
- `running_task`：进行中的升级任务（空闲为 `null`）；`history`：历史任务。

### POST /api/upgrade/check

强制版本检查（绕过缓存并以新结果回填）。

- `200`：`{"version":"v0.7.9-beta","update_available":true,"notes":"...","assets_url":"..."}`
- `400`：当前版本号不可用（部署问题）
- `502`：版本源不可达/检查失败

### POST /api/upgrade/start

启动升级任务。请求体 `{"target_version": ""}`（空 = 最新版本；空 body 亦可）。同一时刻仅允许一个任务。

- `200`：`{"task_id": "..."}`
- `409`：`{"error":"已有升级任务进行中","task":{...}}`（附进行中的任务，客户端可直接转为轮询该任务）
- `429`：上一次失败后的冷却窗口内拒绝重试
- `400`：目标版本非法或不在发布列表中

### GET /api/upgrade/task?id=

轮询单个任务（缺 `id` 返回 400，未知 `id` 返回 404），响应为任务对象。

任务状态机：`detecting → downloading → verifying → replacing → restarting → success`，任一阶段失败即 `failed` 并进入冷却窗口；任务级 `success` 表示「服务重启已提交」，升级完成后服务自动重启，升级前自动在安装目录留滚动备份（见 [deploy/README.md](../deploy/README.md) 6.3）。

### 模块未接线（501）

当前部署形态不支持在线升级（static 模式或构建时未含该模块）时，以上端点统一返回 `501` 并附原因，而非易误导的 404/500。

---

## POST /api/login

```json
{"username": "admin", "password": "<密码>", "totp": "123456"}
```

- `username`：缺省时视为 `admin`。
- `totp`：账号启用了逐用户 MFA，或部署设置了全局 `KINGMOAT_ADMIN_TOTP` 时必填。
- `200`：`{"ok":true,"role":"admin","username":"admin","totp":false}` + `Set-Cookie: km_session=...`
- `401`：`{"error":"invalid credentials"}`（密码错误 / 账号禁用 / 未知用户名）或 `{"error":"totp_required"}`（密码正确但缺动态码或动态码错误，同样计入防爆破计数）
- `429`：`{"error":"too many failed attempts, try again later"}` + `Retry-After`（同一来源 IP 15 分钟内失败达 10 次后触发滑动窗口锁定，成功登录即清零；Basic 认证失败共用同一计数器）
- `400`：`{"error":"auth is not configured"}`（仅当认证模块未装配时；未设置 `ADMIN_HASH` 不会走到这里——认证会自动武装）

## GET /api/status

```json
{"version":"v0.7.8-beta","revision":3,"sites":2,"time":"2026-09-15T08:00:00Z"}
```

## GET /api/config

```json
{"revision": 3, "config": { /* 完整 Config JSON，见 docs/CONFIG.md */ }}
```

## POST /api/config/publish

请求体（config 为完整配置对象，发布前服务端执行 `Config.Validate`）：

```json
{"note": "开通站点 b.local", "config": { ... }}
```

- `200`：`{"revision": 4, "apply": {"revision": 4, "status": "applied", "error": ""}}` —— 校验通过、落库、热生效（原子替换，失败保留旧配置）；`apply.status`：`applied`（数据面已加载）/ `failed`（数据面加载失败，旧配置继续生效，error 携带原因）/ `pending`（无数据面消费者或超时）
- `400`：`{"error":"config: sites[1].upstream.nodes is empty"}` —— 校验失败不落库（含微引擎上限：per-site 分类 disable 规则 ≤4、全局变体 ≤64）

发布失败不影响线上流量（fail-static）。

## GET /api/revisions

```json
[
  {"id":4,"created_at":"2026-09-15T08:01:00Z","author":"admin","note":"rollback"},
  {"id":3,"created_at":"2026-09-15T08:00:10Z","author":"admin","note":"smoke-v3"}
]
```

## POST /api/revisions/{id}/rollback

将历史 revision 内容重新发布为新 revision（版本库只追加、不可改写）。

- `200`：`{"revision":5,"rolled_back_to":3}`
- `400`：revision 不存在

## GET /api/logs?limit=N

事件对象（`capture_requests` 开启时含脱敏后的 `headers` 与 `body` 快样）：

```json
{
  "ts": "2026-09-15T08:00:05.123+08:00",
  "trace_id": "641d2596a6195a8b",
  "site": "a.local",
  "client_ip": "1.2.3.4",
  "method": "GET",
  "path": "/?id=1' OR '1'='1",
  "status": 403,
  "user_agent": "curl/8",
  "action": "blocked",
  "rule": "semantic/sqli",
  "reason": "SQL injection semantics detected (libinjection s&sos)",
  "body_bytes": 0,
  "headers": {"Authorization": "***", "X-Custom": "v"},
  "body": ""
}
```

`action` 取值：`blocked` / `challenged` / `monitor` / `redirected`。
`headers` 中 `Authorization`、`Cookie`、`Set-Cookie`、`Proxy-Authorization`、`X-Api-Key`
固定脱敏为 `***`。

## GET /api/stats

```json
{"revision":3,"sites":1,"blocked_today":12,"challenged_today":3,"monitor_today":0}
```

## GET /api/certificates

```json
[
  {
    "site": "a.local",
    "source": "file",
    "domains": ["a.local"],
    "subject": "a.local",
    "issuer": "R3",
    "not_before": "2026-09-01T00:00:00Z",
    "not_after": "2026-11-30T00:00:00Z"
  },
  {"site":"b.local","source":"acme","domains":["b.local"],"subject":"managed by ACME (auto-renew)"}
]
```

## GET /metrics

Prometheus 文本格式。核心指标：

| 指标 | 标签 | 说明 |
|---|---|---|
| `kingmoat_requests_total` | site, outcome | outcome: forwarded / blocked / challenged / monitor_forwarded / redirected |
| `kingmoat_stage_hits_total` | stage | 各检测阶段命中次数（acl/geo/captcha/bot/ratelimit/semantic/coraza/auth…） |
| `kingmoat_upstream_errors_total` | site | 上游请求失败数 |
| `kingmoat_config_reloads_total` | outcome | ok / failed |
| `kingmoat_audit_dropped_total` | — | 审计队列溢出丢弃数 |

---

## 数据面站点端点（非管理 API）

| 路径 | 说明 |
|---|---|
| `/.well-known/acme-challenge/*` | ACME HTTP-01 挑战应答（启用 ACME 时挂载；挑战路径先于数据面命中 ACME 引擎，生产/staging 双槽按 token 归属应答，其余路径回落数据面；重定向豁免。TLS-ALPN-01 挑战不走 HTTP：由 443 监听常驻协商 ALPN `acme-tls/1` 后直通引擎应答） |
| `/.well-known/km-captcha/verify` | 滑块验证校验端点（GET，参数 token/x/back；成功签发 `km_captcha` Cookie） |
