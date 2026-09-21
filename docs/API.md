# KingMoat REST API 参考

控制台 API（WebUI 与 `/api/*` 同源），由 all-in-one 模式（`kingmoat -console-addr`）提供。

- Base URL：`http://<console-host>:<console-port>`（默认 `127.0.0.1:8081`）
- 数据格式：请求/响应均为 JSON（UTF-8）
- 错误格式：`{"error": "<message>"}`，配合标准 HTTP 状态码

## 认证

设置环境变量 `KINGMOAT_ADMIN_HASH`（argon2id 哈希，`kingmoat-cli hash-password` 生成，支持 `-stdin`）
后启用认证；未设置时 API 无认证（仅建议绑定回环/内网地址）。

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

未认证访问返回 `401`。`/metrics` 与其余 API 一样需要认证（专用 `-metrics-addr`
监听器无认证，仅供回环/内网采集）。

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
| GET | `/api/ipgroups` | 是 | IP 组订阅列表（条目数/预览/最后错误） |
| POST | `/api/ipgroups/{name}/refresh` | operator | 手动刷新订阅组 |
| GET | `/metrics` | 是 | Prometheus 指标（用 API Key/Basic 采集；`-metrics-addr` 专用监听器无认证） |

## 角色权限矩阵（RBAC）

| 操作 | admin | operator | auditor |
|---|---|---|---|
| 仪表盘/日志/资产/风险/证书查看 | ✓ | ✓ | ✓ |
| 配置发布 / 回滚 | ✓ | ✓ | ✗ |
| 风险扫描 / 状态处置 / 资产忽略 / AI 报告 | ✓ | ✓ | ✗ |
| 用户管理 | ✓ | ✗ | ✗ |

未认证访问返回 `401`；角色不足返回 `403`（`insufficient role`）。

---

## POST /api/login

```json
{"username": "admin", "password": "<密码>", "totp": "123456"}
```

- `username`：缺省时视为 `admin`。
- `totp`：账号启用了逐用户 MFA，或部署设置了全局 `KINGMOAT_ADMIN_TOTP` 时必填。
- `200`：`{"ok":true,"role":"admin","username":"admin","totp":false}` + `Set-Cookie: km_session=...`
- `401`：`{"error":"invalid credentials"}`
- `429`：`{"error":"too many failed attempts, try again later"}` + `Retry-After`（同一来源 IP 15 分钟内失败达 10 次后触发滑动窗口锁定，成功登录即清零；Basic 认证失败共用同一计数器）
- `400`：`{"error":"auth is not configured"}`（未设置 ADMIN_HASH 时）

## GET /api/status

```json
{"version":"v0.7.0-rc1","revision":3,"sites":2,"time":"2026-09-15T08:00:00Z"}
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

- `200`：`{"revision": 4}` —— 校验通过、落库、热生效（原子替换，失败保留旧配置）
- `400`：`{"error":"config: sites[1].upstream.nodes is empty"}` —— 校验失败不落库

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
| `/.well-known/acme-challenge/*` | ACME HTTP-01（启用 ACME 时自动挂载；重定向豁免） |
| `/.well-known/km-captcha/verify` | 滑块验证校验端点（GET，参数 token/x/back；成功签发 `km_captcha` Cookie） |
