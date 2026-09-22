# KingMoat 配置参考（v0.3）

配置以 JSON 表达，来源可以是静态文件（`-config`）或控制台发布的 revision
（内容结构完全一致）。所有字段校验失败（`Config.Validate`）都会拒绝启动 /
拒绝发布，线上流量保持旧配置（fail-static）。

# 顶层字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `listen_http` | string | 必填 | 数据面 HTTP 监听地址（如 `":80"`、`"127.0.0.1:8080"`） |
| `listen_https` | string | `""` | 数据面 HTTPS 监听地址；站点 TLS 证书 + SNI |
| `audit_log_dir` | string | `"logs"` | 攻击日志目录：SQLite 库 `audit.db`（FTS5 全文索引）+ 每日快照 `archive/` |
| `audit_retention_days` | int | `7` | 本地攻击日志保留天数（0/未设置=7，负数=永不清理），由每日归档任务执行；修改需重启。保留期过大→本库变大、检索变慢，建议配合外发使用 |
| `audit_archive` | object | 开启 | 每日 DB 快照归档，见 [AuditArchiveSettings](#auditarchivesettings) |
| `audit_query` | object | 空 | 日志查询治理：并发上限/超时/紧急降级，见 [AuditQuerySettings](#auditquerysettings)；发布即热生效 |
| `metrics` | object | 空 | 可选 Prometheus 文本端点（/metrics，控制台认证内），见 [MetricsSettings](#metricssettings)；发布热生效 |
| `telemetry` | object | 空 | 匿名安装统计（**默认关**）：`{ "enabled": true }` 开启后仅上报随机安装 ID / 版本 / OS 架构 / 安装方式；`DO_NOT_TRACK` 环境变量优先级更高；连续 3 次不可达自动停止；详见 README 遥测声明 |
| `webhook` | object | 空 | 告警推送，见 [WebhookSettings](#webhooksettings) |
| `log_shipper` | object | 空 | 审计日志外发，见 [ShipperSettings](#shippersettings) |
| `policy` | object | 空 | 全局策略：CRS 阈值 / 自定义 SecLang 规则 / 全局 IP 黑白名单，见 [Policy](#policy) |
| `access_log` | object | 空 | 全量访问日志管道，见 [AccessLogSettings](#accesslogsettings) |
| `disk_guard` | object | 默认开启 | 日志磁盘占用守卫（数据盘 >90% 时 FIFO 清理归档与最旧事件至 65%），见 [DiskGuardSettings](#diskguardsettings) |
| `capture_requests` | bool | `false` | 审计事件附带脱敏请求头与 body 快样（隐私敏感，默认关） |
| `ip_groups` | array | `[]` | 订阅 IP 组，见 [IPGroupSettings](#ipgroupsettings) |
| `sites` | array | 必填 | 防护站点列表，见 [Site](#site) |

# Site

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `domains` | string[] | 必填 | 匹配的域名（Host / SNI，忽略大小写） |
| `mode` | string | `"intercept"` | `intercept` 拦截 / `monitor` 只记录不拦截（灰度） |
| `upstream` | object | 必填 | 上游池：`{"nodes":[{"address":"host:port","weight":1}],"algorithm":"wrr"}`；algorithm：`wrr` 加权轮询（默认）/ `least_conn` 最少连接 / `source_ip` 源 IP 会话保持 |
| `tls_cert` / `tls_key` | string | `""` | 站点 PEM 证书/私钥路径（两者成对必填） |
| `tls_profile` | string | `"moderate"` | HTTPS 加密套件组：`strong`（仅 AEAD，6 套件）/ `moderate`（默认，AEAD + ECDHE-CBC-SHA1）/ `compatible`（moderate + ECDHE-CBC-SHA256）。全部 TLS 1.2 起步、TLS 1.3 始终可用；套件清单见 tlsprofile.go |
| `acme` | object | 空 | 自动证书，见 [ACMESettings](#acmesettings) |
| `health` | object | 空 | 上游健康检查，见 [HealthSettings](#healthsettings) |
| `redirect_to_https` | bool | `false` | HTTP 监听器对本站返回 308 到 HTTPS（需 TLS 证书或 acme + listen_https）；`/.well-known/` 前缀豁免 |
| `waf` | object | 空 | 见 [WAFSettings](#wafsettings) |
| `security` | object | 空 | 防护阶段集合，见 [SecuritySettings](#securitysettings) |
| `real_ip` | object | 空 | 可信代理真实客户端 IP 解析，见 [RealIPSettings](#realipsettings) |
| `headers` | object | 空 | 转发前请求头改写（set/add/del），见 [HeaderRewrite](#headerrewrite) |

# Policy（全局策略，策略管理页）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `inbound_threshold` | int | 5 | CRS 入站异常评分阈值 |
| `outbound_threshold` | int | 4 | CRS 出站异常评分阈值 |
| `custom_rules` | string | `""` | 全局 SecLang 规则文本（追加在 CRS 之后，发布时编译校验） |
| `global_acl` | object | 空 | `{"blacklist":[...],"whitelist":[...]}`，先于站点 ACL 生效；条目同站点 ACL（IP/CIDR/group:）。顺序：全局白名单 → 全局黑名单 → 站点白名单 → 站点黑名单，白名单命中即放行并跳过后续全部检测 |
| `matchers` | array | `[]` | 条件组合规则（MicroEngine 式）：`{name, enabled, sites[], action, logic, conditions[{field,op,value}], disable_stages[]}`；field：client_ip/hostname/path/uri/method/user_agent/referer/body/header:X/query:Y/cookie:Z；op：eq/neq/contains/not_contains/prefix/suffix/regex/cidr/in；action：deny/allow/monitor/disable；action=disable 时 `disable_stages` 列出对该站点关闭的检测模块（coraza/semantic/botdetect/ratelimit/captcha），发布新配置或删除规则后恢复 |

检测流水线顺序（security 各子块全部可选，缺省即关闭对应阶段）：

```
ACL → 攻击惩罚（penalty）→ GeoIP → Exceptions → Matcher（含 disable 动作）→ BotDetect → Captcha(或 Bot JS 质询) → CC 限流 → 语义检测(libinjection) → Coraza/CRS
站点身份认证（auth）在流水线之前；响应侧：敏感信息过滤 → 动态防护
```

# WAFSettings

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 站点级开关（缺省即开启） |
| `custom_rules_file` | string | `""` | 自定义 SecLang 规则文件路径 |
| `body_limit_bytes` | int | 8388608 | 请求体检测缓冲上限 |
| `body_over_limit` | string | `"reject"` | `reject`(413) / `bypass`（流式透传，仅头检测——存在大包绕过面） / `stream`（深检前 body_limit_bytes，余量原样透传——推荐大包场景） |

# SecuritySettings

## acl（ACLSettings）

```json
{
  "blacklist": ["203.0.113.7", "10.0.0.0/8", "group:threat-feed"],
  "whitelist": ["192.168.0.0/16"]
}
```

- 条目支持单 IP、CIDR、`group:<name>`（引用顶层 `ip_groups`）。
- 白名单命中 → 请求标记可信，跳过后续所有检测阶段。
- `group:` 引用不存在的组会被配置校验拒绝。

## ratelimit（RateLimitSettings，CC 防护）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `requests` | int | 必填 | 窗口内允许次数 |
| `window_sec` | int | 60 | 固定窗口长度 |
| `key` | string | `"ip"` | `ip` / `ip+uri` |
| `action` | string | `"deny"` | `deny`(403) / `throttle`(429) |

## bot（BotSettings，轻量 JS 质询）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `secret` | string | 随机 | HMAC 密钥；为空则每次重启失效 |
| `cookie_name` | string | `km_challenge` | 通行 Cookie 名 |
| `ttl_min` | int | 60 | 通行有效期（分钟） |

站点同时启用 `captcha` 时，本阶段被滑块验证码替代。

## captcha（CaptchaSettings，滑块人机验证）

```json
{"enabled": true, "secret": "<hmac-secret>", "cookie_name": "km_captcha", "ttl_min": 60, "tolerance": 8}
```

无通行 Cookie 的客户端收到自包含 SVG 滑块页；拖动到缺口容差范围内即签发
HMAC 签名通行 Cookie。校验端点固定为 `/.well-known/km-captcha/verify`。

## geo（GeoSettings，GeoIP 封禁）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `db_path` | string | 必填 | MaxMind mmdb 文件路径（自备，如 GeoLite2-Country.mmdb） |
| `blacklist` | string[] | `[]` | ISO 3166-1 alpha-2 国家码，如 `["KP","RU"]` |
| `whitelist` | string[] | `[]` | 白名单模式：仅列出的国家放行 |
| `whitelist_trusted` | bool | `false` | 白名单命中是否同时跳过后续所有检测 |

`blacklist` 与 `whitelist` 二选一使用（同时配置时 whitelist 优先）。

## auth（AuthSettings，站点身份认证）

```json
{"realm": "Internal", "users": [
  {"username": "ops", "password_hash": "$argon2id$v=19$..."},
  {"username": "dev", "password": "quick-plain-pw"}
]}
```

- 整站 HTTP Basic 认证（401 + `WWW-Authenticate`），防未授权访问。
- 每用户 `password`（明文，内网快捷）与 `password_hash`（argon2id，
  `kingmoat-cli hash-password` 生成）二选一。

## semantic（SemanticSettings，轻量语义检测）

```json
{"enabled": true, "check_query": true, "check_body": true}
```

基于 libinjection 的 SQLi/XSS 语义识别（路径、查询参数、Referer、缓冲
body），独立于 CRS 规则集。拦截规则名：`semantic/sqli`、`semantic/xss`。
注意：这是轻量语义层，不是完整 AST 引擎；与 CRS 互补而非替代。

## resp_filter（RespFilterSettings，响应敏感信息过滤）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `action` | string | `"mask"` | `mask` 脱敏 / `block` 整体拦截 |
| `presets` | string[] | `[]` | `phone`（CN 手机号）/ `idcard`（CN 身份证）/ `secret`（AK/SK 形态） |
| `patterns` | array | `[]` | 自定义：`[{"name":"my-id","regex":"\\b[0-9]{18}\\b"}]`（RE2 语法，不支持 lookbehind） |
| `body_limit` | int | 8388608 | 响应体扫描上限 |

## dynamic（DynamicSettings，动态防护）

```json
{"enabled": true, "min_bytes": 512, "max_bytes": 1048576}
```

对 text/html 响应逐请求 AES-GCM 加密并由注入的 WebCrypto 解码器还原，
线上字节形态每次访问都不同。**仅 HTTPS（安全上下文）生效**；压缩响应、
超限 body 自动跳过。动态站点会删除上游请求的 `Accept-Encoding`。

# RealIPSettings（真实客户端 IP）

站点部署在 LB/CDN 后时，TCP 对端是代理而非真实客户端。配置可信代理范围后，只有当请求的直接对端落在 `trusted_proxies` 内，才从指定头解析客户端 IP；ACL、GeoIP、限流、Bot、matcher、WAF（CRS REMOTE_ADDR）及所有日志/审计均改用解析结果。非可信对端永不信任其头（防伪造）。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 开关 |
| `header` | string | `"X-Forwarded-For"` | 承载客户端链的头名 |
| `trusted_proxies` | string[] | 必填（开启时） | 允许设置该头的对端 IP/CIDR 列表（如 `"10.0.0.0/8"`） |

解析规则：从链最右端向左跳过可信代理，首个非可信地址即客户端；全部可信时取最左端；头缺失/无合法 IP 时回退 TCP 对端。

```json
"real_ip": { "enabled": true, "trusted_proxies": ["10.0.0.0/8", "172.16.0.0/12"] }
```

# HeaderRewrite（请求头改写）

转发前对出站请求头执行用户配置的 set/add/del（在内置 X-Forwarded-* 处理之后执行，显式配置优先）。值支持占位符：`$client_ip`（真实客户端 IP）、`$remote_addr`（TCP 对端）、`$host`、`$scheme`、`$trace_id`、`$hdr.<Name>`（复制入站头，缺失时该操作跳过）。

| 字段 | 类型 | 说明 |
|---|---|---|
| `set` | object | 替换（或新增）出站头：`{"X-Real-IP": "$client_ip"}` |
| `add` | object | 追加不替换 |
| `del` | string[] | 删除出站头（内部追踪头外发前清除） |

Host/Content-Length/Transfer-Encoding/Connection 等框架与逐跳头禁止改写（配置加载时报错）。

```json
"headers": {
  "set": { "X-Client-Real-IP": "$client_ip", "X-Forwarded-User": "$hdr.X-Authenticated-User" },
  "del": ["X-Internal-Trace"]
}
```

# HealthSettings（上游健康）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 主动探测（定时 GET `path`，2xx/3xx 视为健康） |
| `path` | string | `"/"` | 探测路径 |
| `interval_sec` | int | 10 | 探测间隔 |
| `timeout_sec` | int | 3 | 探测超时 |
| `passive` | bool | `true` | 被动熔断（上游 5xx/连接失败累计） |
| `fail_threshold` | int | 3 | 连续失败次数触发熔断 |
| `cooldown_sec` | int | 30 | 熔断冷却时长 |

不健康节点自动摘除；全部不健康时 fail-open（轮询兜底，让错误在上游暴露）。

# ACMESettings（自动证书）

```json
{"email": "ops@example.com", "staging": false}
```

基于 Let's Encrypt（TLS-ALPN-01 于 HTTPS 监听器，HTTP-01 于 80 端口自动
短路）。`staging: true` 使用测试 CA。证书缓存在工作目录 `acme-cache/`。

# WebhookSettings（告警推送）

```json
{"url": "https://hooks.example.com/kingmoat", "timeout_sec": 5}
```

每个 blocked/challenged 事件 POST 一条 Event JSON（与 `/api/logs` 条目一致）。
异步有界队列（1024），背压丢弃并计入 `kingmoat_audit_dropped_total`。

# ShipperSettings（审计日志外发）

```json
{"type": "clickhouse", "url": "http://ch:8123", "index": "kingmoat_events", "batch_size": 100, "flush_sec": 5}
{"type": "elasticsearch", "url": "http://es:9200", "index": "kingmoat"}
{"type": "loki", "url": "http://loki:3100", "index": "kingmoat"}
{"type": "s3", "endpoint": "minio.example.com:9000", "bucket": "waf-logs", "access_key": "...", "secret_key": "...", "prefix": "kingmoat/audit", "upload_archives": true}
{"type": "syslog", "url": "udp://siem.example.com:514", "index": "kingmoat", "syslog": {"format": "rfc5424"}}
```

- `clickhouse`：HTTP 接口 `POST {url}/?query=INSERT INTO <index> FORMAT JSONEachRow`，
  每行一条事件 JSON；表需自建，示例：
  ```sql
  CREATE TABLE kingmoat_events (
    ts String, trace_id String, site String, client_ip String,
    method String, path String, status Int32, action String,
    rule String, reason String, bot_class String
  ) ENGINE = MergeTree ORDER BY ts;
  ```
- `elasticsearch`：`POST {url}/_bulk`（索引 `index-YYYY.MM.DD`）
- `loki`：`POST {url}/loki/api/v1/push`（label `app=index`）
- `s3`：任意 S3 兼容对象存储（MinIO / 阿里云 OSS / 华为云 OBS / AWS S3），
  事件批量打包为 gzip NDJSON 对象上传至 `<prefix>/YYYY/MM/DD/audit-HHMMSS-xxxx.ndjson.gz`。
  - `endpoint`：`host[:port]`，可带 `http(s)://` 前缀（决定是否 TLS，`use_ssl` 可显式覆盖）
  - `bucket` / `access_key` / `secret_key` 必填；`region` 可选
  - `prefix`：对象键前缀，默认 `kingmoat/audit`
  - `upload_archives`：同时把每日 SQLite 快照上传到 `<prefix>/archives/`（异地容灾）
- `syslog`：标准 syslog（RFC 5424 / RFC 3164），每条事件一帧，MSG 为事件 JSON
  单行，APP-NAME 取 `index`。`url` 指定目标：`udp://siem:514`、`tcp://siem:514`
  或 `tls://siem:6514`；`syslog` 子对象可选：

  | 字段 | 类型 | 默认 | 说明 |
  |---|---|---|---|
  | `protocol` | string | URL scheme | 传输：`udp` / `tcp` / `tls`（覆盖 URL scheme） |
  | `format` | string | `rfc5424` | 消息格式：`rfc5424`（IETF）/ `rfc3164`（BSD） |
  | `framing` | string | `octet` | TCP/TLS 帧：`octet`（RFC 6587，RFC 5424 默认）/ `newline`（传统，RFC 3164 默认） |
  | `facility` | int | `16` (local0) | 0..23；`0` 表示未设置并取默认 |
  | `severity` | int | `6` (info) | 0..7；`0` 表示未设置并取默认；blocked/challenged 事件固定为 4（warning） |
  | `hostname` | string | 本机主机名 | syslog HOSTNAME 字段 |
  | `app_name` | string | 取 `index` | syslog APP-NAME / tag |
  | `tls_skip_verify` | bool | `false` | `tls://` 目标跳过证书校验 |

  UDP 一条事件一个数据报；TCP/TLS 按 `framing` 分帧，写失败自动重连重试一次；
  拨号/写超时由 `timeout_sec`（默认 5s）约束，外发失败只记日志不影响业务。

> 未配置 webhook / log_shipper 时，控制台日志页会提示“日志仅存于本机”的风险提醒。

# AuditArchiveSettings（每日 DB 快照归档）

```json
{"enabled": true, "retention_days": 30}
```

每天首次跨日时对攻击日志库做一致性快照（`VACUUM INTO`）并 gzip 为
`<audit_log_dir>/archive/audit-YYYYMMDD.db.gz`，随后执行保留期清理：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | 每日快照开关（显式 `false` 关闭） |
| `retention_days` | int | `30` | 本地快照文件保留天数（<=0 永久保留）；配合 `s3` 的 `upload_archives` 可实现异地长存 |

快照恢复：解压后直接用任意 SQLite 工具打开，`events` 表含全字段，`raw`
列为事件完整 JSON。

# AuditQuerySettings（日志查询治理，热生效）

```json
{"degraded": false, "max_concurrent": 2, "timeout_ms": 5000}
```

控制台的历史/趋势查询运行在独立 query_only 只读连接池（与审计写入互不
争抢），并统一经过查询闸门：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `degraded` | bool | `false` | 紧急降级开关：`true` 时所有日志查询返回 503，控制台查询负载归零，转发不受影响 |
| `max_concurrent` | int | `2` | 并发查询上限（1–8），满载请求立即 429 |
| `timeout_ms` | int | `5000` | 单次查询超时（1000–30000），超时返回 504 |

> 保留期（`audit_retention_days` / `audit_archive.retention_days`）为启动时
> 快照，修改需重启；本段设置随配置发布热生效。

# PenaltySettings（攻击惩罚，热生效）

```json
{"enabled": true, "window_sec": 600, "threshold": 20, "ban_sec": 3600, "action": "deny", "throttle_per_min": 10}
```

同一源 IP 在统计窗口内累计 ≥ threshold 次「拦截 + 挑战」即触发惩罚：
`deny`（临时封禁，惩罚期内全部拒绝）或 `throttle`（每分钟仅放行
throttle_per_min 个请求，超出 429）。状态存内存：发布配置或重启后清空。
白名单命中（global/site ACL）与误报例外优先于惩罚；命中记录在攻击日志
（规则 `penalty/engine`）。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 引擎开关 |
| `window_sec` | int | `600` | 统计窗口（秒） |
| `threshold` | int | `20` | 触发阈值（拦截+挑战次数） |
| `ban_sec` | int | `3600` | 惩罚时长（秒） |
| `action` | string | `deny` | `deny` 临时封禁 / `throttle` 严格限速 |
| `throttle_per_min` | int | `10` | throttle 模式下每分钟放行数 |

# MetricsSettings（可选 Prometheus 指标端点，热生效）

```json
{"enabled": false}
```

开启后 `GET /metrics` 输出 Prometheus 文本格式指标（请求/拦截/BOT 计数、
队列深度与丢弃 gauge、Go runtime），位于控制台认证面内（匿名不可抓取）；
默认关闭，关闭时该端点返回 404。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | bool | `false` | 是否暴露 /metrics 端点 |

# AccessLogSettings（全量访问日志管道）

```json
{"enabled": true, "type": "clickhouse", "url": "http://ch:8123", "index": "kingmoat_access", "sample_pct": 100, "batch_size": 200, "flush_sec": 5}
{"enabled": true, "type": "syslog", "url": "tcp://siem.example.com:514", "index": "kingmoat_access", "syslog": {"format": "rfc5424", "framing": "octet"}}
```

每个转发/拦截/挑战/重定向请求记录一条（ts、trace_id、site、client_ip、method、
path、query、status、bytes、latency_ms、user_agent、outcome、rule），批量推送到
ClickHouse（表 `kingmoat_access`，同样 JSONEachRow）/ ES / Loki / syslog（同
`log_shipper` 的 syslog 子对象，APP-NAME 取 `index`，blocked/challenged 请求以
warning 级发送）。本地不落盘；
`sample_pct` 支持确定性采样（如 10 = 仅记录 10%）；背压丢弃计入 metrics。
热路径仅支付一次有界队列发送 + 轻量状态包装（透传 Flush/Hijack，
WebSocket/SSE 不受影响）。

# IPGroupSettings（IP 组订阅）

```json
[{"name": "threat-feed", "url": "https://feeds.example.com/bad-ips.txt", "interval_min": 60},
 {"name": "corp-nets", "file": "/etc/kingmoat/corp.txt"}]
```

列表格式：每行一个 IP/CIDR，`#` 注释。ACL 中以 `"group:<name>"` 引用；
刷新失败保留上次快照。

# 环境变量（管理面）

| 变量 | 说明 |
|---|---|
| `KINGMOAT_ADMIN_HASH` | 控制台管理员 argon2id 哈希；未设置时控制台不认证（会告警） |
| `KINGMOAT_ADMIN_TOTP` | 可选 base32 TOTP 密钥，启用后登录需动态码 |

# 完整示例

见仓库根目录 [config.example.json](../config.example.json)；各防护块示例见
[README](../README.md)。

# DiskGuardSettings（日志磁盘占用守卫）

```json
{"enabled": true, "high_pct": 90, "low_pct": 65, "interval_sec": 300}
```

仅监控**数据盘**（审计库所在卷）参与占比评比。超过 `high_pct`（默认 90%）时按
历史优先先进先出清理：先删最旧的每日归档快照（archive/*.db.gz），再按天删除
最旧的活动事件，直至降到 `low_pct`（默认 65%）或无可清理。每个清理周期都有
结构化日志（disk guard: ...）。`enabled: false` 可关闭（不推荐）。
