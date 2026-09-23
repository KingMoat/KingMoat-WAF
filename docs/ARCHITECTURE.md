# KingMoat WAF 技术架构设计

> **Slogan**：固若金汤，御攻于无形 —— KingMoat, Fortress for Every Request

| 文档信息 | |
|---|---|
| 版本 | v0.7.0-rc1（架构基线：单二进制 All-in-one + SQLite 配置中心 + 内嵌控制台） |
| 状态 | 已实现：数据面/控制面/热更新/控制台/语义检测均已落地；集群下发为演进设计目标（社区版不含） |
| 技术栈 | Go 1.26+ / Coraza v3 / OWASP CRS 4.x / Vue 3 |
| 社区版范围 | 社区版交付单机 all-in-one 与 static 两种形态；文中涉及独立控制面进程、集群 / Valkey / PostgreSQL 的内容均为演进设计目标，社区版不包含。如需多节点集中管理（节点管理）、界面品牌个性化定制或其他功能性定制，请联系作者 |

---

## 1. 项目定位

### 1.1 一句话定位

**KingMoat 是一个开源、云原生、纯 Go 实现的 Web 应用防火墙**：自研 L7 反向代理承载流量，以 Coraza（ModSecurity SecLang 兼容引擎）为签名检测核心， WAF 的产品体验，以「单二进制、可嵌入、全链路可扩展」为核心差异化。

### 1.2 设计原则

1. **三面分离，一体可裁**：数据面 / 控制面 / 观测面在代码与运行时上边界清晰；默认编译为单二进制 all-in-one，也可拆分部署。
2. **检测即流水线**：任何防护能力（ACL、CC、Coraza、Bot、响应过滤）都是 Pipeline 中的一个 Stage，可编排、可跳过、可并行。
3. **配置驱动，热生效**：所有防护行为由版本化配置描述，数据面 watch 配置流，秒级下发，不打断连接。
4. **性能是功能**：热路径零多余分配、Transaction 对象池、流式请求体、检测早退（Early Exit）。
5. **默认安全 + 渐进模式**：每站点支持 `拦截 / 观察（Monitor）` 双模式切换，新站先观察后拦截，兼顾拦截页与灰度体验。

---

## 2. 总体架构

```
                            ┌───────────────────────────────────────────┐
                            │              控制面 (Control)              │
                            │  ┌─────────┐  ┌──────────┐  ┌──────────┐  │
                            │  │ Web UI  │  │ REST API │  │ 配置中心  │  │
                            │  │ (Vue 3) │  │ (Go chi) │  │ (版本化)  │  │
                            │  └────┬────┘  └────┬─────┘  └────┬─────┘  │
                            └───────┼────────────┼─────────────┼────────┘
                                    │            │      gRPC Watch 配置流
                                    ▼            ▼             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            数据面 (Data Plane, Go)                            │
│                                                                              │
│   Client ──TLS──▶ Listener(SNI/多证书/ACME) ──▶ Site Router(Host→Site)        │
│                                                        │                     │
│                                                        ▼                     │
│                                  ┌──────────────────────┐                    │
│                                  │   Detection Pipeline  │                   │
│                                  │  ① Access Control     │                   │
│                                  │  ② Rate Limit (CC)    │                   │
│                                  │  ③ Coraza Engine      │                   │
│                                  │  ④ Bot Management     │                   │
│                                  │  ⑤ Body 深度检测       │                   │
│                                  └───────┬───────┬───────┘                   │
│                                     拦截 │       │ 放行                      │
│                                          ▼       ▼                           │
│                                    403 拦截页   Upstream Pool(LB/健康检查)     │
│                                                    │                         │
│                                                    ▼                         │
│                                  ┌──────────────────────┐                    │
│                                  │   Response Pipeline   │                   │
│                                  │  ⑥ 响应体敏感信息过滤   │                   │
│                                  │  ⑦ 响应头安全加固       │                   │
│                                  └──────────────────────┘                    │
│                                                                              │
│   观测输出: 日志→LogStore(local/OpenSearch/ES/Loki/Kafka)  Metrics→Prometheus │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 三个运行时平面

| 平面 | 进程/包 | 职责 | 规模 |
|---|---|---|---|
| **数据面** `kingmoat` | `cmd/kingmoat` | TLS 终止、L7 反代、检测流水线、拦截、审计 | 单节点可扛万级 QPS（目标） |
| **控制台**（内嵌） | `cmd/kingmoat -console-addr` | 站点/规则/证书管理、日志检索、配置发布 | 单进程内嵌 SQLite |
| **观测面**（内嵌导出器） | `internal/logstore`, `internal/metrics` | 日志管道、LogStore 后端、指标 | 可对接 OpenSearch/ES/Loki/Kafka + Prometheus |

> **All-in-One 模式**：`kingmoat -console-addr` 时控制面以 goroutine 内嵌于数据面进程，共享 SQLite，单二进制单进程即可交付全部能力。

---

## 3. 数据面详细设计（核心）

### 3.1 请求生命周期

```
accept
  │
  ├─ ① TLS 终止（SNI 路由 → 站点证书；可选透传模式 TCP passthrough）
  │
  ├─ ② Site 匹配（Host/SNI → Site 配置快照，atomic.Value 无锁读取）
  │
  ├─ ③ Pipeline Phase-1「头阶段」（无需请求体即可判定，尽早拦截）
  │     ├─ AccessControl: IP/网段黑白名单、GeoIP 国家封禁、威胁情报 IP 库（可选）
  │     ├─ RateLimit: CC 防护（滑动窗口 + 令牌桶，键=IP/URI/指纹/Session 多维）
  │     ├─ BotCheck: UA 库、JS 挑战 Cookie、（可选）验证码跳转
  │     └─ Coraza: tx.ProcessRequestHeaders()  ← SecLang 请求头阶段规则
  │
  ├─ ④ Body 缓冲决策
  │     ├─ Content-Length/实际读入 ≤ bodyMaxBufferSize（默认 8MB）→ 全量缓冲
  │     ├─ 超限 → 按站点策略: bypass(透传不检) / reject(413) / stream(流式)
  │     └─ WebSocket/Upgrade 请求 → 仅头阶段检测，随后双向透传
  │
  ├─ ⑤ Pipeline Phase-2「体阶段」
  │     └─ Coraza: tx.WriteRequestBody() + tx.ProcessRequestBody()
  │        （JSON/Multipart/URLEncoded 由 Coraza body processor 解析）
  │
  ├─ ⑥ 决策点 Verdict
  │     ├─ DENY  → 渲染拦截页(可自定义模板/HTTP状态码) → 记录审计 → 结束
  │     ├─ ALLOW → 继续
  │     └─ Monitor 模式 → 全部放行，仅记录（灰度期）
  │
  ├─ ⑦ 转发上游（自研 RoundTripper）
  │     ├─ 负载均衡: 轮询/加权/最少连接 + 主动健康检查 + 被动熔断
  │     ├─ 头改写: X-Forwarded-For / X-Real-IP / X-KingMoat-Trace-Id
  │     └─ 重试: 幂等方法可重试，连接失败 failover 下一节点
  │
  ├─ ⑧ Response Pipeline
  │     ├─ Coraza: tx.ProcessResponseHeaders() / ProcessResponseBody()（可选开启）
  │     ├─ 敏感信息过滤: 身份证/手机号/银行卡/AK-SK 正则集（响应体流式替换/拦截）
  │     └─ 安全头注入: HSTS/CSP/X-Frame-Options 等
  │
  └─ ⑨ 观测落盘: Access Log(结构化) + Audit Log(仅命中或全量采样) + Metrics
```

### 3.2 反向代理内核选型

**自研，但站在 `net/http/httputil.ReverseProxy` 的肩膀上**：

- 外层使用 `http.Server` + 自定义 `http.Handler` 完成流水线编排；
- 转发内核基于 `httputil.ReverseProxy`（Go 1.20+ 已支持 WebSocket/Upgrade 透传），通过 `Rewrite` 注入检测逻辑，`ModifyResponse` 挂接响应流水线，`ErrorHandler` 统一上游故障页；
- 自定义 `http.Transport`：连接池调优（`MaxIdleConnsPerHost`、`ForceAttemptHTTP2`）、上游 TLS 指纹可配、`DialContext` 绑定健康检查结果。

> 为什么不全自写 TCP 层转发？——HTTP/2、WebSocket、h2c、hop-by-hop 头处理在标准库中已被大量生产验证；KingMoat 的创新点在检测流水线而不是重新实现 HTTP 语义。预留 `proxy.Engine` 接口，未来可替换。

### 3.3 Coraza 集成设计

```go
// internal/coraza/stage.go —— 每个站点一个 WAF 实例（不同站点不同规则集），
// 另按需携带分类变体引擎（见下表）
type SiteEngine struct {
    waf coraza.WAF          // 不可变实例，热更新时整体替换（copy-on-write）
    txPool sync.Pool        // Transaction 对象池，降低热路径分配
    cfg  SiteDetectConfig   // 模式(拦截/观察)、body 限制、ParanoiaLevel 等
}
```

关键决策：

| 决策点 | 方案 |
|---|---|
| 规则源 | OWASP CRS 4.x（内置 vendored）+ 站点自定义 SecLang 规则 + 全局自定义规则 |
| Transaction 生命周期 | 请求进入创建 → defer `tx.Close()` 归还池；`ProcessLogging` 在关闭前收集审计 |
| 中断模型 | 监听 `tx.Interruption()`（Coraza 的中断机制），`StatusID=403` 时短路返回拦截页 |
| 请求体 | `tx.WriteRequestBody` 流式写入；`SecRequestBodyLimit` 与代理层缓冲上限对齐 |
| 审计日志 | 实现 Coraza `AuditLog` 接口，把 `Serial/Relevant` 日志转入统一审计管道（不落 Coraza 默认文件） |
| 热更新 | 规则变更 → 新建 WAF 实例 → 原子替换 `atomic.Pointer[SiteEngine]` → 在途请求用旧实例跑完 |
| 分类变体引擎 | 微引擎 `coraza:<分类>` disable 规则：发布时按「每条规则分类集 + 并集」预编译变体（复用 REQUEST-999 悬空指令过滤），命中后站点内切换变体（请求当次即生效，持续至发布重置），未知组合回退主引擎；变体编译失败仅降级该范围（Error 告警），仅主引擎失败才启动失败；per-site ≤4 条分类规则、全局 ≤64 变体（config.Validate 前置拒绝） |
| 性能护栏 | `ParanoiaLevel` 按站点可配（默认 1，严格站点 2+）；`executing rules` 耗时直方图暴露到 metrics |

### 3.4 CC 防护与客户端指纹

- **限流内核**：`ratelimit` 包，滑动窗口（Redis-free，本地分片 map + 定期清理）；
- **限流键**：`ip`、`ip+uri`、`cookie(session)`、`指纹` 四维，阈值在站点/全局两级配置；
- **动作**：`403 拦截` / `429 限速` / `JS 挑战`（返回计算型 JS 设置挑战 Cookie，人机验证）；
- **指纹**：`fingerprint` 包生成稳定客户端指纹（IP+UA+Accept-Language+Header 序列哈希，v2 引入 TLS JA3/JA4），用于 CC 键与 Bot 评分；
- **分布式模式**：限流计数走 `internal/cache` 的 KV 接口（内存 / Valkey 双实现，见 3.6）。

### 3.5 Bot 管理（M3）

- 已知爬虫 UA 分类库（good bot / bad bot / unknown）；
- JS 挑战 / （可选）图形验证码组件对接；
- 评分制：指纹 + 行为频率 + 挑战通过历史 → 分数 → 动作。

### 3.6 缓存层设计（Redis/Valkey，可选组件）

缓存层是**集群模式才需要的可选依赖**，单机 / all-in-one 模式全部由进程内实现替代——保住“单二进制开箱即用”的卖点。

**部署推荐 Valkey**（BSD-3-Clause，Linux 基金会主导的 Redis 分支）：Redis 7.4 起改用 RSALv2/SSPLv1（非开源许可），Redis 8 虽新增 AGPL-3.0 选项但分发仍有传染约束，故 KingMoat 发行物不捆绑 Redis 服务端；客户端用 `go-redis/v9`（RESP 协议兼容，Valkey/Redis 双栈可用）。

| 场景 | 键模式（示意） | 单机实现 | 集群实现 |
|---|---|---|---|
| CC 限流计数 | `rl:{site}:{dim}:{key}:{window}` | 内存分片滑动窗口 | `INCR + PEXPIRE` 固定分桶窗口（精度/成本折中，必要时 Lua 滑动窗口） |
| Bot 挑战 / 验证码状态 | `chal:{fingerprint}:{nonce}` | 内存 + TTL | Valkey TTL（多数据面共享挑战结果） |
| 配置版本快速探测 | `cfg:revision` | atomic 内存 | Valkey Pub/Sub 推送 + gRPC Watch 双通道互备 |
| 控制面会话 | `sess:{id}` | 内存 | Valkey（控制面多实例共享登录态） |
| GeoIP / UA 解析结果 | 进程内 LRU | LRU（不做远端缓存） | 同左——本地命中率 >99%，不引入热路径远端 RTT |

**接口抽象**（`internal/cache`，与限流 `Counter` 共用底层）：

```go
type KV interface {
    Get(ctx context.Context, key string) ([]byte, error)
    Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
    Del(ctx context.Context, key string) error
    IncrWindow(ctx context.Context, key string, window time.Duration) (int64, error) // 限流专用原子窗口
    Subscribe(ctx context.Context, pattern string) (Subscription, error)
}
```

**降级策略（关键）**：缓存后端不可达时——

- 限流：**fail-open** 切换本地限流并告警（缓存故障不能把全站请求拦死）；
- 配置：走既有 gRPC Watch / fail-static 兜底，不受影响；
- 挑战：临时退化为纯内存（各节点独立挑战）。

---

## 4. 控制面设计

### 4.1 组件

| 组件 | 技术 | 说明 |
|---|---|---|
| API Server | Go + chi + OpenAPI 3 | 站点、证书、规则、策略、日志、用户 |
| 配置中心 | `internal/configcenter` | 配置版本化（只追加 revision 表）、灰度发布、回滚 |
| 存储 | SQLite（默认）/ PostgreSQL（集群） | GORM 或 sqlc，单 schema |
| Web UI | Vue 3 + Element Plus | 暗色科技感控制台：仪表盘/站点/防护/日志/系统 |
| 配置下发 | gRPC双向流 Watch | 数据面长连接订阅，配置变更推送 revision 增量 |

### 4.2 配置模型（核心实体）

```
Site        站点: domains[], upstreams[], tls{cert,acme}, mode(intercept|monitor)
Upstream    上游: nodes[{address, weight}], lb, healthcheck, timeouts
RuleSet     规则集: 全局/站点两级 SecLang 规则 + CRS 开关与 ParanoiaLevel
Policy      防护策略: ACL, GeoIP, CC 阈值, Bot 动作, 响应过滤开关
Certificate 证书: 手动上传 / ACME 自动签发
Revision    配置版本: {id, diff, author, created_at, note} —— 支持一键回滚
User/Role   管理用户与 RBAC（管理员/安全分析师/只读）
```

### 4.3 热更新时序

```
WebUI ──保存──▶ Console API ──写入──▶ SQLite(revision N+1)
                                   │
                                   ▼
                          gRPC stream 推送 revision
                                   │
                                   ▼
              数据面 ConfigLoader: 校验(空跑构建 WAF 实例) 
                 → 校验失败: 上报错误, 保持旧版本 (安全兜底)
                 → 校验通过: atomic 替换 Site 快照 → ACK 新版本号
```

> 兜底原则：**配置校验失败绝不生效**；数据面与控制面断连时按最近已知好配置继续工作（fail-static）。

---

## 5. 观测面设计

### 5.1 统一事件模型（Canonical Event Schema）

访问日志与攻击事件在 KingMoat 内部只有一份规范事件结构，所有存储后端做投影（projection）：

```json
{
  "ts": "2026-09-15T10:30:00.512+08:00",
  "tx_id": "km-01J5...",
  "stream": "access | attack",
  "site": "shop.example.com",
  "client_ip": "1.2.3.4",
  "geo": {"country": "CN", "as": 4134},
  "fingerprint": "fp_9f3a...",
  "action": "blocked | passed | challenged",
  "stage": "acl | ratelimit | coraza | bot | response",
  "rule": {"id": 942100, "msg": "SQLi detected", "severity": "CRITICAL", "ruleset": "CRS"},
  "http": {"method": "POST", "path": "/api/login", "status": 403, "bytes": 512, "latency_ms": 3},
  "ua": "Mozilla/5.0 ..."
}
```

- 攻击事件 = 访问事件的超集（增加 `rule` 与命中 payload 摘要）；
- **落盘前强制脱敏**：Authorization/Cookie/Set-Cookie 头、body 中的密码/token 字段（脱敏规则可配）；
- 请求体只存命中片段（前后 N KB），全量模式按采样率记录。

### 5.2 日志存储接口（LogStore）

数据面热路径与存储后端完全解耦：`内存 ring buffer（背压/丢弃策略可配）→ 批量聚合 → LogStore 实现`。接口在 `pkg/kingmoat/logstore` 公开，第三方可自行实现后端接入。

```go
type LogStore interface {
    Capabilities() Capabilities                    // 声明 Query/Aggregate/Retention 支持度，UI 据此降级
    Write(ctx context.Context, batch []Event) error
    Query(ctx context.Context, q Query) (*ResultSet, error)            // 攻击事件/访问日志检索
    Aggregate(ctx context.Context, agg Aggregation) ([]Bucket, error)  // 仪表盘统计（时间直方图/分组）
    Purge(ctx context.Context, before time.Time) error                 // 保留期清理
    Health(ctx context.Context) error
    Close(ctx context.Context) error
}
```

### 5.3 内置后端与能力矩阵

| 后端 | 许可证 | 写入 | 检索 | 聚合 | 适用场景 |
|---|---|---|---|---|---|
| `sqlite`（默认） | 公有领域（SQLite）+ MIT（modernc 驱动，无 CGO） | SQLite + FTS5 全文索引，异步批量 | 强（字段过滤 + 全文） | SQL GROUP BY | 单机开箱即用，每日快照归档 `archive/` |
| OpenSearch | 客户端 Apache-2.0 | bulk API | 强（全文+结构化） | 强（date_histogram/terms） | 中大规模生产 |
| Elasticsearch | 客户端 Apache-2.0 | bulk API | 强 | 强 | 已有 ES 栈的企业 |
| Loki | AGPL-3.0（仅 HTTP 对接） | push API | 中（LogQL） | 中（标签聚合） | 已有 Grafana 栈 |
| S3 兼容对象存储 | 客户端 Apache-2.0（minio-go） | gzip NDJSON 对象 / 每日 DB 快照 | 不支持（冷备） | 不支持 | MinIO / 阿里云 OSS / 华为云 OBS 异地容灾 |
| Kafka（中转） | 客户端 MIT | produce | 不支持 | 不支持 | 大集群解耦，consumer 再落 ES/OS |
| Webhook / SIEM | — | POST JSON | 不支持 | 不支持 | 对接企业 SOC |

> **许可证边界**：KingMoat 只通过 HTTP/gRPC 协议对接后端，**不分发任何后端代码**——ES（SSPL）、Loki（AGPL）以独立服务部署均无许可证传染问题。

**能力降级**：控制台按 `Capabilities()` 自适应——Loki 后端的仪表盘统计降级为标签聚合；Kafka/Webhook 后端的查询回落 `sqlite` 本地缓冲；未接入任何外部存储时，日志页展示“仅本机存储”风险提醒（`GET /api/logs/storage`）。

### 5.4 指标

Prometheus 原生 `/metrics`：QPS、延迟分位数、各 Stage 命中数、Coraza 规则耗时 TopN、上游状态、限流触发数、日志管道积压/丢弃数、缓存后端健康度、配置版本号等。

---

## 6. 代码结构

```
KingMoat/
├── cmd/
│   ├── kingmoat/              # 入口（all-in-one 内嵌控制台 / static 两模式）
│   └── kingmoat-cli/          # 规则测试/配置校验工具
├── internal/
│   ├── proxy/                 # 反代内核: listener, sni, rewriter, upstream, lb, health
│   ├── pipeline/              # 检测流水线编排: stage 接口 + 默认编排
│   ├── engine/                # 引擎门面: 公共 Go SDK 入口 (embed 模式)
│   ├── coraza/                # Coraza 封装: SiteEngine, tx 池, auditlog 适配
│   ├── stages/                # 各 Stage: acl, ratelimit, bot, geoip, respfilter
│   ├── configcenter/          # 配置版本化 + gRPC watch 下发
│   ├── store/                 # SQLite/PG 访问层
│   ├── api/                   # REST API handlers
│   ├── logstore/              # LogStore 接口 + local/opensearch/es/loki/kafka/webhook 实现
│   ├── cache/                 # KV 接口 + 内存 / Valkey(Redis) 实现
│   ├── metrics/               # Prometheus 指标
│   └── intercept/             # 拦截页渲染(模板)、JS 挑战
├── pkg/kingmoat/              # 对外公开 Go SDK (库模式 + LogStore/KV 接口)
├── rules/                     # vendored CRS 4.x + KingMoat 默认规则集
├── web/                       # Vue 3 管理控制台（web/console）
├── deploy/                    # Dockerfile, docker-compose, Helm
└── docs/                      # 本文档 + 运维手册 + 规则编写指南
```

**库模式（差异化卖点）**：

```go
// 把 KingMoat 作为库嵌入任意 Go 服务
eng, _ := kingmoat.New(kingmoat.Options{
    Rules: kingmoat.EmbeddedCRS,           // 内置 CRS
    Mode:  kingmoat.Monitor,               // 先观察
})
http.ListenAndServe(":8080", eng.Handler(yourHandler)) // 包裹业务 Handler
```

---

## 7. 关键技术难点与对策

| # | 难点 | 对策 |
|---|---|---|
| 1 | 请求体检测与转发矛盾的取舍 | 三态策略 `bypass/reject/stream` + 大小阈值，默认 8MB，站点级覆盖 |
| 2 | Coraza TX 分配开销 | `sync.Pool` + 请求头阶段 Early Exit（无头规则命中且无 body 检测需求时跳过体阶段） |
| 3 | 热更新期间配置一致性 | 版本号单调递增 + atomic 快照；在途请求绑定其启动时的快照 |
| 4 | 拦截误报伤害业务 | 全局/站点 Monitor 模式、规则级 `--灰度`（仅记录不拦截）、一键白名单（对 TX 特征加 `ctl:ruleRemoveById` 范围规则） |
| 5 | WebSocket / gRPC 长连接 | 握手头走检测；Upgrade 成功后透传不检测（明确写文档说明边界） |
| 6 | 检测延迟叠加 | Stage 并行化预留（头阶段各 Stage 独立并行，体阶段串行）；P99 预算：< 5ms（CRS L1） |
| 7 | 日志管道膨胀与后端故障 | ring buffer 背压 + 丢弃计数暴露指标；后端故障回落 localfile 本地缓冲，恢复后重放 |
| 8 | 二次开发门槛 | `pkg/kingmoat` SDK + Stage 插件接口（编译期注册，不做动态加载，规避 Go plugin 平台限制） |

---

## 8. 安全性设计（管理面）

- 控制面认证：本地账号（argon2id）+ RBAC 三角色；预留 OIDC/LDAP；
- API 全程 TLS；会话 Cookie `HttpOnly/Secure/SameSite`；
- 审计：控制面自身操作（改规则、改站点）全量审计；
- 数据面进程以非 root 运行（cap_net_bind_service 绑定 80/443）；
- 供应链：CI 强制 `govulncheck`、依赖固定、镜像 distroless。

---

## 9. 部署形态

| 形态 | 命令/产物 | 适用 |
|---|---|---|
| 单机 all-in-one | `docker run kingmoat`（内置 SQLite + localfile 日志 + 内存限流，零外部依赖） | 个人/中小团队 |
| 集群（设计目标，社区版不含） | 独立控制面 (N=1..3, PG) + 多数据面 + **Valkey**(限流/挑战/会话共享) + 日志后端(OpenSearch/ES/Loki) | 多节点/高可用 |
| K8s | Helm Chart：数据面 + 控制面 + Valkey + 日志栈（可对接外部托管服务） | 云原生 |
| SDK | `go get pkg/kingmoat` | 嵌入自有 Go 服务 |

---

## 10. 里程碑路线

| 阶段 | 周期(估) | 交付 |
|---|---|---|
| **M0 反代内核** | 2–3 周 | TLS/SNI、站点路由、ReverseProxy 转发、WS 透传、基础压测 |
| **M1 检测闭环** | 3 周 | Coraza 集成、CRS 4.x、拦截页、Monitor 模式、审计日志 NDJSON |
| **M2 控制面** | 4 周 | 站点/证书/规则管理 API、SQLite 存储、gRPC 配置热下发、CLI 校验工具 |
| **M3 防护增强** | 3 周 | CC 限流、ACL/GeoIP、Bot JS 挑战、响应敏感信息过滤 |
| **M4 控制台** | 5 周 | Web 控制台（仪表盘/站点/日志/规则编辑器）、docker-compose 一键部署 |
| **M5 进阶** | 持续 | 集群模式、LogStore 后端（OpenSearch/ES/Loki/Kafka）、语义检测层研究、SDK 文档 |

---

## 11. 技术选型清单

| 领域 | 选型 | 理由 |
|---|---|---|
| 语言 | Go 1.22+ | 生态、性能、单二进制交付 |
| 检测引擎 | `coraza.tech/coraza/v3` + `coraza-coreruleset` | SecLang 兼容、CRS 官方支持、纯 Go |
| 规则集 | OWASP CRS 4.x | 行业标准，误报治理资料丰富 |
| 反代内核 | `net/http` + `httputil.ReverseProxy` | 生产验证，专注检测层创新 |
| 路由/HTTP | `chi` | 轻量、中间件模型清晰 |
| 存储 | SQLite (modernc, 纯 Go) / PostgreSQL | 单机零依赖无 CGO，集群平滑升级 |
| 缓存 | go-redis v9 ↔ Valkey / Redis 兼容 | RESP 协议双栈，Valkey 许可证干净 |
| 日志检索 | OpenSearch / Elasticsearch / Loki（HTTP 对接） | LogStore 接口隔离，不引入后端许可证 |
| 日志队列 | twmb/franz-go（Kafka，可选） | 大规模集群日志解耦 |
| 配置下发 | gRPC + 双向流 watch | 强一致推送，断线 fail-static |
| 日志 | `log/slog` + LogStore 管道自研 | 结构化、低开销、后端可插拔 |
| 指标 | Prometheus client | 事实标准 |
| 前端 | Vue 3 + Element Plus | 暗色科技感控制台，组件精简 |
| 部署 | Docker + distroless + Helm | 云原生友好 |
| 质量 | gofuzz（检测引擎模糊测试）+ e2e（恶意样本回放） | 检测正确性回归 |
| 许可证合规 | `scripts/gen-licenses`（内置依赖准入扫描 + THIRD-PARTY-LICENSES/SBOM 生成） | CI 强制依赖准入门禁（见 §12，已落地） |

---

## 12. 商业化与许可证合规

### 12.1 依赖许可证矩阵

准入原则：**核心代码只允许链接 MIT / BSD / Apache-2.0 许可证依赖；GPL / LGPL / AGPL 一律不进 `go.mod`（仅允许以独立服务 + 网络协议方式对接）；SSPL / RSAL 类非开源许可不分发、不链接。**

| 依赖 | 许可证 | 商业化结论 |
|---|---|---|
| Go 标准库 / `httputil` | BSD-3 | 可商用 |
| Coraza v3 | Apache-2.0 | 可商用，保留 LICENSE/NOTICE |
| OWASP CRS 4.x / coraza-coreruleset | Apache-2.0 | 可商用，保留 NOTICE |
| libinjection-go | BSD-3-Clause | 可商用，保留版权声明 |
| modelcontextprotocol/go-sdk | MIT / Apache-2.0（过渡期双许可） | 可商用 |
| modernc.org/sqlite（含 libc/memory 子包） | BSD-3（+ SQLite 公有领域） | 可商用（纯 Go 无 CGO） |
| pgx | MIT | 可商用 |
| chi / GORM / sqlc | MIT | 可商用 |
| gRPC / protobuf-go | Apache-2.0 / BSD-3 | 可商用 |
| go-redis v9（兼容 Valkey） | BSD 系 | 可商用（CI 扫描清单中核实具体子项） |
| Prometheus client | Apache-2.0 | 可商用 |
| React / TypeScript / Ant Design | MIT | 可商用 |
| go-elasticsearch / opensearch-go | Apache-2.0 | 可商用（仅客户端，服务端外部部署） |
| twmb/franz-go（Kafka） | MIT | 可商用 |
| Grafana Loki / ES 服务端 | AGPL / SSPL | **仅外部服务对接，不随 KingMoat 分发，无传染** |
| Redis 7.4+ 服务端 | RSALv2/SSPLv1 | 不捆绑分发；默认推荐 Valkey（BSD-3） |
| MaxMind GeoLite2 | 专属 EULA | **禁止随安装包再分发数据库**：构建为用户自填 license key 运行时下载，或内置可再分发的开放许可（CC0/CC-BY）国家级简表 |

### 12.2 KingMoat 自身的许可策略（Open Core）

- **核心引擎木兰宽松许可证 v2（Mulan PSL v2）**：OSI 认证的中英双语宽松许可，含明确专利授权条款，企业集成无顾虑；与 Apache-2.0 双向组合兼容，中文文本为准降低国内合规解释成本；无商标授权（KingMoat 商标另行主张）；
- **上游组件原许可保留**：Apache-2.0/MIT/BSD 组件按其原许可分发（§12.1 清单与 THIRD-PARTY-LICENSES），Apache-2.0 组件（Coraza/CRS）的 NOTICE 义务随包履行；
- **企业版闭源**：多租户、高级报表、SLA 支持等企业功能单独商业许可，与核心代码仓库物理隔离；
- **贡献者协议**：DCO + CLA（贡献者许可协议），保留未来调整许可 / 双许可的主动权；
- **商标防御**：KingMoat / slogan 在开源发布前完成商标检索与注册（中国商标 + 马德里国际注册），logo 版权登记，避免与既有 WAF 商标冲突。

### 12.3 合规工程化

- CI 集成许可证扫描（`scripts/gen-licenses -check`，自研零依赖实现：枚举实际编译进二进制的全部第三方模块，逐个解析 module cache 内 LICENSE 文本，允许清单 Apache-2.0/MIT/BSD-2/BSD-3/ISC + 公有领域，检出 GPL 族或未知许可证直接失败），新增依赖自动准入检查；
- 发布物附 `NOTICE` 与 `THIRD-PARTY-LICENSES` 清单（`scripts/gen-licenses` 在 `build.sh` / `build.ps1` 打包时生成并内置每个发布包，仓库根目录附当前快照）；
- vendored CRS 保持原 LICENSE/NOTICE 完整；
- 官方发行物（镜像/二进制）不含 AGPL/SSPL 组件，文档引导用户自建日志后端对接；
- 每次发版生成 SBOM（软件物料清单，`go version -m` 产出 `SBOM.txt` 随包分发），供下游商用客户安全合规审计。
