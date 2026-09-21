# API 资产梳理 / 专项风险 / BOT 爬虫识别

三个 observe-first 模块：BOT 识别是数据面实时打标底座，API 资产从流量学习 API 清单，专项风险消费资产库与实时信号产出可运营的风险项。**全部能力缺省关闭或 observe**，开启后不改变任何拦截行为。

## 1. BOT 爬虫识别（站点级 `security.bot_detect`）

```json
"security": {
  "bot_detect": {
    "enabled": true,
    "actions": { "good": "allow", "unknown": "observe", "bad": "observe" },
    "rate_threshold": { "requests": 300, "window_sec": 60 },
    "good_bot_bypass_challenge": true
  }
}
```

- **UA 分类**（内嵌规则表）：good（Googlebot/Baiduspider/bingbot/Sogou/360/Yisou/DuckDuckBot/YandexBot/Applebot…）、bad（python-requests/curl/Go-http-client/okhttp/Java、sqlmap/nuclei/xray/masscan/zgrab、空 UA…）、unknown。
- **指纹**：`sha256(IP + UA + 头名序列)[:16]`，按指纹统计频率（默认 300 次/60 秒超阈加分）。
- **评分**：类别基线（good 10 / unknown 30 / bad 70）+ 频率突增 +15 + 缺 Accept-Language/Accept 各 +5，封顶 100。
- **动作**：`allow` / `observe` / `deny` / `challenge`（challenge 需同站启用 JS 挑战 `bot`，启用滑块验证码的站点退化为 observe）。**v0.4 默认全部 observe**——先观察一周数据，再按站点切 deny。
- **联动**：`good_bot_bypass_challenge` 让已验证 good bot 跳过 JS 挑战。
- **审计事件**：`bot_class`/`bot_name`/`bot_score` 字段（omitempty，兼容旧 NDJSON）。
- **指标**：`bot_requests_total{site,class}`、`bot_denied_total{site}`、`bot_challenged_total{site}`。
- **诚实边界**：UA 可伪造，v0.1 结果必须带置信度展示；JA3/JA4 TLS 指纹与 rDNS 反查列入 v0.5 演进。

## 2. API 资产梳理（顶层 `api_assets`）

```json
"api_assets": {
  "enabled": true,
  "sample_rate": 1.0,
  "min_hits": 5,
  "purge_days": 90
}
```

- **观测旁路**：响应完成后发 AccessTick（内存 channel 4096，满则丢弃并计数，绝不阻塞热路径）；与 audit 完全解耦。
- **归一化**：纯数字/UUID/长 hex/日期/邮箱段 → `{param}`；`v1`/`api` 版本段保持字面；query 只聚合参数名（值不落库）；缓冲 JSON body 只采样顶层 key 名。
- **降噪**：未达 `min_hits` 的路径进候选表，达标转正（防扫描器灌垃圾）；`purge_days` 清理僵尸；支持手动 ignore。
- **打标**：auth（/login /auth /token…）、admin（/admin /actuator /swagger /druid…）、export（/export /download /report…）、file（/upload /file /import…）。
- **存储**：独立 `kingmoat-assets.db`（`db_path` 可覆盖）。
- **BOT 分开计数**：bot 流量计入资产但携带 bot_class 标签，bad bot 命中的路径本身就是攻击面情报。

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/assets/apis?site=&method=&tag=&q=&candidates=&page=` | 分页列表 |
| GET | `/api/assets/apis/{id}` | 详情 |
| POST | `/api/assets/apis/{id}/ignore` | 忽略/恢复 |
| GET | `/api/assets/sites` | 站点清单 |

## 3. 专项风险（顶层 `risks`，全部 observe-only）

```json
"risks": {
  "enabled": true,
  "zombie_days": 30,
  "notify_webhook": "https://hooks.example/xxx"
}
```

| # | 风险 | 级别 | 信号 |
|---|---|---|---|
| R1 | 敏感数据暴露 | high | respfilter 命中统计（复用同一 preset/自定义正则，口径一致）≥10 次 |
| R2 | 未授权访问线索 | medium | 凭证比例 ≥50% 的 API 被大量无凭证调用且 2xx ≥20 |
| R3 | 登录爆破 | high | login 类 API 同 IP 5 分钟内 401/403/429 ≥30（实时，节流 5 分钟） |
| R4 | 影子 API | medium | 近 24h 新出现 admin/export 类（OpenAPI 对照列入后续版本） |
| R5 | 僵尸 API | low | `zombie_days`（默认 30）无流量 |
| R6 | 管理面暴露 | high | admin 类被公网来源访问 ≥10 次 |
| R7 | 明文敏感参数 | high | HTTP 站点传输 password/token 类参数名 |

每项含级别、证据（指向脱敏统计）、状态机 open/ignored/resolved，页面标注「建议人工复核」。新发现经 `notify_webhook` POST JSON 通知；风险页有「立即扫描」。

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/risks?status=&level=&kind=&page=` | 列表 |
| POST | `/api/risks/scan` | 立即扫描 |
| POST | `/api/risks/{id}/status` | `{"status":"open|ignored|resolved"}` |

## 4. 与 AI 助手的关系

AI 助手（见 [AI.md](AI.md)）消费同一份审计数据与资产信号做态势解读；三个模块的 observe 数据让 AI 的分析有据可依（Bot 分类帮助 AI 区分爬虫与真实业务流量）。
