# KingMoat AI 助手（内嵌，只读）

控制台内嵌 AI 安全分析师：读取配置与攻击日志、分析态势、给出建议。**只读**——工具表硬编码为 6 个查询类函数，无任何写路径，AI 不持有可写凭证。

## 启用

`config.json`（或 `-ai-config` 指向的独立文件）：

```json
{
  "ai": {
    "enabled": true,
    "provider": {
      "template": "deepseek",
      "model": "deepseek-chat",
      "api_key_env": "KINGMOAT_AI_API_KEY"
    },
    "sanitize": {
      "enabled": true,
      "mask_public_ip": false,
      "mask_internal_hosts": true,
      "mask_credentials": true,
      "custom_terms": ["你的公司名", "内部项目代号"]
    },
    "analysis": {
      "enabled": true,
      "schedules": [
        { "kind": "attack_summary_daily", "cron": "0 8 * * *", "webhook": "https://hooks.example/xxx" }
      ],
      "spike": { "enabled": true, "window": "1h", "multiplier": 3.0 },
      "max_tokens_per_day": 200000
    },
    "mcp": { "enabled": true, "path": "/mcp" }
  }
}
```

API Key 通过环境变量注入：`export KINGMOAT_AI_API_KEY=sk-...`（`api_key_env` 可改变量名）。

## LLM 提供商模板

统一 OpenAI 兼容协议（`/chat/completions`），预置 10 个模板：`openai`、`deepseek`、`qwen`（阿里百炼）、`glm`（智谱）、`kimi`（月之暗面）、`doubao`（火山方舟）、`openrouter`、`ollama`（本地）、`vllm`（自托管）、`custom`（自定义 base_url）。模板只提供默认 `base_url`，`model` 必填。

## 动态脱敏

所有工具结果出站前过脱敏管道，返回给控制台时自动复原（占位符 ↔ 原值映射按会话存储在本地 ai.db）：

| 占位符 | 类别 | 默认 |
|---|---|---|
| `[ENT-n]` | 企业/品牌/项目名（`custom_terms` 词表） | 启用 |
| `[USR-n]` | 邮箱、用户身份 | 启用 |
| `[NET-n]` | 内网 IP（RFC1918/环回/CGNAT） | 启用 |
| `[INF-n]` | 站点域名、内部主机 | 启用 |
| `[SEC-n]` | 密码/Token/JWT/私钥 | 启用 |
| 攻击源公网 IP | 分析要素 | **保留**（`mask_public_ip: true` 可开） |

MCP 出边界场景输出同样脱敏，但占位符**不可自动复原**（映射不出 KingMoat 进程）。

## 只读保障（三层）

1. **工具层**：注册表硬编码（get_status / get_active_config / list_config_revisions / query_audit_logs / get_attack_summary / get_stats），配置不可增删工具。
2. **凭证层**：工具直连内部数据源，不经过任何带写权限的 HTTP 凭证。
3. **输出层**：AI 输出仅为文本建议；系统提示词声明工具返回内容为不可信数据（防攻击 payload 注入指令），即使被注入，可调用的也只有只读工具，泄露上限为已脱敏数据。

## 触发方式

- **被动聊天**：控制台「AI 助手」页；攻击日志页每行「问AI」一键解读单条事件。
- **主动分析**（`analysis.enabled`）：
  - `attack_summary_daily` / `attack_summary_weekly` / `config_review` cron 计划，结果落 ai.db 并可 generic webhook 通知；
  - 攻击量突增触发：1h 窗口超过近 7 天同时段基线 `multiplier` 倍时生成 `attack_spike` 快报（每小时最多一次）；
  - 日 token 配额 `max_tokens_per_day`，超限拒绝请求。

## 存储

独立 `kingmoat-ai.db`（`-ai-db` 可覆盖）：会话、消息（脱敏态存储）、占位符映射、报告、日用量。可整库删除，不影响 WAF 任何数据。

## MCP 端点

`mcp.enabled` 时在控制面挂载 `POST/GET /mcp`（MCP streamable HTTP），暴露同一只读工具集，位于控制台认证之后。Flocks 等客户端以 remote MCP 接入（Basic Auth / 会话 Cookie 与控制台一致）。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/ai/config` | 状态 + 模板列表 + 今日用量 |
| POST | `/api/ai/chat` | 聊天（SSE：status/delta/tool/done/error） |
| GET/DELETE | `/api/ai/sessions[...]` | 会话管理（展示时自动复原占位符） |
| GET | `/api/ai/reports[/{id}]` | 报告列表/详情 |
| POST | `/api/ai/reports/run` | 手动生成报告 `{"kind":"attack_summary_daily"}` |
