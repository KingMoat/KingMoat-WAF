# Changelog

## Unreleased

### 新增

- **检测引擎分类过滤（CRS Categories per Site）**：WAF 检测引擎按攻击类型拆分为可独立启停的模块（SQLi / XSS / RCE / LFI / RFI / PHP / 通用注入 / 会话固定 / Java 反序列化 / 扫描器检测），每个站点可通过 `waf.categories` 配置启用的检测类别。缺省不设置 = 全部启用（向后兼容）。关闭的类别规则**不加载**（零性能损耗）。基础设施规则（协议校验/阻塞评分/响应分析）始终加载。控制台暂无 UI 开关（后续版本加），可通过 API 配置
- **一键部署脚本**（`deploy/install.sh`）：支持 Debian 12+ / Ubuntu 24.04+ / openEuler 22.03+，自动安装依赖、从 Gitee（备用 GitHub）下载最新 Release、交互式选安装/数据目录、生成 systemd 守护并自启动；支持 `--version` 锁版本、`--data-dir` 非交互、`--uninstall` 卸载；deploy/README.md 同步新增一键部署入口，Releases 链接从 GitHub 修正为 Gitee
- **匿名安装统计（默认关闭，可一键关闭）**：内置可选的安装量统计——默认关闭，在「系统设置 → 通用设置 → 匿名安装统计」显式开启后生效。仅上报随机安装 ID、软件版本、操作系统架构、CPU 核数与安装方式；不采集主机名、用户名、内网 IP 或任何业务数据；支持行业标准 `DO_NOT_TRACK` 环境变量一键关闭（优先级最高，零请求零落盘）；连续 3 次无法连接统计服务自动永久停止上报（设置开关 关→开 可重新尝试）；配置键 `telemetry.enabled`；关于页新增发布者/技术支持联系方式；README 新增遥测声明与设置说明
- **upstream `sni_host`（固定回源 SNI）**：HTTPS 上游可配置固定回源 SNI——回源 TLS 握手的 ServerName 使用该域名（连接级，连接复用安全），与 `sni_forward` 互斥；配置校验拒绝非法主机名与两者同设

### 修复

- **`sni_forward` 连接复用场景 SNI 错配**：SNI 转发转发的是 TCP 连接的 SNI 而非请求实际域名——keep-alive 连接被不同域名请求复用时，上游收到错配的 SNI/证书；需要固定回源身份的站点请改用 `sni_host`

### 变更

- **AI 数据源装配收拢为共享构建函数**（ai.NewCenterSources）：aiSources 由装配点内手写字面量改为统一调用，新增 DataSources 字段只改一处即可同步，配反射对称性测试防字段漏接（与主仓同构，跨仓同步不再冲突）

## v0.7.0-rc1 (2026-09-21)

KingMoat WAF 社区版首个公开候选版本（木兰宽松许可证 Mulan PSL v2）。

- 纯 Go 实现的 All-in-one WAF：自研 L7 反向代理 + Coraza（ModSecurity SecLang 兼容引擎）+ OWASP CRS 4.x 规则内嵌，libinjection 语义层第二道防线
- 不限制站点数与并发；单二进制部署，配置默认存 SQLite（revision 版本化、发布即热生效、一键回滚）
- Web 控制台（Vue 3）：站点防护图形化配置、攻击日志与一键加白、证书管理（Let's Encrypt ACME 自动续签）、API 资产梳理、风险中心、RBAC 三级（admin/operator/auditor）+ MFA + API Key
- AI 安全助手（只读）：SSE 流式对话、日志一键问 AI、定时日报与突增主动报告、出站动态脱敏、OpenAI 兼容多模板、可选 MCP 端点
- 风险引擎 R1–R7（observe-only：敏感暴露/未授权线索/登录爆破/影子 API/僵尸 API/管理面暴露/明文敏感参数）
- 数据面防护：CC 限流、滑块验证码与 JS 质询、IP 黑白名单与订阅式 IP 组、GeoIP、整站 Basic 认证、响应敏感信息脱敏、HTML 动态防护、拦截/观察双模式、拦截页定制（安全设置）
- 可观测与外发：Prometheus `/metrics`、攻击日志外发（Elasticsearch / Loki / ClickHouse / Kafka / S3 / Syslog）、访问日志外发、webhook / 邮件告警
- 部署形态：all-in-one（推荐）/ 静态配置文件；提供 Docker、systemd、Windows 服务化方案
- 如需多节点集中管理（节点管理）、界面品牌个性化定制或其他功能性定制，请联系作者

### 修复与优化

- **【修复】防护总览导出报表不全**：PNG / PDF 打印原来只输出顶部统计卡行；改为整页捕获（图表重绘、打印分页优化），HTML 报表补「攻击趋势」与「最新攻击」两节
- **【修复】上游健康检查与转发 TLS 策略不一致**：探针曾强制校验上游证书，自签 / 内部 CA 的 HTTPS 上游流量正常却持续被标记不健康；探针现遵循站点 `verify_tls` 策略，与转发路径一致
- **【修复】AI 助手对话 404**：`base_url` 形态自动规范化（无路径补 `/v1/chat/completions`，`/v1` 结尾拼 `/chat/completions`，已完整或自定义路径原样/尊重输入）；`api_key_env` 误填密钥字面量可自动识别使用并告警；`/api/ai/config` 的 `enabled` 语义改为「有效可用性」；AI 抽屉每次打开拉取最新状态，模型热重建有回归测试
- **【安全】拦截页存储型 XSS 校验加固**：通用 `on*=` 事件属性正则 + 实体解码复查 + 拒绝 `vbscript:` / `data:text/html`；拦截响应新增 script-free `Content-Security-Policy` 兜底
- **【安全】节点令牌最小权限**：节点身份从 operator 降为只读 auditor，令牌泄露不再能发布 / 回滚配置；合并重复的令牌校验段
- **【修复】磁盘守护二级回收失效**：`OldestEventTime` 查询了不存在的列导致 FIFO 兜底永不执行
- **【优化】风险中心**：明细表新增站点列与发生次数列；行点击打开详情抽屉（完整字段 + 证据明细键值表）；支持从详情一键跳转该站点攻击日志（`/logs?site=`）
- **【合规】DB-IP 署名补齐**：NOTICE / THIRD-PARTY-LICENSES / gen-licenses 增补内嵌 DB-IP IP to Country Lite（CC BY 4.0）署名
- **【文档】**：新增部署总览 `deploy/README.md`；修正 kingmoat.service 可写路径、docker-compose 非 root 端口、windows.md 控制台 HTTPS 与审计日志形态；API/AI/API-ASSETS/windows 去除早期版本标记；架构文档技术栈与基线信息与实现对齐
