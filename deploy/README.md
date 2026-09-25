# KingMoat 部署指南（Deployment Guide）

本目录收录 KingMoat WAF 社区版的部署物料。**新用户请从本文档开始**，按「部署前置 → 三条部署路径任选其一 → 首次上线检查单」的顺序操作即可完成上线；日常备份、升级、回滚见第 6 节。

### ⚡ 一键部署（推荐）

Linux（Debian 12+ / Ubuntu 24.04+ / openEuler 22.03+）可跳过本文档全部手动步骤，直接运行：

```bash
curl -fsSL https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh | bash
```

脚本自动安装依赖、下载最新 Release、交互式选安装/数据目录与端口（默认数据面 80/443、控制台 8443，端口被占用会要求重选）、注册 systemd 守护并自启动。详见脚本头部注释与下方第 3 节（路径 B）。

| 文件 | 用途 |
|---|---|
| `README.md`（本文） | 部署总览：前置规划、三条部署路径、上线检查单、日常运维、FAQ |
| **`install.sh`** | **一键部署脚本（Linux，推荐新用户使用）** |
| `Dockerfile` | All-in-one 镜像构建（distroless，非 root 运行） |
| `docker-compose.yml` | Docker Compose 编排示例（端口、卷、健康检查） |
| `kingmoat.service` | Linux systemd 单元（非 root + 仅授予绑低端口能力） |
| `windows.md` | Windows Server 部署与服务化（WinSW / NSSM） |

## 0. 部署形态（Deployment Modes）

KingMoat 是**纯 Go 单二进制**：数据面（反向代理 + WAF）与控制台（Web UI + REST API + SQLite 配置库）在同一进程内。

- **all-in-one（推荐）**：`kingmoat -config config.json -console-addr :8443`。`-console-addr` 一旦指定即启用内嵌控制台，配置持久化到 SQLite（`-console-db`，默认工作目录下 `kingmoat.db`），控制台发布配置热生效、无需重启。
- **static（静态配置文件模式）**：只给 `-config`、不给 `-console-addr`。无控制台、无热更新，配置即 `config.json` 本身。适合嵌入式/极简场景，本文不再展开。

> 本文档默认 all-in-one。二进制与 `kingmoat-cli` 工具从 [Releases](https://gitee.com/kingmoat/KingMoat-WAF/releases) 下载，或按仓库根 README 自行构建。

## 1. 部署前置（Prerequisites）

### 1.1 硬件与系统

- Linux（amd64/arm64）、Windows Server、或任意可跑 Docker 的宿主机。
- 经验参考值（仓库未定官方基准，【待确认】：正式基线以后续压测报告为准）：**2 核 / 4 GB 内存**起步；磁盘空间按审计日志估算——`audit_retention_days`（默认 7 天）× 日均请求事件量，另建议预留 20% 余量。进程内置磁盘水位守护（`disk_guard`，默认高水位 90% 回收、低水位 65%），但回收不能替代容量规划。
- 时间同步（NTP）：审计时间戳、ACME 续期、TOTP 二次验证都依赖准确时钟。

### 1.2 端口规划

| 端口 | 用途 | 来源 |
|---|---|---|
| `:80` / `:443`（一键部署默认；可自定义） | **数据面**：业务流量入口。由配置的 `listen_http` / `listen_https` 决定 | 访客 |
| `:8443`（一键部署默认，可任意） | **控制台**：Web UI + `/api/*` + `/metrics`。由 `-console-addr` 决定，**默认 HTTPS（自签证书）** | 管理员 |
| （可选）`-console-listen-http` | 控制台额外明文 HTTP 监听。仅建议内网排障用，勿暴露公网 | 管理员 |

要点：

- 数据面端口在**控制台配置里改**（站点/监听设置），改完热生效；重启后沿用控制台里的激活配置，而不是磁盘上的 `config.json` 种子（种子仅在首次初始化配置库时导入）。
- 非 root 监听 80/443：Linux 用 systemd 单元自带的 `CAP_NET_BIND_SERVICE` 能力（见 3.3），无需 root 运行。**Docker 例外**：distroless 非 root 容器内改用非特权端口 `:8080`/`:8443`，宿主侧 80/443 由端口映射提供（见第 2 节）。
- 控制台端口默认 8443；公网/跨网段部署建议改为非常见高位端口并只对管理网段放行。

### 1.3 防火墙放行清单

入站（Inbound）：

```bash
# data plane: business traffic (source = anyone)
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
# console: admin networks only (example: 198.51.100.0/24, RFC 5737 test range)
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=198.51.100.0/24 port port=8443 protocol=tcp accept'
firewall-cmd --reload
```

出站（Outbound）按需放行：

| 目标 | 用途 |
|---|---|
| 上游站点（upstream nodes） | 反向代理回源 |
| `acme-v02.api.letsencrypt.org:443` | ACME 自动证书申请/续期（不用 ACME 可不放行） |
| AI 提供商 API（如 `api.deepseek.com:443`） | AI 安全助手（不用可不放行） |
| Webhook / Elasticsearch / Loki / Kafka / S3 | 告警与日志外发（按配置） |

> 除此之外建议默认出站全拒（WAF 自身不需要更多出站），按白名单逐项放行。

### 1.4 目录规划（重要：数据必须放本地磁盘）

**`kingmoat.db`、审计日志等数据目录必须位于本地磁盘，禁止放在 NFS/SMB/网盘（含各类网盘同步目录、云盘挂载）上。** SQLite 依赖本地文件锁与 fsync 语义，在网络文件系统上会出现 `disk I/O error`、库损坏或进程卡死（见 FAQ #2）。

Linux 推荐（与 `kingmoat.service` 对应）：

```text
/etc/kingmoat/            # config.json（首次种子配置）、env（KINGMOAT_ADMIN_HASH）
/usr/local/bin/kingmoat*  # 二进制
/var/lib/kingmoat/        # 数据目录（本地磁盘）：kingmoat.db、logs/、uploads/certs/、acme-cache/
```

Windows 推荐：`C:\kingmoat\`（二进制、config.json、kingmoat.db、logs\ 同目录，详见 windows.md）。

Docker：单一数据卷挂载到容器 `/data`（本地磁盘目录，勿挂网络盘）。

数据目录运行时会生成/维护：`kingmoat.db`（配置库）、`kingmoat-assets.db` 与 `kingmoat-ai.db`（API 资产学习库 / AI 助手库，由 `-console-db` 文件名派生）、`logs/audit.db` + `logs/archive/`（审计与归档）、`logs/metrics-state.json`（累计请求计数）、`uploads/certs/`（证书库，含控制台自签引导证书）、`ai-kek.key`（AI API Key 加密密钥）、`acme-cache/`（ACME 账户与订单缓存）。**备份必须覆盖整个数据目录**（见 6.1）。

### 1.5 DNS 与证书前置

- 把要防护的站点域名 A/AAAA/CNAME 解析到 WAF 数据面地址。
- 站点证书两种方式（控制台「证书」页配置）：
  - **PEM 上传**：每个站点 `tls_cert`/`tls_key`，或控制台直接上传；
  - **ACME（Let's Encrypt 自动申请续签）**：要求 80/443 公网可达（TLS-ALPN-01 走 HTTPS 监听，HTTP-01 走 HTTP 监听），且域名能解析到本机。
- 控制台自身的 TLS 证书：首次启动自动生成 10 年期自签证书（浏览器告警属预期），可在控制台设置页替换为正式证书。

## 2. 路径 A：Docker / Docker Compose（Path A: Docker）

```bash
# 0. prepare a local-disk data dir and seed config (do NOT use NFS/SMB for /data)
mkdir -p ./kingmoat-data
cp config.example.json ./kingmoat-data/config.json
# distroless image runs as non-root (uid 65532); make the volume writable for it
chown -R 65532:65532 ./kingmoat-data   # or: chmod 777 (lab only)

# 1. MANDATORY for docker: the container process is non-root and cannot bind
#    privileged ports — set listen_http ":8080" / listen_https ":8443"
#    in ./kingmoat-data/config.json (host-side 80/443 comes from the port mapping)

# 2. build and start (build context = repo root)
docker compose -f deploy/docker-compose.yml up -d --build

# 3. verify
docker compose -f deploy/docker-compose.yml ps
docker logs kingmoat --tail 50          # process logs (JSON lines on stdout)
curl -k https://127.0.0.1:8081/api/status
```

控制台访问 `https://<宿主机>:8081/`（compose 示例端口；自签证书加 `-k` 或导入证书）。数据面：容器内监听 `:8080`/`:8443`，宿主侧由端口映射对外提供 80/443（compose 已按此编排）。

不用 Compose 的等价 `docker run`：

```bash
docker run -d --name kingmoat \
  -p 80:8080 -p 443:8443 -p 127.0.0.1:8081:8081 \
  -v /opt/kingmoat/data:/data \
  --restart unless-stopped \
  kingmoat:local \
  -config /data/config.json -console-addr :8081 -console-db /data/kingmoat.db
# config.json must use listen_http :8080 / listen_https :8443 (non-root inside
# the container cannot bind 80/443; host-side 80/443 is provided by the mapping)
```

镜像与编排细节：

- 基础镜像 `gcr.io/distroless/static-debian12:nonroot`：无 shell、非 root（uid 65532）运行；容器内排障用 `docker logs` 与控制台 API，不要指望 `docker exec sh`。
- 镜像默认参数：`-config /data/config.json -console-addr :8081 -console-db /data/kingmoat.db`，可在 `docker run` 末尾覆盖。
- 管理员口令预设（可选）：先 `kingmoat-cli hash-password -password 'YourStrongPassw0rd!'` 生成哈希，写入 compose 的 `KINGMOAT_ADMIN_HASH` 环境变量（见 docker-compose.yml 注释）。
- 健康检查：distroless 里没有 shell/curl，`docker-compose.yml` 的 healthcheck 用 `/kingmoat-cli version` 仅验证二进制可执行；业务级探活建议外部探测控制台 `/api/status` 或数据面端口。

## 3. 路径 B：Linux systemd（Path B: Linux systemd, non-root）

> **⚡ 一键部署**：以下步骤可用一键脚本替代——`curl -fsSL https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh | bash`。脚本自动完成本节全部操作（含依赖安装、目录创建、systemd 注册）。如需精细控制各步骤，继续阅读手动流程。

### 3.1 安装二进制与目录

```bash
# 1. install binaries (adjust version/platform to your download)
sudo install -m 0755 kingmoat      /usr/local/bin/kingmoat
sudo install -m 0755 kingmoat-cli  /usr/local/bin/kingmoat-cli

# 2. create a system user and local-disk data dir
sudo useradd --system --home-dir /var/lib/kingmoat --shell /usr/sbin/nologin kingmoat
sudo mkdir -p /etc/kingmoat /var/lib/kingmoat
sudo chown kingmoat:kingmoat /var/lib/kingmoat

# 3. seed config (copy from the repo root; edit listen_http/listen_https/sites)
sudo install -m 0640 config.example.json /etc/kingmoat/config.json

# 4. seed the console port env file (read by the unit's EnvironmentFile; the
#    in-console port change rewrites this file and restarts the service)
echo CONSOLE_PORT=8443 | sudo tee /var/lib/kingmoat/console.env >/dev/null
sudo chmod 600 /var/lib/kingmoat/console.env

# 5. validate before first start (dry-runs WAF compilation too)
sudo -u kingmoat kingmoat-cli validate -config /etc/kingmoat/config.json
```

### 3.2 预设控制台管理员口令（可选但建议）

```bash
# generate an argon2id hash; -stdin avoids shell history / process list exposure
kingmoat-cli hash-password -stdin <<< 'YourStrongPassw0rd!'

# drop the hash into the env file read by the unit (EnvironmentFile)
sudo install -m 0600 /dev/null /etc/kingmoat/env
echo "KINGMOAT_ADMIN_HASH=<粘贴哈希>" | sudo tee /etc/kingmoat/env >/dev/null
sudo chmod 600 /etc/kingmoat/env
```

未设置 `KINGMOAT_ADMIN_HASH` 也能安全启动：控制台认证会自动武装，首次用内置引导账号 `kmadmin / KingMoat@2026` 登录并被强制改密。预设哈希的意义是把管理凭据锚定为你自选的强口令，跳过默认凭据窗口期（公网暴露控制台前**务必**预设，见根 README 安全提示）。

### 3.3 安装 systemd 单元并启动

```bash
sudo install -m 0644 deploy/kingmoat.service /etc/systemd/system/kingmoat.service
sudo systemctl daemon-reload
sudo systemctl enable --now kingmoat    # start now + enable at boot
systemctl status kingmoat
```

单元要点（与 `kingmoat.service` 对应）：

- **非 root 运行**：`User=kingmoat` + `AmbientCapabilities=CAP_NET_BIND_SERVICE`，只授予绑定 80/443 低端口的能力，其余能力全无。
- 沙箱加固：`NoNewPrivileges` / `ProtectSystem=strict` / `ProtectHome` / `PrivateTmp`；数据目录 `/var/lib/kingmoat` 通过 `StateDirectory`/`ReadWritePaths` 保持可写（配置库、审计日志、证书库都在这里写）。
- 环境变量从 `/etc/kingmoat/env` 读入（`KINGMOAT_ADMIN_HASH`、可选 `KINGMOAT_ADMIN_TOTP`、`KINGMOAT_AI_API_KEY`）；控制台端口从数据目录 `console.env` 读入（`CONSOLE_PORT`，见 3.1，控制台设置页改端口时由服务自动改写并重启）。
- 启动参数：`-config /etc/kingmoat/config.json -console-addr 127.0.0.1:${CONSOLE_PORT} -console-db /var/lib/kingmoat/kingmoat.db`（端口由 systemd 从 EnvironmentFile 展开）。

```bash
# console reachable?
curl -k https://127.0.0.1:8443/api/status
# process logs go to journald (JSON lines)
journalctl -u kingmoat -f
```

> 默认单元把控制台绑在 `127.0.0.1:8443`（仅本机可访问）。需要远程管理时，把 `-console-addr` 改为内网管理地址（如 `198.51.100.10:8443`，RFC 5737 示例），同步放行防火墙，并在控制台「设置」里配置 `console.allowed_ips` 白名单（见 5.3）。

## 4. 路径 C：Windows（Path C: Windows Server）

完整步骤（目录规划、WinSW/NSSM 服务化、防火墙、升级）见 [windows.md](windows.md)。速览：

```powershell
# 1. layout: C:\kingmoat\{kingmoat.exe, kingmoat-cli.exe, config.json, logs\}
cd C:\kingmoat
# 2. manual smoke test (console is HTTPS on the -console-addr port)
.\kingmoat-cli.exe validate -config config.json
.\kingmoat.exe -config config.json -console-addr 127.0.0.1:8443 -console-db C:\kingmoat\kingmoat.db
# 3. register as a service with WinSW (recommended) or NSSM, then:
.\kingmoat-service.exe install ; .\kingmoat-service.exe start
# 4. open firewall for the data plane (and console from admin networks only)
New-NetFirewallRule -DisplayName "KingMoat HTTP" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow
```

## 5. 首次上线检查单（First-launch Checklist）

### 5.1 登录与改密

- [ ] 浏览器打开 `https://<控制台地址>:8443/`——自签证书告警属预期（引导证书为 10 年期自签），继续访问即可；
- [ ] 用内置引导账号 `kmadmin / KingMoat@2026` 登录，**首次登录强制修改密码**——设置强口令（这是产品唯一自动创建的账号）；
- [ ] 建议启用 MFA（TOTP）并为团队建立独立账号（RBAC：admin / operator / auditor），`kmadmin` 留作应急。

### 5.2 监听地址与控制台暴露面

- [ ] 控制台默认建议只绑回环或内网管理地址（`-console-addr 127.0.0.1:8443` 或内网 IP）；
- [ ] 若确需更大范围访问，**必须**同时配置 `console.allowed_ips` 白名单（控制台「设置」页，或配置文件 `console.allowed_ips`，支持 IP/CIDR 列表）。白名单对控制台**所有**请求生效（含登录接口），不在名单内的来源一律 403；为空表示不限制；
- [ ] 确认没有把控制台端口对公网放行（`0.0.0.0` 上裸暴露控制台 = 把管理面交给全网扫描器；默认凭据窗口期内风险最高，务必先完成 5.1）。

### 5.3 建站与证书

- [ ] 控制台新建站点：域名 + 上游节点（`http(s)://上游IP:端口`）+ 模式（新站建议先 `monitor` 只记录不拦截，观察误报后切 `intercept`）；
- [ ] 站点证书：上传 PEM 或启用 ACME 自动证书（前提见 1.5）；HTTPS 站点务必确认证书链完整；
- [ ] 在控制台「发布」配置（revision 追加式记录，可随时一键回滚）。

### 5.4 拦截验证（一条命令）

```bash
# simulates a SQLi probe; expect HTTP 403 with an X-Kingmoat-Rule header
# (site domain must match the site you created; adjust Host/port accordingly)
curl -i -H "Host: example.com" "http://<数据面地址>:80/?id=1 UNION SELECT password FROM users"
```

预期：返回 403 拦截页，响应头含 `X-Kingmoat-Rule`（CRS 规则 ID）；控制台「攻击日志」出现对应事件。若返回 200：检查站点域名匹配、站点 WAF 开关与模式（monitor 不拦截只记录）。

### 5.5 收尾

- [ ] 确认审计日志落盘位置与磁盘水位（数据目录 `logs/audit.db`；`disk_guard` 默认 90% 触发回收）；
- [ ] 配置备份任务上线（见 6.1）；
- [ ] 如接 Prometheus，确认 `/metrics` 采集方式（见 6.5）。

## 6. 日常运维（Operations）

### 6.1 配置与数据备份

需要备份的完整清单（都在数据目录/安装目录）：

| 路径 | 内容 |
|---|---|
| `kingmoat.db` | **配置库**（站点、策略、账号、revision 历史）——最关键 |
| `kingmoat-assets.db` / `kingmoat-ai.db` | API 资产学习库 / AI 助手会话库 |
| `ai-kek.key` | AI 提供商 API Key 的加密密钥（丢失则 AI 设置里已存的 Key 无法解密，需重新录入） |
| `uploads/certs/` | 证书库（站点证书 + 控制台证书） |
| `logs/`（audit.db、archive/、metrics-state.json） | 审计数据与累计计数 |
| `/etc/kingmoat/`（Linux）或 `C:\kingmoat\config.json`（Windows） | 种子配置与 env |

```bash
# cold backup (simplest & safest): stop, copy, start
sudo systemctl stop kingmoat
sudo tar czf /backup/kingmoat-$(date +%F).tar.gz /var/lib/kingmoat /etc/kingmoat
sudo systemctl start kingmoat

# online backup of the config DB only (SQLite hot backup; requires sqlite3 CLI)
sqlite3 /var/lib/kingmoat/kingmoat.db ".backup '/backup/kingmoat-online.db'"
```

建议 cron/计划任务每日冷备或 `.backup`，保留 N 份异地。恢复 = 停服 → 还原文件 → 起服。

### 6.2 升级

配置与版本记录都在 `kingmoat.db`（SQLite），`config.json` 只是首次种子——**升级只替换二进制**：

> **⚡ 一键升级**：重新运行一键部署脚本即可——`curl -fsSL https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh | bash`。脚本会替换二进制但保留已有 config.json 与 kingmoat.db（升级 = 重跑 install.sh）。

```bash
# 1. backup first (see 6.1)
# 2. replace the binary
sudo install -m 0755 kingmoat.new /usr/local/bin/kingmoat
# 3. restart; the existing config DB is picked up automatically
sudo systemctl restart kingmoat
# 4. verify version (and console /api/status shows it too)
kingmoat -version
```

Docker：替换镜像 tag 后 `docker compose up -d`。Windows：停服务 → 替换 `kingmoat.exe` → 起服务。配置库向后兼容自动沿用；升级后打开控制台确认版本号与站点状态即可。

### 6.3 回滚（两层）

**配置回滚**（最常用）：控制台「配置版本」页对任意历史 revision 一键回滚（API：`POST /api/revisions/{id}/rollback`）。机制：把所选旧版本的完整配置作为**新 revision 追加发布**（revision 只增不改，审计可追），热生效无需重启。控制台每次发布失败也会自动保留旧配置继续服务（热更新原子生效，失败仅记日志不切换）。

**版本回滚**（二进制降级）：换回旧二进制重启即可（配置库沿用）；但二进制降级可能遇到新版本写入后的数据结构，【待确认：跨版本降级兼容性未在仓库中明确承诺，降级前请先按 6.1 备份，必要时连同 `kingmoat.db` 一起还原到升级前备份】。若只是误发布配置，优先用配置回滚而不是降级。

### 6.4 日志

| 类型 | 位置 | 说明 |
|---|---|---|
| 进程日志（JSON 行，stdout） | systemd: `journalctl -u kingmoat`；Docker: `docker logs kingmoat`；Windows: WinSW 滚动日志文件 | 启动、热更新、错误 |
| 审计/攻击事件 | 数据目录 `logs/audit.db`（SQLite FTS5） | 控制台「攻击日志」页查询、导出 NDJSON |
| 审计归档 | `logs/archive/audit-YYYYMMDD.db.gz` | 按天归档压缩（`audit_archive` 开启时） |
| 访问日志外发 | Elasticsearch / Loki / Kafka / S3（`log_shipper` 配置） | 全量访问日志走外部存储 |

### 6.5 Prometheus /metrics

`/metrics` 挂在**控制台端口**上，且受控制台认证保护（与 Web UI 同一门禁，含 `allowed_ips` 限制）。采集方式二选一：

1. **拉取**：给 Prometheus 配 API Key（控制台用户设置里生成，形如 `kma1_<id>_<secret>`），请求头带 `Authorization: Bearer kma1_...` 抓 `https://<控制台>/metrics`（自签证书需配 `insecure_skip_verify` 或导入证书）；
2. **推送**：配置 `metrics.push.url`，进程定时把 `/metrics` 全量 POST 到你的接收器（适合拉取不便的场景）。

### 6.6 控制台端口更换与失联恢复

**操作入口**：控制台「系统设置 → 通用设置 → 管理界面端口」。填写新端口（1-65535）并确认后，服务自动改写数据目录的 `console.env`（systemd 单元从这里读控制台端口）并触发服务重启，约 30 秒后请用新地址 `https://<主机>:<新端口>` 重新访问控制台。

要点：

- **重启窗口**：保存后约 30 秒内控制台不可访问，当前浏览器标签页会失联，属预期行为；数据面（80/443 业务流量）不受影响；
- 提交前服务会校验端口范围、与数据面监听端口冲突与宿主机占用，校验不通过不会触发重启；
- 防火墙需同步放行新端口（见 1.3），旧端口可按需收回；
- 该能力依赖一键部署生成的 systemd 单元（`EnvironmentFile` 读 `console.env`）；未按此形态部署的实例请手工改 unit 的 `-console-addr`。

**失联恢复**（改完端口后控制台打不开时的手工恢复路径）：

```bash
# 1. 查看当前控制台端口（一键部署默认数据目录 /var/lib/kingmoat；
#    自定义 --data-dir 安装的按实际路径）
cat /var/lib/kingmoat/console.env

# 2. 改回可用端口
sudo vim /var/lib/kingmoat/console.env      # CONSOLE_PORT=8443

# 3. 重启服务生效
sudo systemctl restart kingmoat
```

若 `console.env` 丢失，手工重建同格式文件（`CONSOLE_PORT=<端口>`，权限 600）后重启即可；unit 文件无需改动。

## 7. 常见问题（FAQ）

**Q1：启动报 `bind: address already in use` / 端口占用？**
数据面或控制台端口被其他进程抢占（常见：IIS/Nginx/Apache 占 80/443）。定位：`sudo ss -lntp | grep -E ':(80|443|8443)'`（Windows：`netstat -ano | findstr :443`）。要么停掉占用者，要么改 `listen_http/listen_https` 与 `-console-addr`。另外控制台发布配置时会预探测监听端口，端口被占的发布会以 400 报错拒绝，不会导致启动失败。

**Q2：SQLite 报 `disk I/O error` / `database is locked` / 配置库打不开？**
数据目录被放在了网络盘（NFS/SMB/网盘同步目录/云盘挂载）上——SQLite 不支持这类文件系统。把数据目录移回本地磁盘（见 1.4），Docker 场景检查 volume 挂载源；恢复从最近备份还原。

**Q3：浏览器访问控制台提示证书不可信？**
预期行为：控制台首次启动自动生成 10 年期自签引导证书（HTTPS）。可导入信任，或在控制台「设置」页上传正式证书热替换。数据面的站点证书与此无关，按 5.3 配置。

**Q4：AI 助手对话/日报报 404？**
自定义接入时 `base_url` 必须写到 OpenAI 兼容网关的**版本路径**（如 `https://api.example.com/v1`、通义为 `.../compatible-mode/v1`、智谱为 `.../api/paas/v4`）。KingMoat 按 `base_url + /chat/completions` 直接拼接发起请求，`base_url` 漏掉 `/v1` 就会 404。使用内置模板（DeepSeek/OpenAI/Kimi 等）时已带正确路径，无需手填。

**Q5：站点返回 502 友好提示页？**
该页表示 **WAF 本身正常、上游故障**：上游地址不可达、端口不对、或上游健康检查失败被剔除。检查站点的 upstream 节点地址/协议/端口、上游服务状态与健康检查配置。若上游就是本机服务，注意容器部署时 `127.0.0.1` 指向容器自身，应改用宿主机地址或容器网络名。

## 8. 相关文档

- 配置字段级说明：[docs/CONFIG.md](../docs/CONFIG.md)
- REST API：[docs/API.md](../docs/API.md)；控制台自带 `/openapi.json`
- AI 安全助手接入：[docs/AI.md](../docs/AI.md)
- 架构与许可证合规：[docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
