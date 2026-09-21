# KingMoat on Windows Server

KingMoat 支持 **all-in-one** 单二进制部署：数据面（反向代理 + WAF）与
控制台（Web UI + REST API + SQLite 配置库）在同一进程内。

## 1. 目录规划

```
C:\kingmoat\
├── kingmoat.exe          # 数据面 + 内嵌控制台
├── kingmoat-cli.exe      # 配置校验 / 密码工具（hash-password / reset-password）
├── config.json           # 初始种子配置（首次启动导入配置库，之后以控制台配置为准）
├── kingmoat.db           # 控制台配置库（首次启动自动创建）
└── logs\                 # 审计数据（audit_log_dir）：audit.db + archive\ 归档
```

> 整个目录必须位于**本地磁盘**：SQLite 在 NFS/SMB/网盘同步目录上会报
disk I/O error。控制台示例端口统一用 `28443`（`-console-addr` 可任意指定）。

## 2. 生成控制台管理员凭证（强烈建议）

```powershell
# 生成 argon2id 哈希（输出形如 $argon2id$v=19$...；-stdin 可避免口令进入 shell 历史）
echo 'YourStrongPassw0rd!' | .\kingmoat-cli.exe hash-password -stdin

# 为服务设置环境变量（系统级，服务重启后生效）
[Environment]::SetEnvironmentVariable("KINGMOAT_ADMIN_HASH", "<粘贴上面的哈希>", "Machine")
```

未设置 `KINGMOAT_ADMIN_HASH` 也能安全使用：控制台认证会自动武装，首次用内置
引导账号 `kmadmin / KingMoat@2026` 登录并被强制改密。预设哈希的意义是把管理
凭据锚定为自选强口令、跳过默认凭据窗口期——控制台需对外网可达时**务必**先预设。

## 3. 手工启动验证

```powershell
cd C:\kingmoat
.\kingmoat-cli.exe validate -config config.json
.\kingmoat.exe -config config.json -console-addr 127.0.0.1:28443 -console-db C:\kingmoat\kingmoat.db
```

- 数据面监听 `config.json` 的 `listen_http` / `listen_https`
- 控制台：`https://127.0.0.1:28443/`（Web UI）、`/api/*`、`/metrics`
  —— `-console-addr` 默认 **HTTPS**（首次启动自动生成 10 年期自签证书，浏览器
  告警属预期；可在控制台设置页替换正式证书）
- 进程日志为 JSON 行输出到 stdout；审计数据在 `logs\audit.db`（SQLite，控制台
  「攻击日志」页查询）

## 4. 注册为 Windows 服务

### 方式 A：WinSW（推荐，无外部依赖）

把 `WinSW-x64.exe` 复制为 `C:\kingmoat\kingmoat-service.exe`，同目录放 `kingmoat-service.xml`：

```xml
<service>
  <id>kingmoat</id>
  <name>KingMoat WAF</name>
  <description>KingMoat WAF data plane + console</description>
  <executable>C:\kingmoat\kingmoat.exe</executable>
  <arguments>-config C:\kingmoat\config.json -console-addr 127.0.0.1:28443 -console-db C:\kingmoat\kingmoat.db</arguments>
  <workingdirectory>C:\kingmoat</workingdirectory>
  <env name="KINGMOAT_ADMIN_HASH">$env{KINGMOAT_ADMIN_HASH}</env>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="3 sec"/>
  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>4</keepFiles></log>
</service>
```

```powershell
.\kingmoat-service.exe install
.\kingmoat-service.exe start
```

### 方式 B：NSSM

```powershell
nssm install kingmoat C:\kingmoat\kingmoat.exe "-config C:\kingmoat\config.json -console-addr 127.0.0.1:28443 -console-db C:\kingmoat\kingmoat.db"
nssm set kingmoat AppDirectory C:\kingmoat
nssm set kingmoat AppEnvironmentExtra KINGMOAT_ADMIN_HASH=<哈希>
nssm start kingmoat
```

## 5. 防火墙

```powershell
# 数据面（按需放行 80/443 或自定义端口）
New-NetFirewallRule -DisplayName "KingMoat HTTP"  -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
New-NetFirewallRule -DisplayName "KingMoat HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
# 控制台默认只绑 127.0.0.1；如需远程管理，改为绑内网地址、放行管理网段，
# 并在控制台「设置」页配置 console.allowed_ips 白名单（IP/CIDR 列表，
# 对控制台所有请求生效含登录；为空表示不限制）
New-NetFirewallRule -DisplayName "KingMoat Console" -Direction Inbound -Protocol TCP -LocalPort 28443 -Action Allow -RemoteAddress 198.51.100.0/24
#                                                                            ^ 示例网段（RFC 5737 文档段），替换为实际管理网段
```

## 6. 升级

配置与版本记录都在 `kingmoat.db`（SQLite），升级只需替换二进制后重启服务；
新版本启动时自动沿用既有配置库（先停服务、备份整个 `C:\kingmoat\`，再替换
`kingmoat.exe`）。误发布配置优先用控制台「配置版本」页一键回滚（旧版本以新
revision 追加发布，热生效），而不是降级二进制。

## 7. 常见问题

- **端口占用**：`netstat -ano | findstr :443`，确认无 IIS/其他代理抢占（控制台
  发布配置时会预探测监听端口，端口被占的发布会以 400 拒绝）。
- **证书**：站点 HTTPS 需要每个站点配置 `tls_cert` / `tls_key`（PEM 路径，或
  控制台上传/启用 ACME 自动证书）。
- **日志**：审计数据在 `logs\audit.db`（SQLite，控制台查询、可导出 NDJSON），
  归档在 `logs\archive\audit-YYYYMMDD.db.gz`（按天压缩，`audit_archive` 开启时）；
  进程日志（JSON 行 stdout）由 WinSW/NSSM 滚动文件承接。
- **502 友好页**：表示 WAF 正常、上游故障——检查站点 upstream 节点地址/端口与
  健康状态。更多共性问题（SQLite 网络盘、AI 404 等）见 [README.md](README.md) FAQ。
