<template>
  <div>
    <div class="km-toolbar km-sticky">
      <el-button type="primary" :disabled="!can('operator')" @click="openEdit(-1)"><el-icon><Plus /></el-icon>&nbsp;添加站点</el-button>
      <el-button :disabled="!can('operator')" @click="publishForm" :loading="publishing">发布配置（热生效）</el-button>
      <el-button :disabled="!can('operator')" @click="rollbackPrev">↩ 回滚上一版本</el-button>
      <el-input v-model="siteFilter" size="small" style="width:220px" placeholder="筛选：域名 / 名称 / 备注 / 源站 IP" clearable />
      <div class="grow"></div>
      <el-tag v-if="!dirty" effect="plain" type="success" class="km-tag">● 配置 revision #{{ rev }} 已发布 · 热更新生效</el-tag>
      <el-tag v-else effect="plain" type="warning" class="km-tag">有未发布变更（草稿）</el-tag>
      <div class="km-seg">
        <span class="seg-item" :class="{ on: mode === 'form' }" @click="mode = 'form'">图形化</span>
        <span class="seg-item" :class="{ on: mode === 'json' }" @click="mode = 'json'">JSON（高级）</span>
      </div>
    </div>

    <!-- 图形化:左列表 + 右能力概览 -->
    <div v-if="mode === 'form'" class="km-grid-2" style="grid-template-columns:320px 1fr;align-items:start">
      <el-card shadow="never" class="km-site-list" style="padding:0" :body-style="{ padding: 0 }">
        <div class="km-card-head"><span class="km-card-title">站点列表（{{ form.sites.length }}）</span></div>
        <div v-for="p in pagedSites" :key="p.i" class="site-item" :class="{ sel: sel === p.i }" @click="sel = p.i">
          <div class="domain">
            {{ p.s.name || p.s.domains?.[0] || '(未命名站点)' }}
            <el-tag size="small" :type="p.s.disabled ? 'info' : (p.s.mode === 'monitor' ? 'warning' : 'success')" effect="plain" class="km-tag">
              {{ p.s.disabled ? '已禁用' : (p.s.mode === 'monitor' ? 'monitor' : 'intercept') }}
            </el-tag>
            <div style="flex:1"></div>
            <el-tooltip content="编辑站点完整配置">
              <el-button v-if="can('operator')" link type="primary" size="small"
                         @click.stop="sel = p.i; openEdit(p.i)"><el-icon><EditPen /></el-icon></el-button>
            </el-tooltip>
            <el-tooltip :content="p.s.disabled ? '启用站点（立即热生效）' : '快速禁用站点（立即热生效）'">
              <el-switch size="small" :model-value="!p.s.disabled" :disabled="!can('operator') || toggling === p.i"
                         @click.stop="toggleSite(p.i)" @update:model-value="() => {}" />
            </el-tooltip>
          </div>
          <div class="meta">
            <span v-if="p.s.domains?.length > 1">{{ p.s.domains.length }} 个域名</span>
            <span>上游 ×{{ (p.s.upstream?.nodes || []).length }}</span>
            <span v-if="wafOn(p.s)">WAF</span>
            <span v-if="sec(p.s).semantic?.enabled">语义</span>
            <span v-if="sec(p.s).captcha?.enabled">滑块</span>
            <span v-if="sec(p.s).ratelimit">CC {{ sec(p.s).ratelimit.requests }}/{{ sec(p.s).ratelimit.window_sec }}s</span>
            <span v-if="sec(p.s).geo?.enabled">GeoIP</span>
            <span v-if="sec(p.s).auth">Basic 认证</span>
            <span v-if="sec(p.s).acl?.blacklist?.length || sec(p.s).acl?.whitelist?.length">ACL</span>
            <span v-if="sec(p.s).dynamic?.enabled">动态防护</span>
            <span v-if="sec(p.s).resp_filter?.enabled">脱敏</span>
            <span v-if="p.s.redirect_to_https">HTTPS 跳转</span>
            <span v-if="p.s.acme">ACME</span>
            <span v-if="p.s.health?.enabled">健康检查</span>
          </div>
        </div>
        <div v-if="filteredSites.length > sitePageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 12px">
          <span class="km-dim" style="font-size:12px">每页</span>
          <el-select v-model="sitePageSize" size="small" style="width:84px"
                     @change="() => { const max = Math.max(1, Math.ceil(filteredSites.length / sitePageSize)); if (sitePage > max) sitePage = max }">
            <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
          </el-select>
          <el-pagination layout="prev, pager, next" small background :total="filteredSites.length"
                         :page-size="sitePageSize" :current-page="sitePage"
                         @current-change="p => sitePage = p" />
        </div>
        <el-empty v-if="!form.sites.length" description="暂无站点，点击左上角新增" :image-size="70" />
        <el-empty v-else-if="!filteredSites.length" description="无匹配站点" :image-size="70" />
      </el-card>

      <el-card shadow="never" :body-style="{ padding: 0 }" v-if="selSite">
        <div class="km-card-head">
          <span class="km-card-title">{{ selSite.name || selSite.domains?.join(', ') }} · 防护配置</span>
          <div class="extra">
            <el-tag v-if="selSite.disabled" size="small" effect="dark" type="info" class="km-tag">已禁用</el-tag>
            <el-tag v-if="selSite.redirect_to_https" size="small" effect="plain" class="km-tag">HTTPS 308 跳转已启用</el-tag>
            <el-tag v-if="selSite.acme" size="small" effect="plain" class="km-tag">ACME 自动续签</el-tag>
            <el-tag v-if="selSite.tls_profile" size="small" effect="plain" type="info" class="km-tag">TLS {{ selSite.tls_profile }}</el-tag>
            <el-button size="small" type="primary" :disabled="!can('operator')" @click="openEdit(sel)">编辑完整配置</el-button>
            <el-button size="small" type="danger" plain :disabled="!can('operator')" @click="removeSite(sel)">删除</el-button>
          </div>
        </div>
        <div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(59,130,246,.14)"><el-icon color="var(--km-blue)"><Document /></el-icon></div>
            <div><div class="name">签名检测 <span class="km-muted" style="font-weight:400;font-size:11px">Coraza + CRS</span></div>
              <div class="desc">请求体全量缓冲检测 · 内嵌二进制规则，无外部文件</div></div>
            <div class="right"><el-switch v-model="selSite.waf.enabled" @change="markDirty" /></div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(139,92,246,.14)"><el-icon color="var(--km-violet)"><EditPen /></el-icon></div>
            <div><div class="name">语义检测 <span class="km-muted" style="font-weight:400;font-size:11px">libinjection</span></div>
              <div class="desc">独立于 CRS 的 SQLi / XSS 语义层第二道防线</div></div>
            <div class="right"><el-switch :model-value="!!sec(selSite).semantic?.enabled"
              @change="v => toggleSec(selSite, 'semantic', v, {})" /></div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(245,158,11,.14)"><el-icon color="var(--km-amber)"><Clock /></el-icon></div>
            <div><div class="name">CC 限流</div>
              <div class="desc">{{ selSite.security?.ratelimit ? `固定窗口 · key = ip + uri · ${selSite.security.ratelimit.requests} 次 / ${selSite.security.ratelimit.window_sec}s` : '按站点维度的请求频率限制' }}</div></div>
            <div class="right">
              <span v-if="selSite.security?.ratelimit" class="val km-mono">{{ selSite.security.ratelimit.action === 'deny' ? 'deny 403' : 'throttle 429' }}</span>
              <el-switch :model-value="!!selSite.security?.ratelimit"
                @change="v => toggleRatelimit(v)" />
            </div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(34,211,238,.14)"><el-icon color="var(--km-cyan)"><Location /></el-icon></div>
            <div><div class="name">GeoIP 封禁 <span class="km-muted" style="font-weight:400;font-size:11px">内置 DB-IP 库</span></div>
              <div class="desc">{{ geoDesc(selSite) }}</div></div>
            <div class="right">
              <span v-if="sec(selSite).geo?.enabled" class="val">{{ (sec(selSite).geo.blacklist?.length || sec(selSite).geo.whitelist?.length || 0) }} 个国家/地区</span>
              <el-button v-if="can('operator')" size="small" link type="primary" @click="openEdit(sel)">配置地区</el-button>
              <el-switch :model-value="!!sec(selSite).geo?.enabled"
                @change="v => toggleSec(selSite, 'geo', v, { blacklist: selSite.security?.geo?.blacklist || [], whitelist: selSite.security?.geo?.whitelist || [] })" />
            </div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(16,185,129,.14)"><el-icon color="var(--km-green)"><CircleCheck /></el-icon></div>
            <div><div class="name">人机验证 <span class="km-muted" style="font-weight:400;font-size:11px">滑块 SVG + HMAC</span></div>
              <div class="desc">bad bot 触发滑块挑战 · good bot 免挑战 · unknown 观察</div></div>
            <div class="right"><el-switch :model-value="!!sec(selSite).captcha?.enabled"
              @change="v => toggleSec(selSite, 'captcha', v, { enabled: true })" /></div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(245,158,11,.14)"><el-icon color="var(--km-amber)"><View /></el-icon></div>
            <div><div class="name">动态防护 <span class="km-muted" style="font-weight:400;font-size:11px">AES-GCM + WebCrypto</span></div>
              <div class="desc">HTML 响应逐请求加密，前端 WebCrypto 还原（需 HTTPS）</div></div>
            <div class="right"><el-switch :model-value="!!sec(selSite).dynamic?.enabled"
              @change="v => toggleSec(selSite, 'dynamic', v, {})" /></div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(139,92,246,.14)"><el-icon color="var(--km-violet)"><Lock /></el-icon></div>
            <div><div class="name">ACL 访问控制 <span class="km-muted" style="font-weight:400;font-size:11px">IP/CIDR + 订阅式 IP 组</span></div>
              <div class="desc">白名单命中跳过后续全部检测 · 支持 group:名称 引用</div></div>
            <div class="right">
              <span v-if="selSite.security?.acl" class="val">黑 {{ selSite.security.acl.blacklist?.length || 0 }} / 白 {{ selSite.security.acl.whitelist?.length || 0 }}</span>
              <el-switch :model-value="!!selSite.security?.acl" @change="toggleAcl" />
            </div>
          </div>
          <div class="km-config-row">
            <div class="ic" style="background:rgba(239,68,68,.14)"><el-icon color="var(--km-red)"><User /></el-icon></div>
            <div><div class="name">站点身份认证 <span class="km-muted" style="font-weight:400;font-size:11px">HTTP Basic · argon2id</span></div>
              <div class="desc">整站防未授权访问 · 凭证在编辑抽屉中维护</div></div>
            <div class="right">
              <span v-if="selSite.security?.auth" class="val">{{ selSite.security.auth.users?.[0]?.username || '-' }}</span>
              <el-switch :model-value="!!selSite.security?.auth" @change="v => { if (!v) { delete sec(selSite).auth; markDirty() } else { openEdit(sel) } }" />
            </div>
          </div>
        </div>
      </el-card>
      <el-card v-else shadow="never">
        <el-empty description="从左侧选择一个站点查看防护配置" :image-size="80" />
      </el-card>
    </div>

    <!-- JSON 模式 -->
    <el-card v-else shadow="never">
      <div class="km-title">配置 JSON（直接编辑，发布前仍会服务端校验）</div>
      <el-input v-model="jsonText" type="textarea" :rows="20" class="km-mono" spellcheck="false" />
    </el-card>

    <el-card shadow="never" style="margin-top:16px">
      <div class="km-title">版本历史</div>
      <el-table :data="pagedRevs" size="small">
        <el-table-column prop="id" label="版本" width="70" />
        <el-table-column label="时间（本地）" width="180">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="author" label="作者" width="110" />
        <el-table-column prop="note" label="备注" show-overflow-tooltip />
        <el-table-column width="140">
          <template #default="{ row }">
            <el-button v-if="can('operator')" link type="primary" @click="rollbackTo(row.id)">回滚到此版本</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="revs.length > revPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 12px">
        <span class="km-dim" style="font-size:12px">每页</span>
        <el-select v-model="revPageSize" size="small" style="width:84px"
                   @change="() => { const max = Math.max(1, Math.ceil(revs.length / revPageSize)); if (revPage > max) revPage = max }">
          <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
        </el-select>
        <el-pagination layout="prev, pager, next" small background :total="revs.length"
                       :page-size="revPageSize" :current-page="revPage"
                       @current-change="p => revPage = p" />
      </div>
    </el-card>

    <!-- 站点编辑抽屉 -->
    <el-drawer v-model="drawer" :title="editIndex < 0 ? '新增站点' : '编辑站点'" size="640px" destroy-on-close>
      <el-form label-width="120px" label-position="left">
        <div class="km-title">基础</div>
        <el-form-item label="协议">
          <el-radio-group v-model="edit.protocol">
            <el-radio-button value="http">HTTP</el-radio-button>
            <el-radio-button value="https">HTTPS</el-radio-button>
          </el-radio-group>
          <span class="km-dim" style="margin-left:10px;font-size:12px">HTTPS 在下方选择证书来源（ACME 自动 / PEM / 已上传）</span>
        </el-form-item>
        <el-form-item label="站点名称">
          <el-input v-model="edit.name" placeholder="可选，便于识别的自定义名称" maxlength="100" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="edit.comment" type="textarea" :rows="2" maxlength="500" show-word-limit placeholder="可选，记录用途、负责人等" />
        </el-form-item>
        <el-form-item label="域名">
          <div style="width:100%">
            <div v-for="(d, di) in edit.domainRows" :key="di" style="display:flex;gap:8px;margin-bottom:6px">
              <input v-model="edit.domainRows[di]" placeholder="example.com" class="km-native-input km-mono" />
              <el-button link type="danger" @click="edit.domainRows.splice(di, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="edit.domainRows.push('')"><el-icon><Plus /></el-icon>&nbsp;新增域名</el-button>
            <div class="km-dim" style="font-size:12px;margin-top:4px">支持逗号（中/英文）分隔批量录入，自动拆分去重</div>
          </div>
        </el-form-item>
        <el-form-item label="上游服务器">
          <div style="width:100%">
            <div v-for="(u, ui) in edit.upstreamRows" :key="ui" style="display:flex;gap:8px;margin-bottom:6px;align-items:center">
              <el-select v-model="u.proto" style="width:96px" size="small" @change="onUpstreamProtoChange(u)">
                <el-option label="HTTP" value="http" />
                <el-option label="HTTPS" value="https" />
              </el-select>
              <input v-model="u.ip" placeholder="IP 或主机名" class="km-native-input km-mono" style="flex:1" />
              <el-input-number v-model="u.port" :min="1" :max="65535" :controls="false" placeholder="端口" size="small" style="width:84px" />
              <el-input-number v-model="u.weight" :min="1" :max="100" size="small" style="width:88px" />
              <span class="km-dim" style="font-size:12px">权重</span>
              <el-button link type="danger" @click="edit.upstreamRows.splice(ui, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="edit.upstreamRows.push({ proto: 'http', ip: '', port: 80, weight: 1 })"><el-icon><Plus /></el-icon>&nbsp;新增上游</el-button>
          </div>
        </el-form-item>
        <el-form-item label="负载算法">
          <el-radio-group v-model="edit.algorithm">
            <el-radio-button value="wrr">加权轮询</el-radio-button>
            <el-radio-button value="least_conn">最少连接</el-radio-button>
            <el-radio-button value="source_ip">源 IP 会话保持</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="监听端口">
          <span class="km-dim" style="font-size:12px">站点不再单独配置端口：统一使用系统设置顶层的监听端口（默认 HTTP 80 / HTTPS 443），按域名自动路由</span>
        </el-form-item>
        <el-form-item label="模式">
          <el-radio-group v-model="edit.mode">
            <el-radio-button value="intercept">拦截</el-radio-button>
            <el-radio-button value="monitor">观察（只记录）</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <template v-if="edit.protocol === 'https'">
          <el-form-item label="HTTPS 跳转">
            <el-switch v-model="edit.redirect_to_https" :disabled="edit.tlsSource === 'none'" />
            <span class="km-dim" style="margin-left:10px;font-size:12px">HTTP 访问 308 跳转 HTTPS（需 TLS/ACME）</span>
          </el-form-item>
          <el-form-item label="HTTP/2">
            <el-switch v-model="edit.http2Enabled" />
            <span class="km-dim" style="margin-left:10px;font-size:12px">默认开启；关闭后该站点 TLS 协商仅提供 HTTP/1.1</span>
          </el-form-item>
          <el-form-item label="SNI 转发">
            <el-switch v-model="edit.sniForward" />
            <span class="km-dim" style="margin-left:10px;font-size:12px">上游为 HTTPS 时，把客户端原始 SNI 转发给后端（后端证书需匹配该域名）</span>
          </el-form-item>

          <div class="km-title" style="margin-top:18px">TLS / 证书</div>
        <el-form-item label="证书来源">
          <el-radio-group v-model="edit.tlsSource" @change="onTlsSource">
            <el-radio-button value="none">无</el-radio-button>
            <el-radio-button value="file">PEM 文件</el-radio-button>
            <el-radio-button value="acme">ACME 自动</el-radio-button>
            <el-radio-button value="uploaded">已上传证书</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <template v-if="edit.tlsSource === 'file'">
          <el-form-item label="证书路径"><el-input v-model="edit.tls_cert" placeholder="/etc/kingmoat/certs/x.pem" /></el-form-item>
          <el-form-item label="私钥路径"><el-input v-model="edit.tls_key" placeholder="/etc/kingmoat/certs/x.key" /></el-form-item>
        </template>
        <el-form-item v-if="edit.tlsSource === 'uploaded'" label="选择证书">
          <el-select v-model="edit.uploadedName" style="width:100%">
            <el-option v-for="u in uploads" :key="u.name" :value="u.name"
                       :label="u.name + '（' + (u.subject || '?') + '，至 ' + fmtShort(u.not_after) + '）'" />
          </el-select>
          <div class="km-dim" style="font-size:12px;margin-top:4px">证书在「证书管理」页上传</div>
        </el-form-item>
        <el-form-item v-if="edit.tlsSource === 'acme'" label="ACME 说明">
          <span class="km-dim" style="font-size:12px">开启后该域名自动申请 Let's Encrypt 证书并续签；联系邮箱使用系统设置中的「ACME 全局邮箱」，状态见证书管理页</span>
        </el-form-item>

        <el-form-item label="加密套件组">
          <el-select v-model="edit.tls_profile" style="width:320px">
            <el-option label="中等（默认：AEAD + 前向安全兼容套件）" value="moderate" />
            <el-option label="强加密（仅 AEAD 套件）" value="strong" />
            <el-option label="高兼容性（放宽至旧版套件）" value="compatible" />
          </el-select>
          <div class="km-dim" style="font-size:12px;margin-top:4px">HTTPS 站点统一 TLS 1.2 起步，TLS 1.3 始终可用；三档差异见配置文档</div>
        </el-form-item>
        </template>

        <div class="km-title" style="margin-top:18px">检测与防护</div>
        <el-form-item label="WAF (CRS)"><el-switch v-model="edit.wafEnabled" /></el-form-item>
        <el-form-item label="语义检测"><el-switch v-model="edit.semanticEnabled" /></el-form-item>
        <el-form-item label="滑块验证码"><el-switch v-model="edit.captchaEnabled" />
          <el-input v-if="edit.captchaEnabled" v-model="edit.captchaSecret" placeholder="HMAC 密钥（可选）" style="width:220px;margin-left:10px" size="small" />
        </el-form-item>
        <el-form-item label="CC 限流">
          <el-switch v-model="edit.rlEnabled" />
          <template v-if="edit.rlEnabled">
            <el-input-number v-model="edit.rlRequests" :min="1" size="small" style="margin-left:10px;width:110px" />
            <span class="km-dim" style="margin:0 6px;font-size:12px">次 /</span>
            <el-input-number v-model="edit.rlWindow" :min="1" size="small" style="width:110px" />
            <span class="km-dim" style="margin-left:6px;font-size:12px">秒</span>
            <el-select v-model="edit.rlAction" size="small" style="width:90px;margin-left:10px">
              <el-option label="429 限速" value="throttle" /><el-option label="403 拒绝" value="deny" />
            </el-select>
          </template>
        </el-form-item>
        <el-form-item label="GeoIP 封禁">
          <el-switch v-model="edit.geoEnabled" style="margin-left:10px" />
          <template v-if="edit.geoEnabled">
            <el-radio-group v-model="edit.geoMode" size="small" style="margin-left:12px">
              <el-radio-button value="blacklist">封禁所选地区</el-radio-button>
              <el-radio-button value="whitelist">仅允许所选地区</el-radio-button>
            </el-radio-group>
            <el-select v-model="edit.geoCountries" multiple filterable collapse-tags collapse-tags-tooltip
                       placeholder="选择国家/地区（可多选，内置 DB-IP 库）" size="small" style="width:100%;margin-top:8px">
              <el-option-group v-for="g in geoRegions" :key="g.region" :label="g.region">
                <el-option v-for="c in g.countries" :key="c.code" :label="c.code + ' · ' + c.name" :value="c.code" />
              </el-option-group>
            </el-select>
            <el-checkbox v-if="edit.geoMode === 'whitelist'" v-model="edit.geoTrusted" style="margin-top:4px">
              白名单命中跳过后续全部检测（trusted）
            </el-checkbox>
          </template>
        </el-form-item>
        <el-form-item label="站点认证">
          <el-switch v-model="edit.authEnabled" />
          <template v-if="edit.authEnabled">
            <el-input v-model="edit.authUser" placeholder="用户名" size="small" style="width:130px;margin-left:10px" />
            <el-input v-model="edit.authPass" placeholder="密码(≥8位，留空保持原有密码)" size="small" style="width:220px;margin-left:10px" show-password />
          </template>
        </el-form-item>
        <el-form-item label="响应脱敏">
          <el-switch v-model="edit.respEnabled" />
          <el-select v-if="edit.respEnabled" v-model="edit.respPresets" multiple size="small" style="width:280px;margin-left:10px">
            <el-option label="手机号" value="phone" /><el-option label="身份证" value="idcard" /><el-option label="密钥" value="secret" />
          </el-select>
        </el-form-item>
        <el-form-item label="动态防护">
          <el-switch v-model="edit.dynamicEnabled" />
          <span class="km-dim" style="margin-left:10px;font-size:12px">HTML 逐请求加密（需 HTTPS）</span>
        </el-form-item>

        <div class="km-title" style="margin-top:18px">访问控制 / 可用性</div>
        <el-form-item label="IP 黑名单">
          <el-select v-model="edit.aclBlack" multiple filterable allow-create default-first-option
                     placeholder="IP/CIDR/group:名称" style="width:100%" />
        </el-form-item>
        <el-form-item label="IP 白名单">
          <el-select v-model="edit.aclWhite" multiple filterable allow-create default-first-option
                     placeholder="IP/CIDR/group:名称" style="width:100%" />
        </el-form-item>
        <el-form-item label="健康检查">
          <el-switch v-model="edit.healthEnabled" />
          <el-input v-if="edit.healthEnabled" v-model="edit.healthPath" placeholder="探测路径 /" size="small" style="width:150px;margin-left:10px" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="drawer = false">取消</el-button>
        <el-button type="primary" @click="applyEdit">保存到配置（待发布）</el-button>
        <el-button type="success" :loading="publishingSite" :disabled="!can('operator')" @click="saveAndPublishSite">保存并发布此站点</el-button>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, can, post } from '../api'
import { fmtTime } from '../timefmt'

const route = useRoute()

const uploads = ref([])
async function loadUploads() { try { uploads.value = await api('/api/certificates/uploads') } catch (e) { uploads.value = [] } }
function fmtShort(ts) { return (ts || '').slice(0, 10) }

// GeoIP 主要区域国家码（ISO 3166-1 alpha-2），按区域分组供多选下拉展示。
const geoRegions = [
  { region: '东亚', countries: [
    { code: 'CN', name: '中国' }, { code: 'HK', name: '中国香港' }, { code: 'MO', name: '中国澳门' },
    { code: 'TW', name: '中国台湾' }, { code: 'JP', name: '日本' }, { code: 'KR', name: '韩国' },
    { code: 'KP', name: '朝鲜' }, { code: 'MN', name: '蒙古' }] },
  { region: '东南亚', countries: [
    { code: 'SG', name: '新加坡' }, { code: 'MY', name: '马来西亚' }, { code: 'TH', name: '泰国' },
    { code: 'VN', name: '越南' }, { code: 'ID', name: '印度尼西亚' }, { code: 'PH', name: '菲律宾' },
    { code: 'MM', name: '缅甸' }, { code: 'KH', name: '柬埔寨' }, { code: 'LA', name: '老挝' },
    { code: 'BN', name: '文莱' }, { code: 'TL', name: '东帝汶' }] },
  { region: '南亚', countries: [
    { code: 'IN', name: '印度' }, { code: 'PK', name: '巴基斯坦' }, { code: 'BD', name: '孟加拉国' },
    { code: 'LK', name: '斯里兰卡' }, { code: 'NP', name: '尼泊尔' }, { code: 'MV', name: '马尔代夫' },
    { code: 'AF', name: '阿富汗' }] },
  { region: '中东/西亚', countries: [
    { code: 'AE', name: '阿联酋' }, { code: 'SA', name: '沙特' }, { code: 'QA', name: '卡塔尔' },
    { code: 'KW', name: '科威特' }, { code: 'TR', name: '土耳其' }, { code: 'IL', name: '以色列' },
    { code: 'IR', name: '伊朗' }, { code: 'IQ', name: '伊拉克' }, { code: 'JO', name: '约旦' },
    { code: 'LB', name: '黎巴嫩' }, { code: 'SY', name: '叙利亚' }, { code: 'YE', name: '也门' },
    { code: 'OM', name: '阿曼' }, { code: 'BH', name: '巴林' }] },
  { region: '欧洲', countries: [
    { code: 'GB', name: '英国' }, { code: 'DE', name: '德国' }, { code: 'FR', name: '法国' },
    { code: 'IT', name: '意大利' }, { code: 'ES', name: '西班牙' }, { code: 'PT', name: '葡萄牙' },
    { code: 'NL', name: '荷兰' }, { code: 'BE', name: '比利时' }, { code: 'CH', name: '瑞士' },
    { code: 'AT', name: '奥地利' }, { code: 'SE', name: '瑞典' }, { code: 'NO', name: '挪威' },
    { code: 'DK', name: '丹麦' }, { code: 'FI', name: '芬兰' }, { code: 'IS', name: '冰岛' },
    { code: 'IE', name: '爱尔兰' }, { code: 'PL', name: '波兰' }, { code: 'CZ', name: '捷克' },
    { code: 'HU', name: '匈牙利' }, { code: 'RO', name: '罗马尼亚' }, { code: 'GR', name: '希腊' },
    { code: 'RU', name: '俄罗斯' }, { code: 'UA', name: '乌克兰' }, { code: 'BY', name: '白俄罗斯' }] },
  { region: '北美', countries: [
    { code: 'US', name: '美国' }, { code: 'CA', name: '加拿大' }, { code: 'MX', name: '墨西哥' }] },
  { region: '南美', countries: [
    { code: 'BR', name: '巴西' }, { code: 'AR', name: '阿根廷' }, { code: 'CL', name: '智利' },
    { code: 'CO', name: '哥伦比亚' }, { code: 'PE', name: '秘鲁' }, { code: 'VE', name: '委内瑞拉' }] },
  { region: '大洋洲', countries: [
    { code: 'AU', name: '澳大利亚' }, { code: 'NZ', name: '新西兰' }, { code: 'FJ', name: '斐济' }] },
  { region: '非洲', countries: [
    { code: 'ZA', name: '南非' }, { code: 'EG', name: '埃及' }, { code: 'NG', name: '尼日利亚' },
    { code: 'KE', name: '肯尼亚' }, { code: 'MA', name: '摩洛哥' }, { code: 'TZ', name: '坦桑尼亚' },
    { code: 'GH', name: '加纳' }, { code: 'ET', name: '埃塞俄比亚' }] },
]

// 防护概览卡片的 GeoIP 描述：方向 + 国家/地区摘要。
function geoDesc(s) {
  const geo = s.security?.geo
  if (!geo?.enabled) return '按国家/地区黑白名单控制来源 · 使用内置 DB-IP 库，无需自备 mmdb'
  const list = geo.blacklist?.length ? geo.blacklist : geo.whitelist || []
  const dir = geo.blacklist?.length ? '黑名单' : '白名单'
  const head = list.slice(0, 6).join(' / ')
  return `${dir}模式：${head}${list.length > 6 ? ` 等 ${list.length} 个国家/地区` : (list.length ? '' : '（未选择地区）')}`
}

const rev = ref(0)
const revs = ref([])
const mode = ref('form')
const publishing = ref(false)
const publishingSite = ref(false)
const drawer = ref(false)
const editIndex = ref(-1)
const jsonText = ref('')
const sel = ref(0)
const dirty = ref(false)
function markDirty() { dirty.value = true }

// 上游协议切换时端口跟随默认值：HTTP→80、HTTPS→443；
// 用户已填非默认端口（如 8443）时保留不覆盖
function onUpstreamProtoChange(u) {
  const d = u.proto === 'https' ? 443 : 80
  if (!u.port || u.port === 80 || u.port === 443) u.port = d
}

// 表单模型 = 整份配置（sites 数组 + 顶层）
const form = reactive({ listen_http: '', listen_https: '', audit_log_dir: 'logs', sites: [], _raw: null })

const selSite = computed(() => (form.sites.length ? form.sites[Math.min(sel.value, form.sites.length - 1)] : null))

// 站点列表分页：默认每页 10 条，可选 10/20/50/100
const sitePage = ref(1)
const sitePageSize = ref(10)

// 站点筛选：不区分大小写子串匹配 名称/备注/域名/源站地址，空词返回全部。
// 保留 form.sites 原始索引 i，选中与编辑仍指向原始站点。
const siteFilter = ref('')
const filteredSites = computed(() => {
  const q = siteFilter.value.trim().toLowerCase()
  const all = form.sites.map((s, i) => ({ s, i }))
  if (!q) return all
  return all.filter(({ s }) => {
    const fields = [s.name, s.comment, ...(s.domains || []), ...((s.upstream?.nodes || []).map(n => n?.address))]
    return fields.some(v => String(v || '').toLowerCase().includes(q))
  })
})
watch(siteFilter, () => { sitePage.value = 1 })

const pagedSites = computed(() => {
  const list = filteredSites.value
  const start = (sitePage.value - 1) * sitePageSize.value
  return list.slice(start, start + sitePageSize.value)
})

// 版本历史分页：默认每页 10 行，可选 10/20/50/100
const revPage = ref(1)
const revPageSize = ref(10)
const pagedRevs = computed(() => {
  const start = (revPage.value - 1) * revPageSize.value
  return revs.value.slice(start, start + revPageSize.value)
})
watch(revPageSize, () => { const max = Math.max(1, Math.ceil(revs.value.length / revPageSize.value)); if (revPage.value > max) revPage.value = max })
watch(revs, () => { const max = Math.max(1, Math.ceil(revs.value.length / revPageSize.value)); if (revPage.value > max) revPage.value = max })

function sec(s) { if (!s.security) s.security = {}; return s.security }
function wafOn(s) { return !s.waf || s.waf.enabled !== false }

// 行内开关辅助:开启时以 extra 作为初始对象
function toggleSec(s, key, v, extra) {
  if (v) sec(s)[key] = { enabled: true, ...extra }
  else delete sec(s)[key]
  markDirty()
}
function toggleRatelimit(v) {
  const s = selSite.value
  if (!s) return
  if (v) sec(s).ratelimit = { requests: s.security?.ratelimit?.requests || 120, window_sec: s.security?.ratelimit?.window_sec || 10, action: s.security?.ratelimit?.action || 'deny' }
  else delete sec(s).ratelimit
  markDirty()
}
function toggleAcl(v) {
  const s = selSite.value
  if (!s) return
  if (v) sec(s).acl = { blacklist: s.security?.acl?.blacklist || [], whitelist: s.security?.acl?.whitelist || [] }
  else delete sec(s).acl
  markDirty()
}

// 单站点快速禁用/启用:改 disabled 字段后立即走单站点发布(热生效)
const toggling = ref(-1)
async function toggleSite(i) {
  if (!can('operator') || toggling.value >= 0) return
  const s = form.sites[i]
  if (!s) return
  toggling.value = i
  try {
    const next = { ...JSON.parse(JSON.stringify(s)), disabled: !s.disabled }
    const d = await post('/api/config/site/publish', {
      domain: (next.domains && next.domains[0]) || '',
      note: (next.disabled ? 'site disabled: ' : 'site enabled: ') + ((next.domains && next.domains[0]) || ''),
      site: next,
    })
    ElMessage.success((next.disabled ? '站点已禁用' : '站点已启用') + '，热生效（版本 ' + d.revision + '）')
    await load()
    sel.value = i
  } catch (e) {
    ElMessage.error('切换失败：' + e.message)
  } finally {
    toggling.value = -1
  }
}

async function load() {
  const d = await api('/api/config')
  rev.value = d.revision
  jsonText.value = JSON.stringify(d.config, null, 2)
  Object.assign(form, JSON.parse(JSON.stringify(d.config)))
  const rs = await api('/api/revisions')
  revs.value = rs
  dirty.value = false
  if (sel.value >= form.sites.length) sel.value = Math.max(0, form.sites.length - 1)
}

async function publishForm() {
  let cfg
  if (mode.value === 'json') {
    try { cfg = JSON.parse(jsonText.value) } catch (e) { return ElMessage.error('JSON 解析失败：' + e.message) }
  } else {
    cfg = JSON.parse(JSON.stringify(form))
    delete cfg._raw
  }
  publishing.value = true
  try {
    const d = await post('/api/config/publish', { note: 'console publish', config: cfg })
    ElMessage.success('发布成功，版本 ' + d.revision + '，已热生效')
    await load()
  } catch (e) {
    if (e && e.code === 'no_changes') {
      ElMessage.info('配置无变更，未创建新版本')
      await load()
    } else {
      ElMessage.error('发布失败：' + e.message)
    }
  } finally {
    publishing.value = false
  }
}

async function rollbackPrev() {
  if (revs.value.length < 2) return ElMessage.warning('没有可回滚的历史版本')
  const d = await post(`/api/revisions/${revs.value[1].id}/rollback`)
  ElMessage.success('已回滚至版本 ' + revs.value[1].id + '，发布为 v' + d.revision)
  await load()
}
async function rollbackTo(id) {
  const d = await post(`/api/revisions/${id}/rollback`)
  ElMessage.success('已回滚至版本 ' + id + '，发布为 v' + d.revision)
  await load()
}

// ---- 编辑抽屉:config site ↔ 表单模型 ----
const edit = reactive({})
function onTlsSource(v) {
  if (v === 'none') edit.redirect_to_https = false
}
// 协议切换：HTTP 时清空 TLS 相关选择；HTTPS 且无证书来源时默认 ACME 自动
function onProtoChange(v) {
  if (v === 'http') {
    edit.tlsSource = 'none'
    edit.redirect_to_https = false
  } else if (edit.tlsSource === 'none') {
    edit.tlsSource = 'acme'
  }
}
function openEdit(i) {
  editIndex.value = i
  if (i < 0) sel.value = Math.max(0, form.sites.length - 1)
  const s = i >= 0 ? JSON.parse(JSON.stringify(form.sites[i])) : {}
  edit.domainRows = (s.domains || []).map(d => d)
  edit.name = s.name || ''
  edit.comment = s.comment || ''
  if (!edit.domainRows.length) edit.domainRows.push('')
  edit.upstreamRows = (s.upstream?.nodes || []).map(n => {
    let proto = 'http', rest = n.address || '', ip = rest, port = 80
    const m = String(n.address || '').match(/^(https?):\/\/(.+)$/)
    if (m) { proto = m[1]; rest = m[2] }
    const hi = rest.lastIndexOf(':')
    if (hi > 0) { ip = rest.slice(0, hi); const p = parseInt(rest.slice(hi + 1), 10); if (p > 0) port = p }
    return { proto, ip, port, weight: n.weight || 1 }
  })
  if (!edit.upstreamRows.length) edit.upstreamRows.push({ proto: 'http', ip: '', port: 80, weight: 1 })
  edit.algorithm = s.upstream?.algorithm || 'wrr'
  edit.sniForward = !!s.upstream?.sni_forward
  edit.verifyTls = !!s.upstream?.verify_tls
  edit.mode = s.mode || 'intercept'
  edit.redirect_to_https = i >= 0 ? !!s.redirect_to_https : true
  edit.protocol = i >= 0 && !s.tls_cert && !s.acme && !s.redirect_to_https ? 'http' : 'https'
  edit.http2Enabled = s.http2_enabled === undefined ? true : !!s.http2_enabled
  // 证书来源识别:acme / 已上传(路径命中证书库) / PEM / 无;新站点默认 ACME
  edit.tlsSource = i >= 0 ? (s.acme ? 'acme' : (s.tls_cert ? (uploads.value.some(u => u.cert_path === s.tls_cert) ? 'uploaded' : 'file') : 'none')) : 'acme'
  edit.uploadedName = i >= 0 ? (uploads.value.find(u => u.cert_path === s.tls_cert)?.name || '') : ''
  edit.tls_cert = s.tls_cert || ''
  edit.tls_key = s.tls_key || ''
  edit.tls_profile = s.tls_profile || 'moderate'
  loadUploads()
  edit.wafEnabled = wafOn(s)
  const sec0 = s.security || {}
  // 新建站点默认开启语义检测；编辑已有站点保持其现值
  edit.semanticEnabled = i < 0 ? true : !!sec0.semantic?.enabled
  edit.captchaEnabled = !!sec0.captcha?.enabled
  edit.captchaSecret = sec0.captcha?.secret || ''
  edit.rlEnabled = !!sec0.ratelimit
  edit.rlRequests = sec0.ratelimit?.requests || 100
  edit.rlWindow = sec0.ratelimit?.window_sec || 60
  edit.rlAction = sec0.ratelimit?.action || 'throttle'
  edit.geoEnabled = !!sec0.geo?.enabled
  edit.geoMode = (sec0.geo?.whitelist?.length ? 'whitelist' : 'blacklist')
  edit.geoCountries = sec0.geo?.whitelist?.length ? (sec0.geo.whitelist || []) : (sec0.geo?.blacklist || [])
  edit.geoTrusted = !!sec0.geo?.whitelist_trusted
  edit.authEnabled = !!sec0.auth
  edit.authUser = sec0.auth?.users?.[0]?.username || ''
  edit.authPass = ''
  edit.respEnabled = !!sec0.resp_filter?.enabled
  edit.respPresets = sec0.resp_filter?.presets || ['phone', 'idcard', 'secret']
  edit.dynamicEnabled = !!sec0.dynamic?.enabled
  edit.aclBlack = sec0.acl?.blacklist || []
  edit.aclWhite = sec0.acl?.whitelist || []
  edit.healthEnabled = !!s.health?.enabled
  edit.healthPath = s.health?.path || '/'
  drawer.value = true
}

function applyEdit() {
  // 域名行支持中/英文逗号分隔的批量录入：拆分、去空白、去重，杜绝
  // "a.com,b.com" 被存成单一字面域名导致的数据面 no_site 403。
  const seen = new Set()
  const domains = []
  for (const row of edit.domainRows) {
    for (const piece of String(row || '').split(/[,，]/)) {
      const d = piece.trim()
      if (!d) continue
      if (seen.has(d)) continue
      seen.add(d)
      domains.push(d)
    }
  }
  const nodes = []
  for (const u of edit.upstreamRows) {
    const ip = String(u.ip || '').trim()
    const port = Number(u.port) || 0
    if (!ip || port < 1 || port > 65535) continue
    nodes.push({ address: `${u.proto || 'http'}://${ip}:${port}`, weight: u.weight || 1 })
  }
  if (domains.length === 0) { ElMessage.error('至少需要一个域名'); return null }
  if (nodes.length === 0) { ElMessage.error('至少需要一个完整的上游服务器（协议/IP/端口）'); return null }
  const s = {
    name: (edit.name || '').trim(),
    domains,
    mode: edit.mode,
    upstream: { nodes, algorithm: edit.algorithm || 'wrr' }
  }
  if (edit.sniForward) s.upstream.sni_forward = true
  if (edit.verifyTls) s.upstream.verify_tls = true
  if ((edit.comment || '').trim()) s.comment = edit.comment.trim()
  if (edit.protocol === 'https') {
    if (edit.redirect_to_https) s.redirect_to_https = true
    if (!edit.http2Enabled) s.http2_enabled = false
    if (edit.tlsSource === 'file') { s.tls_cert = edit.tls_cert; s.tls_key = edit.tls_key }
    s.tls_profile = edit.tls_profile || 'moderate'
    if (edit.tlsSource === 'uploaded') {
      if (!edit.uploadedName) {
        ElMessage.error('请选择已上传证书')
        return null
      }
      const found = uploads.value.find(u => u.name === edit.uploadedName)
      if (!found) {
        ElMessage.error('证书不存在，请先在证书管理上传')
        return null
      }
      s.tls_cert = found.cert_path
      s.tls_key = found.key_path
    }
    if (edit.tlsSource === 'acme') {
      // 空邮箱 = 使用系统设置中的 ACME 全局邮箱（服务端兜底）
      s.acme = {}
    }
  }
  s.waf = { enabled: !!edit.wafEnabled }
  const sec0 = {}
  if (edit.semanticEnabled) sec0.semantic = { enabled: true }
  if (edit.captchaEnabled) {
    sec0.captcha = { enabled: true }
    if (edit.captchaSecret) sec0.captcha.secret = edit.captchaSecret
  }
  if (edit.rlEnabled) sec0.ratelimit = { requests: edit.rlRequests, window_sec: edit.rlWindow, action: edit.rlAction }
  if (edit.geoEnabled) {
    sec0.geo = { enabled: true }
    if (edit.geoMode === 'whitelist') {
      sec0.geo.whitelist = [...edit.geoCountries]
      if (edit.geoTrusted) sec0.geo.whitelist_trusted = true
    } else {
      sec0.geo.blacklist = [...edit.geoCountries]
    }
  }
  if (edit.authEnabled) {
    const username = (edit.authUser || '').trim()
    if (!username) { ElMessage.error('启用站点认证需填写用户名'); return null }
    if (edit.authPass) {
      if (edit.authPass.length < 8) { ElMessage.error('站点认证密码至少 8 位'); return null }
      sec0.auth = { users: [{ username, password: edit.authPass }] }
    } else {
      const prev = editIndex.value >= 0 ? form.sites[editIndex.value] : null
      const prevAuth = prev && prev.security && prev.security.auth
      if (!prevAuth || !prevAuth.users || !prevAuth.users.length) {
        ElMessage.error('启用站点认证需填写密码（至少 8 位）'); return null
      }
      sec0.auth = prevAuth
    }
  }
  if (edit.respEnabled) sec0.resp_filter = { enabled: true, presets: edit.respPresets }
  if (edit.dynamicEnabled) sec0.dynamic = { enabled: true }
  if (edit.aclBlack.length || edit.aclWhite.length) sec0.acl = { blacklist: edit.aclBlack, whitelist: edit.aclWhite }
  if (Object.keys(sec0).length) s.security = sec0
  if (edit.healthEnabled) s.health = { enabled: true, path: edit.healthPath || '/' }

  if (editIndex.value >= 0) form.sites[editIndex.value] = s
  else {
    form.sites.push(s)
    sel.value = form.sites.length - 1
  }
  dirty.value = true
  drawer.value = false
  jsonText.value = JSON.stringify(formSitesConfig(), null, 2)
  return s
}

async function saveAndPublishSite() {
  // applyEdit shows the validation ElMessage errors itself; capture the
  // resulting site by re-running the draft update it performs.
  const before = JSON.stringify(form.sites)
  const s = applyEdit()
  if (!s) return
  publishingSite.value = true
  try {
    const d = await post('/api/config/site/publish', {
      domain: (s.domains && s.domains[0]) || '',
      note: 'console site publish: ' + ((s.domains && s.domains[0]) || ''),
      site: s,
    })
    ElMessage.success('站点已发布，版本 ' + d.revision + '，已热生效')
  } catch (e) {
    // Roll the draft back so the stale entry is not mistaken for live config.
    form.sites = JSON.parse(before)
    ElMessage.error('站点发布失败：' + e.message)
    return
  } finally {
    publishingSite.value = false
  }
  await load()
}

function formSitesConfig() {
  const c = JSON.parse(JSON.stringify(form))
  delete c._raw
  return c
}

function removeSite(i) {
  ElMessageBox.confirm('删除站点 ' + (form.sites[i].domains.join(', ')) + '？删除后需点击「发布配置」才会生效。', '确认', { type: 'warning' })
    .then(() => { form.sites.splice(i, 1); dirty.value = true })
    .catch(() => {})
}

// 证书页「引用站点」tag 跳转携带 /sites?site=<domain>：初始化与后续变化
// 均同步到站点筛选框（复用现有筛选，无新增 UI）。
function applySiteQuery() {
  const v = route.query.site
  siteFilter.value = typeof v === 'string' ? v : ''
}
watch(() => route.query.site, applySiteQuery)

onMounted(() => { applySiteQuery(); load() })
</script>

<style scoped>
.km-site-list .site-item { padding: 11px 14px; border-bottom: 1px solid var(--km-line-soft); cursor: pointer; }
.km-site-list .site-item:last-child { border-bottom: none; }
.km-site-list .site-item:hover { background: var(--km-panel-2); }
.km-site-list .site-item.sel { background: var(--km-nav-grad); }
.km-site-list .domain { font-size: 13.5px; font-weight: 600; color: var(--km-txt); display: flex; align-items: center; gap: 8px; }
.km-site-list .meta { font-size: 11.5px; color: var(--km-txt-3); margin-top: 4px; display: flex; gap: 8px; flex-wrap: wrap; }
</style>
