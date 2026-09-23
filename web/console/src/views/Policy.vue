<template>
  <div>
    <div class="km-toolbar">
      <el-alert type="info" :closable="false" show-icon style="flex:1"
                title="策略保存即发布为新配置版本并热生效；CRS 阈值、微引擎规则与自定义规则对所有开启 WAF 的站点生效" />
      <el-tag effect="plain" type="success" class="km-tag">● 规则 revision #{{ rev }} 已发布 · 热加载生效</el-tag>
    </div>

    <div style="display:flex;gap:16px;align-items:flex-start">
      <!-- 左栏二级菜单（复用 Settings.vue .km-set-nav 三件套） -->
      <el-card shadow="never" class="km-set-nav" :body-style="{ padding: '8px' }">
        <div v-for="t in tabs" :key="t.id" class="item" :class="{ on: tab === t.id }" @click="tab = t.id">
          <span>{{ t.icon }} {{ t.name }}</span>
        </div>
      </el-card>

      <div style="flex:1;min-width:0">
        <!-- ① CRS 异常评分阈值 -->
        <template v-if="tab === 'thresholds'">
          <el-card shadow="never">
            <div class="km-title">CRS 异常评分阈值</div>
            <el-form label-width="220px" label-position="left">
              <el-form-item label="入站异常评分阈值（inbound）">
                <el-input-number v-model="p.inbound" :min="1" :max="100" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">默认 5；调高减少误拦，调低更严格</span>
              </el-form-item>
              <el-form-item label="出站异常评分阈值（outbound）">
                <el-input-number v-model="p.outbound" :min="1" :max="100" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">默认 4</span>
              </el-form-item>
            </el-form>
            <div style="text-align:right">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveThresholds">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

        <!-- ② 黑白名单管理 -->
        <template v-else-if="tab === 'acl'">
          <el-card shadow="never">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
              <div class="km-title" style="margin:0">黑白名单管理（全局 · 先于站点 ACL）</div>
              <div class="km-seg" style="margin-left:auto">
                <span class="seg-item" :class="{ on: blTab === 'black' }" @click="blTab = 'black'">黑名单（{{ p.gBlack.filter(Boolean).length }}）</span>
                <span class="seg-item" :class="{ on: blTab === 'white' }" @click="blTab = 'white'">白名单（{{ p.gWhite.filter(Boolean).length }}）</span>
              </div>
            </div>
            <div class="km-dim" style="font-size:12px;margin-bottom:10px" v-if="blTab === 'black'">黑名单命中即拦截（403）。</div>
            <div class="km-dim" style="font-size:12px;margin-bottom:10px" v-else>白名单在 CRS 之前短路放行（信任来源）；支持从攻击日志一键加白，加白记录见「微引擎规则防护」页签。</div>
            <div v-for="row in pagedBL" :key="row.i" style="display:flex;gap:8px;margin-bottom:6px">
              <el-input v-model="blList[row.i]" placeholder="IP/CIDR/group:名称" class="km-mono" />
              <el-button link type="danger" @click="blList.splice(row.i, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="addBlankBL"><el-icon><Plus /></el-icon>&nbsp;新增</el-button>
            <div v-if="blList.length > blPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
              <span class="km-dim" style="font-size:12px">每页</span>
              <el-select v-model="blPageSize" size="small" style="width:84px"
                         @change="() => { const max = Math.max(1, Math.ceil(blList.length / blPageSize)); if (blPage > max) blPage = max }">
                <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
              </el-select>
              <el-pagination layout="prev, pager, next" small background :total="blList.length"
                             :page-size="blPageSize" :current-page="blPage"
                             @current-change="p => blPage = p" />
            </div>
            <div style="text-align:right;margin-top:12px">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveACL">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

        <!-- ③ IP 组管理 -->
        <template v-else-if="tab === 'ipgroups'">
          <el-card shadow="never">
            <div style="display:flex;align-items:center;gap:10px">
              <div class="km-title" style="margin:0">IP 组管理（手动维护 / 订阅，ACL 中以 group:名称 引用）</div>
              <el-button v-if="can('operator')" size="small" type="primary" style="margin-left:auto" @click="openGroup(-1)"><el-icon><Plus /></el-icon>&nbsp;新建 IP 组</el-button>
            </div>
            <el-table :data="pagedGroups" size="small" style="margin-top:10px">
              <el-table-column prop="name" label="组名" width="140" class-name="km-mono" />
              <el-table-column label="类型" width="90">
                <template #default="{ row }">
                  <el-tag size="small" effect="plain" :type="row.type === 'manual' ? 'primary' : 'success'" class="km-tag">{{ row.type === 'manual' ? '手动' : '订阅' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="来源 / 成员" show-overflow-tooltip>
                <template #default="{ row }">
                  {{ row.type === 'manual' ? ((row.members || []).join(', ') || '-') : (row.url || row.file) }}
                </template>
              </el-table-column>
              <el-table-column prop="entries" label="成员" width="80" />
              <el-table-column label="预览" show-overflow-tooltip>
                <template #default="{ row }">{{ (row.sample || []).join(', ') }}</template>
              </el-table-column>
              <el-table-column label="操作" width="150">
                <template #default="{ row }">
                  <el-button v-if="can('operator') && row.type === 'manual'" link type="primary" size="small" @click="openGroup(ipGroups.indexOf(row))">编辑</el-button>
                  <el-button v-if="can('operator') && row.type !== 'manual'" link type="primary" size="small" @click="refreshGroup(row.name)">刷新</el-button>
                  <el-button v-if="can('operator')" link type="danger" size="small" @click="delGroup(row.name)">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
            <div v-if="ipGroups.length > grpPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
              <span class="km-dim" style="font-size:12px">每页</span>
              <el-select v-model="grpPageSize" size="small" style="width:84px"
                         @change="() => { const max = Math.max(1, Math.ceil(ipGroups.length / grpPageSize)); if (grpPage > max) grpPage = max }">
                <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
              </el-select>
              <el-pagination layout="prev, pager, next" small background :total="ipGroups.length"
                             :page-size="grpPageSize" :current-page="grpPage"
                             @current-change="p => grpPage = p" />
            </div>
            <div class="km-muted" style="font-size:11.5px;margin-top:8px">手动组发布后立即生效；订阅组按间隔自动拉取，被 ACL 引用中的组删除前请先移除引用</div>
          </el-card>
        </template>

        <!-- ④ 微引擎规则防护 + 规则命中 TOP -->
        <template v-else-if="tab === 'matchers'">
          <el-card shadow="never" style="margin-bottom:16px">
            <div class="km-title" style="margin:0 0 4px">CRS 检测分类全局默认</div>
            <div class="km-dim" style="font-size:12px;margin-bottom:12px">
              新建站点与未单独配置分类的站点按此默认装载 CRS 检测类别；站点可在「站点管理」页单独覆盖
            </div>
            <div class="cat-grid">
              <div v-for="c in CRS_CATEGORIES" :key="c.id" class="cat-item">
                <span class="cat-label">{{ c.label }}</span>
                <el-switch v-model="wafCats[c.id]" size="small" />
              </div>
            </div>
            <div style="text-align:right;margin-top:12px">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveWafCategories">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>

          <el-alert v-if="legacyWhitelist.length" type="warning" :closable="false" style="margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
              <span>发现 {{ legacyWhitelist.length }} 条旧版误报加白记录（exception 模式），可一键迁移为微引擎放行规则</span>
              <el-button size="small" type="primary" :loading="migrating" @click="migrateWhitelist">一键迁移</el-button>
              <el-button size="small" @click="dismissMigration">忽略</el-button>
            </div>
          </el-alert>

          <el-card shadow="never" style="margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
              <div class="km-title" style="margin:0">规则命中 TOP</div>
              <el-select v-model="ruleStatsHours" size="small" style="width:110px">
                <el-option v-for="h in [1, 6, 24, 72, 168, 720]" :key="h" :label="h + ' 小时'" :value="h" />
              </el-select>
              <span class="km-dim" style="font-size:12px">窗口内共 {{ ruleStats.total.toLocaleString() }} 次规则命中（攻击口径）· 右侧为占总命中百分比 · 点击规则跳转日志页</span>
            </div>
            <div v-if="ruleStatsLoading" class="km-muted" style="font-size:12px;padding:6px 0">统计加载中…</div>
            <div v-else-if="!ruleStats.items.length" class="km-muted" style="font-size:12px;padding:6px 0">窗口内暂无规则命中</div>
            <div v-for="(it, i) in ruleStats.items" :key="it.rule" class="km-rule-hit" @click="gotoRuleLogs(it.rule)">
              <span class="rank">{{ i + 1 }}</span>
              <span class="rule km-mono" :title="it.rule">{{ it.rule }}</span>
              <el-progress class="bar" :percentage="rulePct(it.count)" :show-text="false" :stroke-width="8" />
              <span class="cnt">{{ it.count.toLocaleString() }}</span>
              <span class="pct">{{ totalPct(it.count) }}</span>
            </div>
          </el-card>

          <el-card shadow="never" style="margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
              <div class="km-title" style="margin:0">微引擎规则防护</div>
              <div style="flex:1"></div>
              <el-button v-if="can('operator')" type="primary" size="small" @click="openMatcher(-1)"><el-icon><Plus /></el-icon>&nbsp;新建规则</el-button>
            </div>
            <div class="km-dim" style="font-size:12px;margin-bottom:10px">
              基于来源 / 域名 / 路径 / 方法 / Header 等条件的轻量匹配，先于 CRS 全量规则执行，用于高频场景的快速放行与拦截；支持命中后关闭指定检测模块。
            </div>
            <el-table :data="pagedMatchers" size="small">
              <el-table-column label="规则名称" width="200">
                <template #default="{ row }">
                  <span>{{ row.name }}</span>
                  <el-tag v-if="isWhitelistRule(row)" size="small" type="success" effect="plain" class="km-tag" style="margin-left:6px">误报加白</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="作用站点" width="150" show-overflow-tooltip>
                <template #default="{ row }">{{ (row.sites && row.sites.length) ? row.sites.join(', ') : '全部站点' }}</template>
              </el-table-column>
              <el-table-column label="条件" show-overflow-tooltip>
                <template #default="{ row }">
                  <span class="km-mono" style="font-size:12px">
                    {{ (row.conditions || []).map(c => condLabel(c)).join(row.logic === 'or' ? ' 或 ' : ' 且 ') }}
                  </span>
                </template>
              </el-table-column>
              <el-table-column label="动作" width="110">
                <template #default="{ row }">
                  <el-tag size="small" :type="{ deny: 'danger', allow: 'success', monitor: 'info', disable: 'warning' }[row.action]" effect="dark" class="km-tag">
                    {{ { deny: '拦截', allow: '放行(信任)', monitor: '观察', disable: '关闭模块' }[row.action] }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="状态" width="80">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.enabled ? 'success' : 'info'" effect="dark" class="km-tag">{{ row.enabled ? '启用' : '停用' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column width="130">
                <template #default="{ row }">
                  <el-button link type="primary" size="small" @click="openMatcher(matchers.indexOf(row))">编辑</el-button>
                  <el-button link type="danger" size="small" @click="removeMatcher(matchers.indexOf(row))">删除</el-button>
                </template>
              </el-table-column>
            </el-table>
            <div v-if="matchers.length > mPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
              <span class="km-dim" style="font-size:12px">每页</span>
              <el-select v-model="mPageSize" size="small" style="width:84px"
                         @change="() => { const max = Math.max(1, Math.ceil(matchers.length / mPageSize)); if (mPage > max) mPage = max }">
                <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
              </el-select>
              <el-pagination layout="prev, pager, next" small background :total="matchers.length"
                             :page-size="mPageSize" :current-page="mPage"
                             @current-change="p => mPage = p" />
            </div>
          </el-card>

          <el-card shadow="never">
            <div class="km-title" style="margin-bottom:6px">说明</div>
            <div class="km-muted" style="font-size:11.5px">攻击日志页「一键加白」会在此创建名称以「误报加白」开头的放行规则（站点+路径条件，命中后跳过全部检测）；规则可编辑、禁用、删除，与普通微引擎规则一致，变更发布后热生效</div>
          </el-card>
        </template>

        <!-- ⑤ 攻击惩罚 -->
        <template v-else-if="tab === 'penalty'">
          <el-card shadow="never">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
              <div class="km-title" style="margin:0">攻击惩罚（扫描/爆破自动处置）</div>
              <el-switch v-model="p.penalty_enabled" style="margin-left:auto" />
            </div>
            <template v-if="p.penalty_enabled">
              <div class="km-set-row"><div class="grow"><div class="set-name">统计窗口</div><div class="set-desc">窗口内累计同源 IP 的拦截与挑战次数</div></div>
                <el-input-number v-model="p.penalty_window" :min="60" :max="86400" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">秒</span></div>
              <div class="km-set-row"><div class="grow"><div class="set-name">触发阈值</div><div class="set-desc">达到阈值即对该 IP 施加惩罚</div></div>
                <el-input-number v-model="p.penalty_threshold" :min="3" :max="10000" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">次</span></div>
              <div class="km-set-row"><div class="grow"><div class="set-name">惩罚方式</div><div class="set-desc">临时封禁或严格限速</div></div>
                <el-radio-group v-model="p.penalty_action" size="small">
                  <el-radio-button value="deny">临时封禁</el-radio-button>
                  <el-radio-button value="throttle">严格限速</el-radio-button>
                </el-radio-group></div>
              <div class="km-set-row"><div class="grow"><div class="set-name">惩罚时长</div><div class="set-desc">默认 3600（1 小时）</div></div>
                <el-input-number v-model="p.penalty_ban" :min="60" :max="86400" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">秒</span></div>
              <div v-if="p.penalty_action === 'throttle'" class="km-set-row"><div class="grow"><div class="set-name">限速</div><div class="set-desc">惩罚期内超出即 429</div></div>
                <el-input-number v-model="p.penalty_per_min" :min="1" :max="1000" size="small" style="width:130px" /><span class="km-muted" style="font-size:12px">次/分</span></div>
            </template>
            <div class="km-muted" style="font-size:11.5px;margin-top:8px">
              惩罚状态保存在内存中，配置发布或服务重启后清空；命中惩罚的请求以 penalty/engine 记录在攻击日志中
            </div>
            <div style="text-align:right;margin-top:12px">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="savePenalty">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

        <!-- ⑥ 自定义规则 -->
        <template v-else-if="tab === 'custom'">
          <el-card shadow="never">
            <div class="km-title">自定义规则（SecLang，全局，追加在 CRS 之后）</div>
            <el-input v-model="p.customRules" type="textarea" :rows="14" class="km-mono" spellcheck="false"
                      placeholder="# 示例：# 拦截特定 UA&#10;SecRule REQUEST_HEADERS:User-Agent &quot;@contains sqlmap&quot; &quot;id:100001,phase:1,deny,status:403,msg:'block sqlmap'&quot;" />
            <div class="km-dim" style="margin-top:8px;font-size:12px">
              保存时服务端会编译校验，语法错误将拒绝发布并保留旧配置；发布失败信息在发布返回中给出
            </div>
            <div style="text-align:right;margin-top:12px">
              <el-button type="primary" :loading="saving" :disabled="!can('operator')" @click="saveCustom">
                保存并发布（热生效）
              </el-button>
            </div>
          </el-card>
        </template>

        <!-- ⑦ 引擎与规则版本(编译期内嵌只读) -->
        <template v-else-if="tab === 'versions'">
          <el-card shadow="never">
            <div class="km-title" style="margin-bottom:8px">引擎与规则版本</div>
            <div class="ver-grid">
              <div class="ver-item"><div class="ver-k">检测引擎</div><div class="ver-v km-mono">{{ engine.coraza || '-' }}</div><div class="ver-s">上游发布：{{ engine.coraza_release || '-' }} · Go 实现，兼容 ModSecurity SecLang</div></div>
              <div class="ver-item"><div class="ver-k">规则集</div><div class="ver-v km-mono">{{ engine.crs ? 'OWASP CRS ' + engine.crs.replace('v', '') : '-' }}</div><div class="ver-s">上游发布：{{ engine.crs_release || '-' }} · PL1–PL2 · SQLi / XSS / RCE 规则族</div></div>
              <div class="ver-item"><div class="ver-k">运行时</div><div class="ver-v km-mono">{{ engine.go || '-' }}</div><div class="ver-s">上游发布：{{ engine.go_release || '-' }} · 单二进制 · embed UI</div></div>
              <div class="ver-item"><div class="ver-k">GeoIP 库（内置）</div><div class="ver-v km-mono">{{ engine.geoip || '-' }}</div><div class="ver-s">DB-IP Lite{{ engine.geoip_build ? ' · ' + engine.geoip_build + ' 构建' : '' }} · CC BY 4.0</div></div>
              <div class="ver-item"><div class="ver-k">控制台版本</div><div class="ver-v km-mono">{{ version || '-' }}</div><div class="ver-s">发布物与引擎同版本构建</div></div>
            </div>
          </el-card>
        </template>

        <!-- ⑧ 检测引擎启用情况(站点级聚合) -->
        <template v-else-if="tab === 'engines'">
          <el-card shadow="never">
            <div class="km-title" style="margin-bottom:8px">检测引擎启用情况（按站点聚合）</div>
            <div class="km-config-row" v-for="e in engineStats" :key="e.name" style="padding:8px 0">
              <div><div class="name" style="font-size:13px">{{ e.name }}</div><div class="desc" style="font-size:11.5px">{{ e.desc }}</div></div>
              <div class="right">
                <span class="val">{{ e.count }} / {{ totalSites }} 站点</span>
                <el-progress type="circle" :percentage="totalSites ? Math.round(e.count * 100 / totalSites) : 0" :width="34" :stroke-width="4" :show-text="false" />
              </div>
            </div>
            <div class="km-muted" style="font-size:11.5px;margin-top:6px">各引擎在「站点防护」中按站点独立开关</div>
          </el-card>
        </template>
      </div>
    </div>

    <!-- 条件组合规则构建器 -->
    <el-dialog v-model="mDlg" :title="mEditIndex < 0 ? '新建微引擎规则' : '编辑规则 · ' + m.name" width="720px">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="规则名称"><el-input v-model="m.name" placeholder="如 封禁扫描器 UA" /></el-form-item>
        <el-form-item label="匹配动作">
          <el-radio-group v-model="m.action">
            <el-radio-button value="deny">拦截</el-radio-button>
            <el-radio-button value="allow">放行（信任）</el-radio-button>
            <el-radio-button value="monitor">仅观察</el-radio-button>
            <el-radio-button value="disable">关闭检测模块</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="m.action === 'disable'" label="关闭模块">
          <el-checkbox-group v-model="m.disable_stages">
            <el-checkbox value="coraza">CRS 签名检测</el-checkbox>
            <el-checkbox value="semantic">语义检测</el-checkbox>
            <el-checkbox value="botdetect">BOT 识别</el-checkbox>
            <el-checkbox value="ratelimit">CC 限流</el-checkbox>
            <el-checkbox value="captcha">人机验证</el-checkbox>
          </el-checkbox-group>
          <div class="km-dim" style="font-size:12px;margin-top:4px">命中该规则后，作用站点的这些检测模块被关闭（重新发布配置或删除规则后恢复）；访问控制类模块不可关闭</div>
        </el-form-item>
        <el-form-item label="作用站点">
          <el-select v-model="m.sites" multiple filterable allow-create default-first-option
                     placeholder="留空 = 全部站点" style="width:100%">
            <el-option v-for="d in siteOptions" :key="d" :value="d" :label="d" />
          </el-select>
        </el-form-item>
        <el-form-item label="条件逻辑">
          <el-radio-group v-model="m.logic">
            <el-radio-button value="and">全部满足（AND）</el-radio-button>
            <el-radio-button value="or">任一满足（OR）</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="条件列表">
          <div style="width:100%">
            <div v-for="(c, i) in m.conditions" :key="i" style="display:flex;gap:6px;margin-bottom:6px">
              <el-select v-model="c.field" style="width:190px" filterable allow-create default-first-option>
                <el-option-group label="基础字段">
                  <el-option label="来源 IP" value="client_ip" /><el-option label="域名" value="hostname" />
                  <el-option label="路径" value="path" /><el-option label="完整 URI" value="uri" />
                  <el-option label="请求方法" value="method" /><el-option label="User-Agent" value="user_agent" />
                  <el-option label="Referer" value="referer" /><el-option label="请求体" value="body" />
                </el-option-group>
                <el-option-group label="组合字段">
                  <el-option label="请求头（header:名）" value="header:" /><el-option label="查询参数（query:名）" value="query:" />
                  <el-option label="Cookie（cookie:名）" value="cookie:" />
                </el-option-group>
              </el-select>
              <el-select v-model="c.op" style="width:130px">
                <el-option label="等于" value="eq" /><el-option label="不等于" value="neq" />
                <el-option label="包含" value="contains" /><el-option label="不包含" value="not_contains" />
                <el-option label="前缀" value="prefix" /><el-option label="后缀" value="suffix" />
                <el-option label="正则" value="regex" /><el-option label="CIDR" value="cidr" />
                <el-option label="属于列表" value="in" />
              </el-select>
              <el-input v-model="c.value" placeholder="值" style="flex:1" class="km-mono" />
              <el-button link type="danger" @click="m.conditions.splice(i, 1)"><el-icon><Delete /></el-icon></el-button>
            </div>
            <el-button size="small" @click="m.conditions.push({ field: 'client_ip', op: 'contains', value: '' })">
              <el-icon><Plus /></el-icon>&nbsp;添加条件
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="备注"><el-input v-model="m.comment" /></el-form-item>
        <el-form-item label="启用"><el-switch v-model="m.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="mDlg = false">取消</el-button>
        <el-button type="primary" :loading="savingMatcher" @click="saveMatcher">保存并发布</el-button>
      </template>
    </el-dialog>

    <!-- IP 组新建/编辑弹窗(手动成员 或 订阅源) -->
    <el-dialog v-model="gDlg" :title="gEditName ? '编辑 IP 组 · ' + gEditName : '新建 IP 组'" width="560px">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="组名">
          <el-input v-model="g.name" placeholder="如 grp-office-cn" class="km-mono" :disabled="!!gEditName" />
        </el-form-item>
        <el-form-item label="维护方式">
          <el-radio-group v-model="g.mode">
            <el-radio-button value="manual">手动维护</el-radio-button>
            <el-radio-button value="subscription">订阅源</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="g.mode === 'manual'" label="成员列表">
          <el-input v-model="g.members" type="textarea" :rows="7" class="km-mono" spellcheck="false"
                    placeholder="每行一个 IP 或 CIDR，如&#10;10.0.0.0/8&#10;192.168.1.5&#10;# 注释行会被忽略" />
        </el-form-item>
        <template v-if="g.mode === 'subscription'">
          <el-form-item label="来源类型">
            <el-radio-group v-model="g.srcType">
              <el-radio-button value="url">URL 订阅</el-radio-button>
              <el-radio-button value="file">本地文件</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="来源地址">
            <el-input v-model="g.source" :placeholder="g.srcType === 'url' ? 'https://example.com/ip-list.txt' : '/path/to/list.txt'" class="km-mono" />
          </el-form-item>
          <el-form-item label="刷新间隔">
            <el-input-number v-model="g.interval" :min="10" :max="1440" size="small" style="width:130px" />
            <span class="km-dim" style="margin-left:8px;font-size:12px">分钟（默认 60）</span>
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="gDlg = false">取消</el-button>
        <el-button type="primary" :loading="gSaving" @click="saveGroup">保存并发布</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, can, del, post } from '../api'

const router = useRouter()

// 二级菜单：8 个策略模块页签（样式复用 Settings.vue 的 .km-set-nav 三件套）
const tabs = [
  { id: 'thresholds', name: 'CRS 异常评分阈值', icon: '🎚️' },
  { id: 'acl', name: '黑白名单管理', icon: '🛡️' },
  { id: 'ipgroups', name: 'IP 组管理', icon: '👥' },
  { id: 'matchers', name: '微引擎规则防护', icon: '🧩' },
  { id: 'penalty', name: '攻击惩罚', icon: '⛔' },
  { id: 'custom', name: '自定义规则', icon: '📜' },
  { id: 'versions', name: '引擎与规则版本', icon: 'ℹ️' },
  { id: 'engines', name: '检测引擎启用情况', icon: '✅' },
]
const tab = ref('thresholds')

// CRS 10 个检测类别：固定顺序与中英文标签，与 Sites 页站点级子面板、后端规则类别一致
const CRS_CATEGORIES = [
  { id: 'sqli', label: 'SQL 注入' },
  { id: 'xss', label: 'XSS 跨站' },
  { id: 'rce', label: '远程代码执行' },
  { id: 'lfi', label: '本地文件包含' },
  { id: 'rfi', label: '远程文件包含' },
  { id: 'php', label: 'PHP 攻击' },
  { id: 'generic', label: '通用攻击' },
  { id: 'session', label: '会话固定' },
  { id: 'java', label: 'Java 攻击' },
  { id: 'scanner', label: '扫描器' },
]

const FIELD_LABELS = {
  client_ip: '来源 IP', hostname: '域名', path: '路径', uri: '完整 URI', method: '请求方法',
  user_agent: 'User-Agent', referer: 'Referer', body: '请求体',
  'header:': '请求头', 'query:': '查询参数', 'cookie:': 'Cookie'
}
const OP_LABELS = { eq: '=', neq: '≠', contains: '包含', not_contains: '不包含', prefix: '前缀',
  suffix: '后缀', regex: '正则', cidr: 'CIDR', in: '属于' }
function condLabel(c) {
  const f = FIELD_LABELS[c.field] || (c.field.startsWith('header:') ? '头 ' + c.field.slice(7)
    : c.field.startsWith('query:') ? '参数 ' + c.field.slice(6) : c.field.startsWith('cookie:') ? 'Cookie ' + c.field.slice(7) : c.field)
  return `${f} ${OP_LABELS[c.op] || c.op} ${c.value}`
}

const saving = ref(false)
// 旧版误报加白记录（exception 模式）：仅用于迁移检测，不再单独展示。
const legacyWhitelist = ref([])
const migrating = ref(false)
const migrationDismissed = ref(false)
const ipGroups = ref([])
const matchers = ref([])
const siteOptions = ref([])
const blTab = ref('black')
const rev = ref(0)
const version = ref('')
const engine = ref({})
const mDlg = ref(false)
const mEditIndex = ref(-1)
const savingMatcher = ref(false)
const m = reactive({ name: '', action: 'deny', logic: 'and', sites: [], enabled: true, comment: '', disable_stages: [], conditions: [{ field: 'client_ip', op: 'contains', value: '' }] })
const p = reactive({
  inbound: 5, outbound: 4,
  gBlack: [], gWhite: [],
  customRules: '',
  penalty_enabled: false, penalty_window: 600, penalty_threshold: 20, penalty_ban: 3600,
  penalty_action: 'deny', penalty_per_min: 10
})

// CRS 检测分类全局默认开关状态（policy.waf_categories；nil = 全部启用）
const wafCats = reactive({})

// 站点级引擎启用统计(读当前配置聚合)
const totalSites = ref(0)
const engineStats = ref([])
function aggregateEngines(cfg) {
  const sites = cfg.sites || []
  totalSites.value = sites.length
  const count = fn => sites.filter(fn).length
  engineStats.value = [
    { name: '签名检测（CRS）', desc: 'Coraza + OWASP CRS 请求体检测', count: count(s => !s.waf || s.waf?.enabled !== false) },
    { name: '语义检测', desc: 'libinjection SQLi / XSS', count: count(s => s.security?.semantic?.enabled) },
    { name: 'BOT 识别', desc: '指纹分类观察 / 拦截 / 挑战', count: count(s => s.security?.bot_detect?.enabled) },
    { name: 'CC 限流', desc: '固定窗口频率限制', count: count(s => s.security?.ratelimit) },
    { name: 'GeoIP 封禁', desc: '国家黑白名单', count: count(s => s.security?.geo?.enabled) },
    { name: '人机验证', desc: '滑块验证码 + JS 质询', count: count(s => s.security?.captcha?.enabled) },
    { name: '响应脱敏', desc: '手机号 / 身份证 / 密钥', count: count(s => s.security?.resp_filter?.enabled) },
  ]
}

async function load() {
  const d = await api('/api/config')
  const c = d.config
  rev.value = d.revision
  siteOptions.value = [...new Set((c.sites || []).flatMap(s => s.domains || []))]
  p.inbound = c.policy?.inbound_threshold || 5
  p.outbound = c.policy?.outbound_threshold || 4
  p.gBlack = [...(c.policy?.global_acl?.blacklist || [])]
  p.gWhite = [...(c.policy?.global_acl?.whitelist || [])]
  p.customRules = c.policy?.custom_rules || ''
  p.penalty_enabled = !!c.policy?.penalty?.enabled
  p.penalty_window = c.policy?.penalty?.window_sec || 600
  p.penalty_threshold = c.policy?.penalty?.threshold || 20
  p.penalty_ban = c.policy?.penalty?.ban_sec || 3600
  p.penalty_action = c.policy?.penalty?.action || 'deny'
  p.penalty_per_min = c.policy?.penalty?.throttle_per_min || 10
  const wafCatCfg = c.policy?.waf_categories
  const activeCats = Array.isArray(wafCatCfg) ? wafCatCfg : CRS_CATEGORIES.map(x => x.id)
  for (const x of CRS_CATEGORIES) wafCats[x.id] = activeCats.includes(x.id)
  matchers.value = c.policy?.matchers || []
  aggregateEngines(c)
  try { legacyWhitelist.value = migrationDismissed.value ? [] : (await api('/api/policy/exceptions') || []) }
  catch (e) { legacyWhitelist.value = [] }
  try { ipGroups.value = await api('/api/ipgroups') } catch (e) { ipGroups.value = [] }
  try {
    const st = await api('/api/status')
    version.value = st.version || ''
    engine.value = st.engine || {}
  } catch (e) { /* version card optional */ }
  loadRuleStats()
}

// ---- 规则命中 TOP 统计卡（GET /api/stats/rules）----
const ruleStats = ref({ total: 0, items: [] })
const ruleStatsHours = ref(24)
const ruleStatsLoading = ref(false)
async function loadRuleStats() {
  ruleStatsLoading.value = true
  try {
    ruleStats.value = await api('/api/stats/rules?hours=' + ruleStatsHours.value + '&limit=10')
  } catch (e) {
    ruleStats.value = { total: 0, items: [] }
  } finally {
    ruleStatsLoading.value = false
  }
}
watch(ruleStatsHours, loadRuleStats)
function rulePct(count) {
  const max = Math.max(1, ...(ruleStats.value.items || []).map(i => i.count || 0))
  return Math.max(2, Math.round(count * 100 / max))
}
// 占窗口内总命中的百分比（与后端 total 同口径）；total 为 0 时展示占位符
function totalPct(count) {
  const total = ruleStats.value.total || 0
  if (!total) return '-'
  return (count * 100 / total).toFixed(1) + '%'
}
function gotoRuleLogs(rule) {
  router.push('/logs?rule=' + encodeURIComponent(rule))
}

// ---- 列表分页（默认 10，可选 10/20/50/100）----
const blPage = ref(1)
const blPageSize = ref(10)
const blList = computed(() => (blTab.value === 'black' ? p.gBlack : p.gWhite))
const pagedBL = computed(() => {
  const start = (blPage.value - 1) * blPageSize.value
  return blList.value.slice(start, start + blPageSize.value).map((v, k) => ({ v, i: start + k }))
})
watch(blTab, () => { blPage.value = 1 })
function addBlankBL() {
  blList.value.push('')
  blPage.value = Math.max(1, Math.ceil(blList.value.length / blPageSize.value))
}

const grpPage = ref(1)
const grpPageSize = ref(10)
const pagedGroups = computed(() => {
  const start = (grpPage.value - 1) * grpPageSize.value
  return ipGroups.value.slice(start, start + grpPageSize.value)
})

const mPage = ref(1)
const mPageSize = ref(10)
const pagedMatchers = computed(() => {
  const start = (mPage.value - 1) * mPageSize.value
  return matchers.value.slice(start, start + mPageSize.value)
})

// 误报加白来源的微引擎规则：按 Name/Comment 前缀识别（与后端命名约定一致）
function isWhitelistRule(row) {
  return (row.name || '').startsWith('误报加白') || (row.comment || '').startsWith('误报加白')
}

// 一键迁移：逐条转换为 POST /api/policy/whitelist（幂等，重复迁移安全），
// 全部成功后按下标删除旧记录——先删大下标后删小下标，避免删険位移。
async function migrateWhitelist() {
  migrating.value = true
  const items = [...legacyWhitelist.value]
  try {
    for (const it of items) {
      await post('/api/policy/whitelist', {
        site: it.site || '', path: it.path, prefix: !!it.prefix, comment: it.comment || ''
      })
    }
    for (let i = items.length - 1; i >= 0; i--) {
      await del('/api/policy/exceptions/' + i)
    }
    ElMessage.success('已迁移 ' + items.length + ' 条旧版加白记录为微引擎放行规则')
    legacyWhitelist.value = []
    load()
  } catch (e) {
    ElMessage.error('迁移失败：' + e.message)
    load()
  } finally {
    migrating.value = false
  }
}

function dismissMigration() {
  migrationDismissed.value = true
  legacyWhitelist.value = []
}

async function refreshGroup(name) {
  try {
    await post('/api/ipgroups/' + encodeURIComponent(name) + '/refresh')
    ElMessage.success('已刷新')
    load()
  } catch (e) { ElMessage.error(e.message) }
}

// ---- IP 组新建/编辑/删除(手动成员 或 订阅) ----
const gDlg = ref(false)
const gSaving = ref(false)
const gEditName = ref('')
const g = reactive({ name: '', mode: 'manual', members: '', srcType: 'url', source: '', interval: 60 })

function openGroup(idx) {
  gEditName.value = ''
  if (idx >= 0 && ipGroups.value[idx]) {
    const row = ipGroups.value[idx]
    gEditName.value = row.name
    g.name = row.name
    if (row.type === 'manual') {
      g.mode = 'manual'
      g.members = (row.members || []).join('\n')
    } else {
      g.mode = 'subscription'
      g.members = ''
      g.srcType = row.url ? 'url' : 'file'
      g.source = row.url || row.file || ''
      g.interval = row.interval_min || 60
    }
  } else {
    Object.assign(g, { name: '', mode: 'manual', members: '', srcType: 'url', source: '', interval: 60 })
  }
  gDlg.value = true
}

async function saveGroup() {
  const name = (g.name || '').trim()
  if (!name) return ElMessage.error('请填写组名')
  const entry = { name }
  if (g.mode === 'manual') {
    const members = g.members.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'))
    if (!members.length) return ElMessage.error('手动组至少需要一个成员(IP/CIDR)')
    entry.members = members
  } else {
    if (!g.source.trim()) return ElMessage.error('请填写订阅来源')
    if (g.srcType === 'url') entry.url = g.source.trim()
    else entry.file = g.source.trim()
    entry.interval_min = g.interval
  }
  gSaving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.ip_groups = cfg.ip_groups || []
    const at = cfg.ip_groups.findIndex(x => x.name === name)
    if (gEditName.value && at >= 0) cfg.ip_groups[at] = entry
    else if (at >= 0) cfg.ip_groups[at] = entry
    else cfg.ip_groups.push(entry)
    const r = await post('/api/config/publish', { note: 'ip group: ' + name, config: cfg })
    ElMessage.success('IP 组已发布并热生效（版本 ' + r.revision + '）')
    gDlg.value = false
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
  } finally {
    gSaving.value = false
  }
}

async function delGroup(name) {
  try {
    await ElMessageBox.confirm('删除 IP 组 ' + name + '？引用它的 ACL 条目将失效。', '确认', { type: 'warning' })
  } catch (e) { return }
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.ip_groups = (cfg.ip_groups || []).filter(x => x.name !== name)
    await post('/api/config/publish', { note: 'ip group removed: ' + name, config: cfg })
    ElMessage.success('已删除并热生效')
    load()
  } catch (e) { ElMessage.error(e.message) }
}

// ---- 按 tab 粒度的保存函数：读全量 config → 只改本块字段 → publish，
// spread 保留其余块字段，未展示块字段不丢 ----
async function publish(cfg, note) {
  const r = await post('/api/config/publish', { note, config: cfg })
  ElMessage.success('策略已发布并热生效（版本 ' + r.revision + '）')
  await load()
}

async function saveThresholds() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}), inbound_threshold: p.inbound, outbound_threshold: p.outbound }
    await publish(cfg, 'policy: crs thresholds')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function saveWafCategories() {
  const enabled = CRS_CATEGORIES.map(x => x.id).filter(id => wafCats[id])
  if (!enabled.length) return ElMessage.error('至少启用一个分类')
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}) }
    // 全部启用 = 恢复默认，不写 waf_categories 字段（后端字段缺省即全类别装载）
    if (enabled.length === CRS_CATEGORIES.length) delete cfg.policy.waf_categories
    else cfg.policy.waf_categories = enabled
    await publish(cfg, 'policy: waf categories default')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function saveACL() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    const acl = { blacklist: p.gBlack.filter(Boolean), whitelist: p.gWhite.filter(Boolean) }
    cfg.policy = { ...(cfg.policy || {}) }
    if (acl.blacklist.length || acl.whitelist.length) cfg.policy.global_acl = acl
    else delete cfg.policy.global_acl
    await publish(cfg, 'policy: global acl')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function savePenalty() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}) }
    if (p.penalty_enabled) {
      cfg.policy.penalty = {
        enabled: true,
        window_sec: p.penalty_window,
        threshold: p.penalty_threshold,
        ban_sec: p.penalty_ban,
        action: p.penalty_action,
        throttle_per_min: p.penalty_per_min
      }
    } else {
      delete cfg.policy.penalty
    }
    await publish(cfg, 'policy: penalty')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

async function saveCustom() {
  saving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.policy = { ...(cfg.policy || {}), custom_rules: p.customRules }
    if (!p.customRules) delete cfg.policy.custom_rules
    await publish(cfg, 'policy: custom rules')
  } catch (e) {
    ElMessage.error('发布失败（旧配置保持生效）：' + e.message)
  } finally {
    saving.value = false
  }
}

onMounted(load)

function openMatcher(i) {
  mEditIndex.value = i
  if (i >= 0) {
    const r = matchers.value[i]
    Object.assign(m, JSON.parse(JSON.stringify(r)))
    if (!m.conditions.length) m.conditions.push({ field: 'client_ip', op: 'contains', value: '' })
  } else {
    Object.assign(m, { name: '', action: 'deny', logic: 'and', sites: [], enabled: true, comment: '', disable_stages: [],
      conditions: [{ field: 'client_ip', op: 'contains', value: '' }] })
  }
  mDlg.value = true
}

async function saveMatcher() {
  if (!m.name.trim()) return ElMessage.error('请填写规则名称')
  if (!m.conditions.length) return ElMessage.error('至少一个条件')
  const d = await api('/api/config')
  const cfg = d.config
  cfg.policy = cfg.policy || {}
  cfg.policy.matchers = cfg.policy.matchers || []
  const rule = JSON.parse(JSON.stringify(m))
  rule.logic = rule.logic || 'and'
  if (rule.action !== 'disable' || !Array.isArray(rule.disable_stages) || !rule.disable_stages.length) delete rule.disable_stages
  if (mEditIndex.value >= 0) cfg.policy.matchers[mEditIndex.value] = rule
  else cfg.policy.matchers.push(rule)
  try {
    const r = await post('/api/config/publish', { note: 'matcher rule: ' + rule.name, config: cfg })
    ElMessage.success('规则已发布并热生效（版本 ' + r.revision + '）')
    mDlg.value = false
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
  }
}

async function removeMatcher(i) {
  const d = await api('/api/config')
  const cfg = d.config
  cfg.policy = cfg.policy || {}
  const name = (cfg.policy.matchers[i] || {}).name || ''
  cfg.policy.matchers.splice(i, 1)
  try {
    await post('/api/config/publish', { note: 'matcher removed: ' + name, config: cfg })
    ElMessage.success('已删除并热生效')
    load()
  } catch (e) { ElMessage.error(e.message) }
}
</script>

<style scoped>
.ver-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.ver-item .ver-k { font-size: 11px; color: var(--km-txt-3); }
.ver-item .ver-v { font-size: 15px; font-weight: 700; color: var(--km-txt); margin: 2px 0; }
.ver-item .ver-s { font-size: 11px; color: var(--km-txt-3); }
.km-config-row .name { font-size: 13px; font-weight: 600; color: var(--km-txt); }
.km-config-row .desc { font-size: 11.5px; color: var(--km-txt-3); }
.km-config-row .right { margin-left: auto; display: flex; align-items: center; gap: 10px; }
.km-config-row .val { font-size: 12px; color: var(--km-txt-2); }
.km-rule-hit { display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-radius: 8px; cursor: pointer; }
.km-rule-hit:hover { background: var(--km-panel-2); }
.km-rule-hit .rank { width: 22px; height: 22px; border-radius: 6px; background: var(--km-panel-2); color: var(--km-txt-2); font-size: 12px; font-weight: 700; display: flex; align-items: center; justify-content: center; flex: none; }
.km-rule-hit .rule { flex: none; width: 230px; font-size: 12.5px; color: var(--km-txt); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.km-rule-hit .bar { flex: 1; }
.km-rule-hit .cnt { flex: none; min-width: 64px; text-align: right; font-size: 13px; font-weight: 700; color: var(--km-soft-blue); }
.km-rule-hit .pct { flex: none; min-width: 52px; text-align: right; font-size: 11.5px; color: var(--km-txt-3); }
.cat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; }
.cat-item { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 12px; border-radius: 8px; background: var(--km-panel-2); border: 1px solid var(--km-line-soft); }
.cat-item .cat-label { font-size: 12.5px; color: var(--km-txt-2); }
</style>
