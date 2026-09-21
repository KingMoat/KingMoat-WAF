<template>
  <div>
    <el-alert v-if="storeInfo && !storeInfo.external_configured" type="warning" show-icon :closable="false"
              style="margin-bottom:12px"
              title="攻击日志当前仅存储在本机 SQLite，未接入外部日志存储"
              :description="storageRiskText" />

    <div class="km-toolbar">
      <div class="km-chip" :class="{ on: fType === '' }" @click="fType = ''">全部</div>
      <div v-for="t in chipTypes" :key="t" class="km-chip" :class="{ on: fType === t }" @click="fType = t">{{ t }}</div>
      <el-select v-model="fAction" size="small" style="width:120px" clearable placeholder="动作">
        <el-option label="拦截 blocked" value="blocked" /><el-option label="挑战 challenged" value="challenged" />
        <el-option label="观察 monitor" value="monitor" /><el-option label="跳转 redirected" value="redirected" />
      </el-select>
      <el-input v-model="fIp" size="small" style="width:150px" placeholder="来源 IP（前缀）" clearable class="km-mono" />
      <el-input v-model="fText" size="small" style="width:190px" placeholder="过滤 IP / 路径 / 规则 ID…" clearable />
      <el-date-picker v-model="fRange" type="datetimerange" size="small" style="width:330px"
                      start-placeholder="开始时间" end-placeholder="结束时间" />
      <div class="grow"></div>
      <el-button size="small" @click="exportNdjson"><el-icon><Download /></el-icon>&nbsp;导出 NDJSON</el-button>
      <el-button size="small" type="primary" plain @click="askAI"><el-icon><ChatDotRound /></el-icon>&nbsp;一键问 AI</el-button>
    </div>
    <div style="display:flex;gap:10px;margin-bottom:12px;align-items:center;flex-wrap:wrap">
      <el-input v-model="fSite" size="small" style="width:150px" placeholder="站点过滤" clearable />
      <el-input v-model="fRule" size="small" style="width:180px" placeholder="规则过滤" clearable />
      <el-input v-model="fTrace" size="small" style="width:190px" placeholder="Trace ID 搜索" clearable class="km-mono" />
      <span class="km-dim" style="font-size:12px">共 {{ total.toLocaleString() }} 条 · SQLite 全量检索 · 10s 自动刷新</span>
    </div>

    <el-card shadow="never" :body-style="{ padding: 0 }">
      <el-table :data="viewLogs" size="small" style="cursor:pointer" @row-click="openDetail">
        <el-table-column label="时间" width="160">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="site" label="站点" width="130" show-overflow-tooltip />
        <el-table-column label="等级" width="72">
          <template #default="{ row }">
            <el-tag size="small" :type="levelOf(row).type" effect="dark" class="km-tag">{{ levelOf(row).label }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="attack_type" label="类型" width="110" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tag v-if="row.attack_type" size="small" effect="plain" class="km-tag">{{ row.attack_type }}</el-tag>
            <span v-else class="km-muted">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="client_ip" label="来源 IP" width="130">
          <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.client_ip }}</span></template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="64" class-name="km-mono" />
        <el-table-column label="目标路径" show-overflow-tooltip class-name="km-mono">
          <template #default="{ row }">{{ row.url || row.path }}</template>
        </el-table-column>
        <el-table-column prop="rule" label="命中规则" width="170" show-overflow-tooltip class-name="km-mono" />
        <el-table-column prop="action" label="动作" width="96">
          <template #default="{ row }">
            <el-tag size="small" :type="tagType(row.action)" effect="dark" class="km-tag">{{ actionLabel(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="快照" width="76">
          <template #default="{ row }">
            <el-tag v-if="row.headers || row.body" size="small" effect="plain" type="success" class="km-tag">已捕获</el-tag>
            <span v-else class="km-muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="140">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="openDetail(row)">详情</el-button>
            <el-button v-if="can('operator') && row.action === 'blocked'" link type="warning" size="small"
                       @click.stop="openWhitelist(row)">一键加白</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px">
        <span class="km-muted" style="font-size:12px">显示 {{ viewLogs.length }} 条 / 共 {{ total.toLocaleString() }} 条</span>
        <el-pagination layout="prev, pager, next, sizes" :total="total" :page-size="pageSize" :current-page="page"
                       :page-sizes="[20, 50, 100, 200]" @current-change="p => { page = p; load() }"
                       @size-change="s => { pageSize = s; page = 1; load() }" />
      </div>
    </el-card>

    <el-dialog v-model="wlDlg" title="误报加白（生成微引擎放行规则）" width="500px">
      <el-form label-width="110px" label-position="left">
        <el-form-item label="加白范围">
          <el-radio-group v-model="wl.prefix">
            <el-radio-button :value="false">精确路径</el-radio-button>
            <el-radio-button :value="true">含子路径（前缀）</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="目标">
          <div class="km-mono" style="font-size:12px">
            站点 {{ wl.site }} ｜ 路径 {{ wl.path }}
          </div>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="wl.comment" placeholder="误报原因，便于审计" />
        </el-form-item>
        <el-alert type="warning" :closable="false"
                  title="将创建微引擎放行规则：该站点此路径将跳过全部检测" />
      </el-form>
      <template #footer>
        <el-button @click="wlDlg = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveWhitelist">确认加白并发布</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api, can, post } from '../api'
import { fmtRFC3339, fmtTime } from '../timefmt'

const router = useRouter()
const route = useRoute()
const logs = ref([])
const total = ref(0)
const storeInfo = ref(null)
const page = ref(1)
const pageSize = ref(50)
const fAction = ref('')
const fSite = ref('')
const fRule = ref('')
const fIp = ref('')
const fText = ref('')
const fRange = ref(null)
const fType = ref('')
const fTrace = ref('')
const typeOptions = ref([])
let timer = null
let reloadTimer = null

// chips:常见攻击类型(来自当前结果集与已知类型合并)
const knownTypes = ['SQL注入', 'XSS', '扫描器', 'CC攻击', 'Bot爬虫', '路径穿越', 'GeoIP封禁']
const chipTypes = computed(() => [...new Set([...typeOptions.value, ...knownTypes])].slice(0, 9))

// 等级映射口径:高危 = 拦截且严重类型;中危 = 其余拦截;低危 = 挑战/爬虫类;通知 = 观察/跳转/GeoIP
const HIGH_TYPES = ['SQL注入', 'XSS', '命令执行', '代码执行', '路径穿越', '文件包含', '反序列化', 'SSRF', 'RCE']
function levelOf(row) {
  const t = row.attack_type || ''
  if (row.action === 'monitor' || row.action === 'redirected' || t.includes('GeoIP')) return { label: '通知', type: 'info' }
  if (row.action === 'challenged' || t.includes('Bot') || t.includes('爬虫')) return { label: '低危', type: 'primary' }
  if (row.action === 'blocked' && HIGH_TYPES.some(h => t.includes(h))) return { label: '高危', type: 'danger' }
  if (row.action === 'blocked') return { label: '中危', type: 'warning' }
  return { label: '通知', type: 'info' }
}
function tagType(a) {
  return { blocked: 'danger', challenged: 'warning', monitor: 'info', redirected: 'primary' }[a] || 'info'
}
function actionLabel(a) {
  return { blocked: 'deny 403', challenged: 'challenge', monitor: 'monitor', redirected: 'redirect' }[a] || a
}

// 类型筛选为当前页内过滤(attack_type 派生自规则,不入库)
const viewLogs = computed(() => (fType.value ? logs.value.filter(e => e.attack_type === fType.value) : logs.value))

const storageRiskText = computed(() => {
  if (!storeInfo.value) return ''
  const days = storeInfo.value.retention_days > 0
    ? `仅保留最近 ${storeInfo.value.retention_days} 天`
    : '永久保留在本机'
  const arch = storeInfo.value.archive_enabled
    ? `每日快照归档已开启（本地保留 ${storeInfo.value.archive_retention_days} 天）`
    : '每日快照归档未开启'
  return `日志${days}，${arch}。本机磁盘故障或重装会导致日志丢失，建议在系统设置中启用日志外发（Elasticsearch / Loki / ClickHouse / S3 兼容对象存储 OSS），将日志同步到独立存储。`
})

function baseParams() {
  const p = new URLSearchParams()
  if (fAction.value) p.set('action', fAction.value)
  if (fSite.value) p.set('site', fSite.value)
  if (fRule.value) p.set('rule', fRule.value)
  if (fTrace.value) p.set('trace_id', fTrace.value)
  if (fIp.value) p.set('ip', fIp.value)
  if (fText.value) p.set('q', fText.value)
  if (fRange.value && fRange.value[0] && fRange.value[1]) {
    p.set('since', fmtRFC3339(new Date(fRange.value[0])))
    p.set('until', fmtRFC3339(new Date(fRange.value[1])))
  }
  return p
}

function buildQuery() {
  const p = baseParams()
  p.set('page', page.value)
  p.set('page_size', pageSize.value)
  return '/api/logs?' + p.toString()
}

async function load() {
  try {
    const d = await api(buildQuery())
    if (Array.isArray(d)) {
      logs.value = d
      total.value = d.length
    } else {
      logs.value = d.items || []
      total.value = d.total || 0
    }
    typeOptions.value = [...new Set(logs.value.map(e => e.attack_type).filter(Boolean))]
  } catch (e) { /* 401 handled in api() */ }
}

function exportNdjson() {
  const p = baseParams()
  p.set('limit', '50000')
  window.open('/api/logs/export?' + p.toString(), '_blank')
}

function askAI() {
  const parts = []
  if (fAction.value) parts.push('动作=' + fAction.value)
  if (fSite.value) parts.push('站点=' + fSite.value)
  if (fRule.value) parts.push('规则=' + fRule.value)
  if (fIp.value) parts.push('来源IP前缀=' + fIp.value)
  if (fText.value) parts.push('关键词=' + fText.value)
  if (fType.value) parts.push('攻击类型=' + fType.value)
  const seed = parts.length
    ? `请分析当前攻击日志（筛选条件：${parts.join('；')}）中反映的攻击态势、主要攻击来源与意图，并给出处置建议。`
    : '请总结最近的攻击态势：主要攻击类型、来源分布与建议的处置动作。'
  sessionStorage.setItem('km-ai-seed', seed)
  router.push('/ai')
}

async function loadStorage() {
  try {
    storeInfo.value = await api('/api/logs/storage')
  } catch (e) { /* storage info is advisory only */ }
}

watch([fAction, fSite, fRule, fIp, fText, fRange, fTrace], () => {
  page.value = 1
  clearTimeout(reloadTimer)
  reloadTimer = setTimeout(load, 400)
})

// 策略页「规则命中 TOP」跳转：/logs?rule=<id> 自动填入规则筛选；
// fRule watcher 已带防抖加载，这里只同步筛选值
watch(() => route.query.rule, (v) => {
  const next = typeof v === 'string' ? v : ''
  if (next === fRule.value) return
  fRule.value = next
})

// 风险中心详情跳转：/logs?site=<domain> 自动填入站点筛选
watch(() => route.query.site, (v) => {
  const next = typeof v === 'string' ? v : ''
  if (next === fSite.value) return
  fSite.value = next
})

onMounted(() => {
  const qr = route.query.rule
  if (typeof qr === 'string' && qr) fRule.value = qr
  const qs = route.query.site
  if (typeof qs === 'string' && qs) fSite.value = qs
  load(); loadStorage(); timer = setInterval(load, 10000)
})
onBeforeUnmount(() => { clearInterval(timer); clearTimeout(reloadTimer) })

// ---- 一键加白（误报申诉 → 微引擎放行规则）----
const wlDlg = ref(false)
const saving = ref(false)
const wl = reactive({ site: '', path: '', prefix: false, comment: '' })

function openDetail(row) {
  window.open('/#/log/' + encodeURIComponent(row.trace_id || ''), '_blank')
}

function openWhitelist(row) {
  wl.site = row.site || ''
  wl.path = row.path || '/'
  wl.prefix = false
  wl.comment = ''
  wlDlg.value = true
}

async function saveWhitelist() {
  saving.value = true
  try {
    await post('/api/policy/whitelist', {
      site: wl.site, path: wl.path, prefix: wl.prefix,
      comment: wl.comment
    })
    ElMessage.success('已创建微引擎放行规则，可在策略管理 → 微引擎规则防护中管理')
    wlDlg.value = false
    load()
  } catch (e) {
    ElMessage.error('加白失败：' + e.message)
  } finally {
    saving.value = false
  }
}
</script>
