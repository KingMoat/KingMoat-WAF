<template>
  <div>
    <div class="km-toolbar">
      <el-alert type="info" :closable="false" show-icon style="flex:1"
                title="风险中心：对 API 资产与流量的专项风险评估（observe-only，仅记录不阻断，建议人工复核）"
                description="覆盖敏感数据暴露 / 未授权访问 / 登录爆破 / 影子 API / 僵尸 API / 管理面暴露 / 明文敏感参数。" />
      <el-button v-if="can('operator')" type="primary" @click="scan" :loading="scanning">立即扫描</el-button>
    </div>

    <!-- 风险项总览卡 -->
    <div class="risk-grid" style="margin-bottom:16px">
      <el-card v-for="c in riskCards" :key="c.name" shadow="never" class="km-risk-card"
               :body-style="{ padding: '14px 16px' }">
        <div class="rid" :style="{ color: c.color }">{{ c.label }}</div>
        <div class="rcount" :style="{ color: c.count ? c.color : 'var(--km-txt-3)' }">{{ c.count }}</div>
        <div class="rdesc">{{ c.desc }}</div>
      </el-card>
    </div>

    <el-card shadow="never" :body-style="{ padding: 0 }">
      <div class="km-card-head"><span class="km-card-title">风险事件明细</span></div>
      <el-table :data="risks" size="small" highlight-current-row @row-click="openDetail" style="cursor:pointer">
        <el-table-column prop="kind" label="风险项" width="180">
          <template #default="{ row }">{{ kindLabel(row.kind) }}</template>
        </el-table-column>
        <el-table-column prop="site" label="站点" width="170" show-overflow-tooltip>
          <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.site || '-' }}</span></template>
        </el-table-column>
        <el-table-column prop="level" label="级别" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="row.level === 'high' ? 'danger' : row.level === 'medium' ? 'warning' : 'info'" effect="dark" class="km-tag">
              {{ levelLabel(row.level) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="count" label="次数" width="70">
          <template #default="{ row }"><span class="km-mono">{{ row.count ? row.count.toLocaleString() : '-' }}</span></template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status === 'open' ? 'warning' : 'success'" effect="dark" class="km-tag">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="证据" show-overflow-tooltip />
        <el-table-column width="240">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="openDetail(row)">详情</el-button>
            <template v-if="can('operator') && row.status === 'open'">
              <el-button link type="success" size="small" @click.stop="setStatus(row, 'resolved')">标记已处理</el-button>
              <el-button link size="small" @click.stop="setStatus(row, 'ignored')">忽略</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 风险详情抽屉 -->
    <el-drawer v-model="detailDlg" :title="detail ? kindLabel(detail.kind) : '风险详情'" size="480px">
      <template v-if="detail">
        <el-descriptions :column="1" border size="small" style="margin-bottom:14px">
          <el-descriptions-item label="风险项">{{ kindLabel(detail.kind) }}</el-descriptions-item>
          <el-descriptions-item label="级别">
            <el-tag size="small" :type="detail.level === 'high' ? 'danger' : detail.level === 'medium' ? 'warning' : 'info'" effect="dark" class="km-tag">{{ levelLabel(detail.level) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="detail.status === 'open' ? 'warning' : 'success'" effect="dark" class="km-tag">{{ statusLabel(detail.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="站点">
            <span class="km-mono">{{ detail.site || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detail.asset_ref" label="关联资产">
            <span class="km-mono">{{ detail.asset_ref }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="发生次数">{{ detail.count ? detail.count.toLocaleString() : '-' }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ fmtTime(detail.created_at) }}</el-descriptions-item>
          <el-descriptions-item label="最近更新">{{ fmtTime(detail.updated_at) }}</el-descriptions-item>
        </el-descriptions>

        <div class="km-title" style="margin-bottom:6px">证据说明</div>
        <div class="km-dim" style="font-size:12.5px;line-height:1.7;white-space:pre-wrap;word-break:break-all;margin-bottom:14px">{{ detail.message }}</div>

        <template v-if="evidenceRows.length">
          <div class="km-title" style="margin-bottom:6px">证据明细</div>
          <el-descriptions :column="1" border size="small" style="margin-bottom:14px">
            <el-descriptions-item v-for="r in evidenceRows" :key="r.k" :label="r.k">
              <span class="km-mono" style="font-size:12px;word-break:break-all">{{ r.v }}</span>
            </el-descriptions-item>
          </el-descriptions>
        </template>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <el-button v-if="detail.site" size="small" type="primary" plain @click="goLogs(detail.site)">查看该站点攻击日志</el-button>
          <template v-if="can('operator') && detail.status === 'open'">
            <el-button size="small" type="success" @click="setStatus(detail, 'resolved'); detail.status = 'resolved'">标记已处理</el-button>
            <el-button size="small" @click="setStatus(detail, 'ignored'); detail.status = 'ignored'">忽略</el-button>
          </template>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, can, post } from '../api'
import { useRouter } from 'vue-router'
import { fmtTime } from '../timefmt'

const router = useRouter()
const risks = ref([])
const scanning = ref(false)
const detailDlg = ref(false)
const detail = ref(null)
let timer = null

// 后端 Risk.kind 常量见 internal/apiasset/risk.go（R1–R7）
const RISK_DEFS = [
  { key: 'sensitive_exposure', label: '敏感信息暴露', desc: '响应中检测到手机号 / 密钥等敏感信息未脱敏', color: 'var(--km-soft-red)' },
  { key: 'unauthorized', label: '未授权访问', desc: '接口未携带凭证即可返回数据，疑似缺失鉴权', color: 'var(--km-soft-amber)' },
  { key: 'bruteforce', label: '登录爆破', desc: '/login 出现高频失败尝试，来源集中', color: 'var(--km-soft-amber)' },
  { key: 'shadow_api', label: '影子API', desc: '未纳入清单的内部接口存在外部访问', color: 'var(--km-soft-violet)' },
  { key: 'zombie_api', label: '僵尸API', desc: '长期无调用的遗留接口，建议下线', color: 'var(--km-txt-2)' },
  { key: 'admin_exposure', label: '管理面暴露', desc: '管理接口可从公网访问', color: 'var(--km-soft-red)' },
  { key: 'plaintext_secret', label: '明文敏感参数', desc: 'URL 查询串中发现明文 token / 密码参数', color: 'var(--km-soft-amber)' },
]

const riskCards = computed(() => {
  const open = risks.value.filter(r => r.status === 'open')
  return RISK_DEFS.map(def => ({
    name: def.key,
    label: def.label,
    desc: def.desc,
    color: def.color,
    count: open.filter(r => r.kind === def.key).length,
  }))
})

const evidenceRows = computed(() => {
  const ev = detail.value?.evidence
  if (!ev || typeof ev !== 'object') return []
  return Object.entries(ev).map(([k, v]) => ({
    k,
    v: typeof v === 'object' ? JSON.stringify(v) : String(v),
  }))
})

function kindLabel(k) { return RISK_DEFS.find(d => d.key === k)?.label || k || '-' }
function levelLabel(s) { return { high: '高危', medium: '中危', low: '低危' }[s] || s }
function statusLabel(s) { return { open: '待处理', resolved: '已处理', ignored: '已忽略' }[s] || s }

function openDetail(row) {
  detail.value = row
  detailDlg.value = true
}

function goLogs(site) {
  detailDlg.value = false
  router.push({ path: '/logs', query: { site } })
}

async function load() {
  try { const d = await api('/api/risks'); risks.value = d.risks || d || [] } catch (e) { /* module off */ }
}
async function scan() {
  scanning.value = true
  try { await post('/api/risks/scan'); ElMessage.success('扫描完成'); load() }
  catch (e) { ElMessage.error(e.message) }
  finally { scanning.value = false }
}
async function setStatus(row, status) {
  await post(`/api/risks/${row.id}/status`, { status })
  load()
}
onMounted(() => { load(); timer = setInterval(load, 30000) })
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.risk-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
.km-risk-card .rid { font-size: 11px; font-weight: 700; letter-spacing: 0.4px; }
.km-risk-card .rcount { font-size: 26px; font-weight: 700; margin: 2px 0; }
.km-risk-card .rdesc { font-size: 11.5px; color: var(--km-txt-3); line-height: 1.5; }
</style>
