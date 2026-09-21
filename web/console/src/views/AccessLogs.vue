<template>
  <div>
    <el-alert v-if="!enabled" type="info" :closable="false" show-icon style="margin-bottom:12px"
              title="访问日志管道未启用"
              description="在「系统设置 → 日志外发 → 全量访问日志」开启后,这里可查询最近 5000 条访问记录(内存实时尾,重启清空;长期留存请配置外部存储)。" />

    <div class="km-toolbar" v-if="enabled">
      <el-select v-model="fOutcome" size="small" style="width:150px" clearable placeholder="结果">
        <el-option label="转发 forwarded" value="forwarded" />
        <el-option label="拦截 blocked" value="blocked" />
        <el-option label="挑战 challenged" value="challenged" />
        <el-option label="观察放行 monitor_forwarded" value="monitor_forwarded" />
        <el-option label="跳转 redirected" value="redirected" />
      </el-select>
      <el-input v-model="fSite" size="small" style="width:170px" placeholder="站点过滤" clearable />
      <el-input v-model="fTrace" size="small" style="width:170px" placeholder="Trace ID" clearable class="km-mono" />
      <el-input v-model="fText" size="small" style="width:240px" placeholder="过滤 IP / 路径 / UA / 规则…" clearable />
      <div class="grow"></div>
      <span class="km-muted" style="font-size:12px">内存尾 {{ count.toLocaleString() }} 条 · 5s 自动刷新</span>
    </div>

    <el-card shadow="never" :body-style="{ padding: 0 }">
      <el-table :data="viewItems" size="small">
        <el-table-column label="时间" width="165">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="site" label="站点" width="150" show-overflow-tooltip />
        <el-table-column prop="client_ip" label="来源" width="130">
          <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.client_ip }}</span></template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="66" class-name="km-mono" />
        <el-table-column label="路径" show-overflow-tooltip class-name="km-mono">
          <template #default="{ row }">{{ row.path }}<template v-if="row.query">?{{ row.query }}</template></template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="74">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status >= 400 ? 'danger' : row.status >= 300 ? 'warning' : 'success'" effect="plain" class="km-tag">{{ row.status || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="时延" width="84">
          <template #default="{ row }"><span class="km-mono km-dim">{{ row.latency_ms ?? '-' }} ms</span></template>
        </el-table-column>
        <el-table-column label="结果" width="140">
          <template #default="{ row }">
            <el-tag size="small" effect="dark" :type="outcomeType(row.outcome)" class="km-tag">{{ outcomeLabel(row.outcome) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule" label="命中规则" width="150" show-overflow-tooltip class-name="km-mono" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api } from '../api'
import { fmtTime } from '../timefmt'

const enabled = ref(false)
const count = ref(0)
const items = ref([])
const fOutcome = ref('')
const fSite = ref('')
const fText = ref('')
const fTrace = ref('')
let timer = null
let reloadTimer = null

// 站点/全文为当前结果集内过滤(内存尾本身有限)
const viewItems = computed(() => items.value.filter(e =>
  (!fSite.value || (e.site || '').includes(fSite.value)) &&
  (!fOutcome.value || e.outcome === fOutcome.value) &&
  (!fTrace.value || (e.trace_id || '').toLowerCase().includes(fTrace.value.toLowerCase())) &&
  (!fText.value || [e.path, e.user_agent, e.client_ip, e.rule].some(v => (v || '').toLowerCase().includes(fText.value.toLowerCase())))))

function outcomeType(o) {
  return { blocked: 'danger', challenged: 'warning', redirected: 'primary' }[o] || 'info'
}
function outcomeLabel(o) {
  return { forwarded: '转发', blocked: '拦截', challenged: '挑战', monitor_forwarded: '观察放行', redirected: '跳转' }[o] || o || '-'
}

async function load() {
  try {
    const p = new URLSearchParams()
    p.set('limit', '500')
    if (fOutcome.value) p.set('outcome', fOutcome.value)
    const d = await api('/api/access_logs?' + p.toString())
    enabled.value = !!d.enabled
    count.value = d.count || 0
    items.value = d.items || []
  } catch (e) { /* 401 handled in api() */ }
}

watch([fOutcome], () => load())
watch([fSite, fText], () => { clearTimeout(reloadTimer); reloadTimer = setTimeout(load, 300) })

onMounted(() => { load(); timer = setInterval(load, 5000) })
onBeforeUnmount(() => { clearInterval(timer); clearTimeout(reloadTimer) })
</script>
