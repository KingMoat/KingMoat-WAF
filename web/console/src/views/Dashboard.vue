<template>
  <div id="km-dashboard-report">
    <!-- 统计时间范围 + 导出 -->
    <div class="km-toolbar" data-html2canvas-ignore="true">
      <div class="km-seg">
        <span class="seg-item" :class="{ on: statsDays === 1 }" @click="setDays(1)">今日</span>
        <span class="seg-item" :class="{ on: statsDays === 7 }" @click="setDays(7)">近 7 日</span>
        <span class="seg-item" :class="{ on: statsDays === 30 }" @click="setDays(30)">近 30 日</span>
      </div>
      <span class="km-muted" style="font-size:12px">统计范围：{{ statsDays === 1 ? '今天 0 点至今' : `最近 ${statsDays} 天` }} · 对比上一周期</span>
      <div class="grow"></div>
      <el-dropdown @command="exportReport">
        <el-button size="small"><el-icon><Download /></el-icon>&nbsp;导出报表</el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="png">PNG 图片（截图当前仪表盘）</el-dropdown-item>
            <el-dropdown-item command="html">HTML 报表（自包含数据）</el-dropdown-item>
            <el-dropdown-item command="pdf">PDF / 打印</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>

    <!-- 统计卡 -->
    <div class="km-cards" style="margin-bottom:16px">
      <div class="km-stat">
        <div class="num">{{ reqTotal }}</div>
        <div class="lbl">累计请求</div>
        <div class="km-delta km-muted">今日攻击事件 {{ eventTotal.toLocaleString() }}</div>
      </div>
      <div class="km-stat danger">
        <div class="num">{{ st.blocked_today ?? '-' }}</div>
        <div class="lbl">{{ rangeLabel }}拦截 <el-tag size="small" effect="plain" type="danger" class="km-tag">intercept</el-tag></div>
        <div class="km-delta" :class="deltaCls">{{ deltaLabel }}</div>
        <svg class="km-spark" width="120" height="26" v-if="sparkPoints">
          <polyline :points="sparkPoints" fill="none" stroke="var(--km-soft-red)" stroke-width="1.6" />
        </svg>
      </div>
      <div class="km-stat green">
        <div class="num">{{ blockRate }}</div>
        <div class="lbl">累计拦截率</div>
        <div class="km-delta km-muted">挑战 {{ st.challenged_today ?? 0 }} · 观察 {{ st.monitor_today ?? 0 }}</div>
      </div>
      <div class="km-stat cyan">
        <div class="num">{{ st.sites ?? '-' }}</div>
        <div class="lbl">防护站点 <el-tag size="small" effect="plain" type="success" class="km-tag">配置版本 {{ st.revision ?? '-' }}</el-tag></div>
      </div>
    </div>

    <div class="km-grid-2" style="margin-bottom:16px">
      <el-card shadow="never">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <div class="km-title" style="margin:0">攻击趋势</div>
          <div style="flex:1"></div>
          <div class="km-seg">
            <span v-for="h in [{v:1,t:'1时'},{v:6,t:'6时'},{v:24,t:'24时'},{v:168,t:'7天'}]" :key="h.v"
                  class="seg-item" :class="{ on: trendHours === h.v }" @click="setTrend(h.v)">{{ h.t }}</span>
          </div>
        </div>
        <div ref="chart" style="height:280px"></div>
      </el-card>

      <el-card shadow="never">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <div class="km-title" style="margin:0">攻击类型分布 · 今日</div>
          <div class="extra km-muted" style="margin-left:auto;font-size:12px">按命中规则归类</div>
        </div>
        <div ref="donut" style="height:280px"></div>
      </el-card>
    </div>

    <div class="km-grid-3">
      <el-card shadow="never">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div class="km-title" style="margin:0">攻击来源 TOP 5</div>
          <div class="extra km-muted" style="margin-left:auto;font-size:12px">GeoIP</div>
        </div>
        <div v-if="geoAvailable">
          <template v-if="geoItems.length">
            <div v-for="g in geoItems.slice(0, 5)" :key="g.country" style="margin-bottom:10px">
              <div style="display:flex;justify-content:space-between;font-size:12.5px">
                <span class="km-mono" style="color:var(--km-txt)">{{ g.country }}</span>
                <span class="km-mono km-dim">{{ g.count.toLocaleString() }}</span>
              </div>
              <div class="km-progress-track"><i :style="{ width: geoPct(g.count) + '%', background: 'var(--km-grad)' }" /></div>
            </div>
          </template>
          <div v-else class="km-muted" style="font-size:12.5px;padding:20px 0;text-align:center">
            当前时间范围内暂无攻击事件
          </div>
        </div>
        <div v-else class="km-muted" style="font-size:12.5px;padding:20px 0;text-align:center">
          GeoIP 数据不可用
        </div>
      </el-card>

      <el-card shadow="never">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div class="km-title" style="margin:0">攻击 IP TOP 5</div>
          <div class="extra km-muted" style="margin-left:auto;font-size:12px">按攻击次数</div>
        </div>
        <div v-if="geoAvailable">
          <template v-if="topIps.length">
            <div v-for="t in topIps" :key="t.ip" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;font-size:12.5px">
              <span class="km-mono" style="color:var(--km-txt)">{{ t.ip }}</span>
              <span style="display:flex;align-items:center;gap:8px">
                <el-tag v-if="t.country" size="small" effect="plain" type="info" class="km-tag">{{ t.country }}</el-tag>
                <span class="km-mono km-dim">{{ t.count.toLocaleString() }}</span>
              </span>
            </div>
          </template>
          <div v-else class="km-muted" style="font-size:12.5px;padding:20px 0;text-align:center">
            当前时间范围内暂无攻击事件
          </div>
        </div>
        <div v-else class="km-muted" style="font-size:12.5px;padding:20px 0;text-align:center">
          GeoIP 数据不可用
        </div>
      </el-card>

      <el-card shadow="never">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div class="km-title" style="margin:0">最新攻击</div>
          <div class="extra" style="margin-left:auto;font-size:12px;cursor:pointer" @click="$router.push('/logs')">查看全部 →</div>
        </div>
        <el-table :data="recent" size="small">
          <el-table-column prop="ts" label="时间" width="150">
            <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
          </el-table-column>
          <el-table-column prop="attack_type" label="类型" width="110" show-overflow-tooltip />
          <el-table-column prop="client_ip" label="来源" width="125">
            <template #default="{ row }"><span class="km-mono" style="color:var(--km-soft-blue)">{{ row.client_ip }}</span></template>
          </el-table-column>
          <el-table-column prop="path" label="目标路径" show-overflow-tooltip />
          <el-table-column prop="action" label="动作" width="100">
            <template #default="{ row }">
              <el-tag size="small" :type="tagType(row.action)" effect="dark" class="km-tag">{{ actionLabel(row.action) }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import html2canvas from 'html2canvas'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { chartPalette, getTheme } from '../theme'
import { fmtTime } from '../timefmt'

const st = ref({})
const statsDays = ref(1)
const rangeLabel = computed(() => (statsDays.value === 1 ? '今日' : `近 ${statsDays.value} 日`))
function setDays(n) {
  statsDays.value = n
  load()
}
const recent = ref([])
const nodeCount = ref(0)
const nodeHealth = ref('-')
const geoItems = ref([])
const geoAvailable = ref(false)
const topIps = ref([])
const chart = ref(null)
const donut = ref(null)
const trendHours = ref(24)
const trendData = ref([])
let chartInst = null
let donutInst = null
let timer = null
let trendTimer = null


const reqTotal = computed(() => {
  const r = st.value.requests || {}
  const t = Object.values(r).reduce((a, b) => a + Number(b || 0), 0)
  return t ? t.toLocaleString() : (st.value.requests ? '0' : '-')
})
const eventTotal = computed(() => (st.value.blocked_today || 0) + (st.value.challenged_today || 0) + (st.value.monitor_today || 0))
const blockRate = computed(() => {
  const r = st.value.requests || {}
  const total = Object.values(r).reduce((a, b) => a + Number(b || 0), 0)
  if (!total) return '-'
  return ((Number(r.blocked || 0) * 1000 / total) / 10).toFixed(1) + '%'
})

// 环比:后端 blocked_prev = 上一同长窗口的拦截量
const delta = computed(() => {
  const cur = st.value.blocked_today || 0
  const prev = st.value.blocked_prev ?? null
  if (prev === null) return null
  if (!prev && !cur) return null
  if (!prev) return cur > 0 ? 100 : 0
  return Math.round((cur - prev) * 100 / prev)
})
const deltaLabel = computed(() => {
  if (delta.value === null) return '数据积累中'
  const d = delta.value
  if (d === 0) return '与上一周期持平'
  return d > 0 ? `较上一周期 +${d}%` : `较上一周期 ${d}%`
})
const deltaCls = computed(() => (delta.value === null || delta.value === 0 ? 'km-muted' : delta.value > 0 ? 'up' : 'down'))

const sparkPoints = computed(() => {
  const b = trendData.value.slice(-14)
  if (b.length < 2) return null
  const vals = b.map(x => (x.by_action || x.ByAction || {}).blocked || 0)
  const max = Math.max(...vals, 1)
  return vals.map((v, i) => `${(i * 120 / (vals.length - 1)).toFixed(1)},${(24 - v * 22 / max).toFixed(1)}`).join(' ')
})

// 报表导出:PNG(html2canvas 截图)/ PDF(打印)/ HTML(自包含数据快照)
async function exportReport(kind) {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
  if (kind === 'png') {
    const el = document.getElementById('km-dashboard-report')
    if (!el) return
    try {
      window.scrollTo(0, 0)
      if (chartInst) chartInst.resize()
      if (donutInst) donutInst.resize()
      await new Promise(r => setTimeout(r, 500))
      const canvas = await html2canvas(el, {
        backgroundColor: getTheme() === 'dark' ? '#070b14' : '#f4f6f8',
        scale: 2,
        windowWidth: document.documentElement.clientWidth,
        windowHeight: el.scrollHeight,
        scrollX: 0,
        scrollY: 0,
      })
      const a = document.createElement('a')
      a.href = canvas.toDataURL('image/png')
      a.download = `kingmoat-dashboard-${stamp}.png`
      a.click()
      ElMessage.success('PNG 报表已导出')
    } catch (e) {
      ElMessage.error('截图失败：' + e.message)
    }
    return
  }
  if (kind === 'pdf') {
    window.print()
    return
  }
  // HTML:自包含数据快照(不依赖页面 DOM/样式)
  const stv = st.value || {}
  const dist = (stv.attack_distribution || []).map(h => `<tr><td>${esc(h.key)}</td><td class="n">${h.count.toLocaleString()}</td></tr>`).join('')
  const geo = geoItems.value.slice(0, 5).map(g => `<tr><td>${esc(g.country)}</td><td class="n">${g.count.toLocaleString()}</td></tr>`).join('')
  const ips = topIps.value.map(t => `<tr><td class="m">${esc(t.ip)}</td><td>${esc(t.country || '-')}</td><td class="n">${t.count.toLocaleString()}</td></tr>`).join('')
  const trend = trendData.value.slice(-trendHours.value).map(b => {
    const a = b.by_action || b.ByAction || {}
    return `<tr><td>${esc(bucketLabel(b.BucketMs ?? b.bucket_ms))}</td><td class="n">${(a.blocked || 0).toLocaleString()}</td><td class="n">${(a.challenged || 0).toLocaleString()}</td><td class="n">${(a.monitor || 0).toLocaleString()}</td></tr>`
  }).join('')
  const rec = recent.value.map(e => `<tr><td>${esc(fmtTime(e.ts))}</td><td>${esc(e.attack_type || '-')}</td><td class="m">${esc(e.client_ip || '-')}</td><td>${esc(e.path || '-')}</td><td>${esc(actionLabel(e.action))}</td></tr>`).join('')
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>KingMoat WAF 统计报表 · ${stamp}</title>
<style>body{font-family:system-ui,'PingFang SC','Microsoft YaHei',sans-serif;max-width:860px;margin:32px auto;padding:0 24px;color:#1b2a38}
h1{font-size:22px}h2{font-size:16px;margin-top:28px;border-left:4px solid #0fae8e;padding-left:10px}
.meta{color:#5e6f82;font-size:13px}table{width:100%;border-collapse:collapse;margin-top:10px}
td,th{padding:8px 12px;border-bottom:1px solid #e3e9ef;font-size:13px;text-align:left}th{background:#f4f6f8}
.n{text-align:right;font-variant-numeric:tabular-nums}.m{font-family:ui-monospace,Consolas,monospace}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.card{border:1px solid #e3e9ef;border-radius:10px;padding:14px}.card .v{font-size:24px;font-weight:700}.card .l{color:#5e6f82;font-size:12px}
footer{margin-top:32px;color:#93a3b3;font-size:11px}</style></head><body>
<h1>KingMoat WAF 统计报表</h1>
<div class="meta">统计范围:${statsDays.value === 1 ? '今日' : `近 ${statsDays.value} 日`} · 生成时间 ${new Date().toLocaleString()} · 配置 rev ${stv.revision ?? '-'}</div>
<div class="cards">
<div class="card"><div class="v">${(stv.blocked_today ?? 0).toLocaleString()}</div><div class="l">拦截攻击</div></div>
<div class="card"><div class="v">${(stv.challenged_today ?? 0).toLocaleString()}</div><div class="l">人机挑战</div></div>
<div class="card"><div class="v">${(stv.monitor_today ?? 0).toLocaleString()}</div><div class="l">观察事件</div></div>
<div class="card"><div class="v">${stv.sites ?? '-'}</div><div class="l">防护站点</div></div>
</div>
<h2>攻击类型分布</h2><table><tr><th>类型</th><th style="text-align:right">次数</th></tr>${dist || '<tr><td colspan=2>暂无数据</td></tr>'}</table>
<h2>攻击来源 TOP 5(GeoIP)</h2><table><tr><th>国家/地区</th><th style="text-align:right">次数</th></tr>${geo || '<tr><td colspan=2>暂无数据</td></tr>'}</table>
<h2>攻击 IP TOP 5</h2><table><tr><th>来源 IP</th><th>国家/地区</th><th style="text-align:right">次数</th></tr>${ips || '<tr><td colspan=3>暂无数据</td></tr>'}</table>
<h2>攻击趋势（近 ${trendHours.value} 时）</h2><table><tr><th>时间</th><th style="text-align:right">拦截</th><th style="text-align:right">挑战</th><th style="text-align:right">观察</th></tr>${trend || '<tr><td colspan=4>暂无数据</td></tr>'}</table>
<h2>最新攻击</h2><table><tr><th>时间</th><th>类型</th><th>来源</th><th>目标路径</th><th>动作</th></tr>${rec || '<tr><td colspan=5>暂无数据</td></tr>'}</table>
<footer>KingMoat WAF · IP Geolocation by DB-IP · 本报表由控制台导出,数据为导出时刻快照</footer>
</body></html>`
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `kingmoat-report-${stamp}.html`
  a.click()
  URL.revokeObjectURL(a.href)
  ElMessage.success('HTML 报表已导出')
}
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) }

function tagType(a) {
  return { blocked: 'danger', challenged: 'warning', monitor: 'info', redirected: 'primary' }[a] || 'info'
}
function actionLabel(a) {
  return { blocked: '拦截', challenged: '挑战', monitor: '观察', redirected: '跳转' }[a] || a
}
function geoPct(c) {
  const max = Math.max(...geoItems.value.slice(0, 5).map(g => g.count), 1)
  return Math.round(c * 100 / max)
}

function palette() { return chartPalette(getTheme()) }

async function load() {
  try {
    st.value = await api('/api/stats?days=' + statsDays.value)
    const evs = await api('/api/logs?limit=200')
    recent.value = evs.slice(0, 8)
    renderDonut()
  } catch (e) { /* 401 handled in api() */ }
}

async function loadGeo() {
  try {
    const d = await api('/api/stats/geo?limit=10&hours=' + (trendHours.value || 24))
    geoItems.value = d.items || []
    topIps.value = d.top_ips || []
    geoAvailable.value = !!d.geo_available
  } catch (e) { geoAvailable.value = false; topIps.value = [] }
}

async function loadTrend() {
  try {
    // 48h 窗口同时服务趋势图(裁剪到所选范围)与环比计算
    const d = await api('/api/stats/trend?hours=48')
    trendData.value = d.buckets || []
    renderChart()
  } catch (e) { /* 401 handled in api() */ }
}

function setTrend(v) {
  trendHours.value = v
  renderChart()
  loadGeo()
}

function renderChart() {
  if (!chart.value) return
  if (!chartInst) chartInst = echarts.init(chart.value)
  const pal = palette()
  const cutoff = Date.now() - trendHours.value * 3600 * 1000
  const buckets = trendData.value.filter(x => (x.BucketMs ?? x.bucket_ms) >= cutoff)
  const keys = buckets.map(b => b.BucketMs ?? b.bucket_ms)
  const byAction = a => buckets.map(b => (b.by_action || b.ByAction || {})[a] || 0)
  const series = [
    { name: '拦截', key: 'blocked', color: pal.series[1] },
    { name: '挑战', key: 'challenged', color: '#f59e0b' },
    { name: '观察', key: 'monitor', color: pal.series[0] },
  ].map(s => ({
    name: s.name, type: 'line', smooth: true, data: byAction(s.key),
    lineStyle: { color: s.color, width: 2 }, itemStyle: { color: s.color },
    areaStyle: { opacity: pal.areaOpacity },
  }))
  chartInst.setOption({
    backgroundColor: 'transparent',
    grid: { left: 44, right: 20, top: 34, bottom: 28 },
    tooltip: {
      trigger: 'axis',
      backgroundColor: pal.tooltipBg, borderColor: pal.tooltipBorder,
      textStyle: { color: pal.textColor },
    },
    legend: { textStyle: { color: pal.subText }, top: 0 },
    xAxis: { type: 'category', data: keys.map(bucketLabel), axisLine: { lineStyle: { color: pal.axisLine } }, axisLabel: { color: pal.subText } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: pal.splitLine } }, axisLabel: { color: pal.subText } },
    series,
  }, { notMerge: true })
}

function renderDonut() {
  if (!donut.value) return
  if (!donutInst) donutInst = echarts.init(donut.value)
  const pal = palette()
  const dist = st.value.attack_distribution || []
  const data = dist.slice(0, 8).map(h => ({ name: h.key, value: h.count }))
  donutInst.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', backgroundColor: pal.tooltipBg, borderColor: pal.tooltipBorder, textStyle: { color: pal.textColor } },
    legend: { orient: 'vertical', right: 6, top: 'middle', textStyle: { color: pal.donutLabel, fontSize: 11 }, formatter: n => {
      const it = data.find(d => d.name === n)
      return `${n}  ${it ? it.value.toLocaleString() : ''}`
    } },
    series: [{
      type: 'pie', radius: ['48%', '72%'], center: ['36%', '50%'],
      label: { show: false }, itemStyle: { borderRadius: 4, borderColor: pal.tooltipBg, borderWidth: 2 },
      data,
    }],
  }, { notMerge: true })
}

function bucketLabel(ms) {
  const d = new Date(ms)
  const p = n => String(n).padStart(2, '0')
  const hm = `${p(d.getHours())}:${p(d.getMinutes())}`
  if (trendHours.value > 24) return `${d.getMonth() + 1}-${p(d.getDate())} ${hm}`
  return hm
}

function onThemeChanged() {
  renderChart()
  renderDonut()
}
function onResize() { chartInst && chartInst.resize(); donutInst && donutInst.resize() }

onMounted(() => {
  load()
  loadTrend()
  loadGeo()
  timer = setInterval(load, 10000)
  trendTimer = setInterval(loadTrend, 30000)
  window.addEventListener('resize', onResize)
  window.addEventListener('km-theme-changed', onThemeChanged)
})
onBeforeUnmount(() => {
  clearInterval(timer); clearInterval(trendTimer)
  window.removeEventListener('resize', onResize)
  window.removeEventListener('km-theme-changed', onThemeChanged)
  chartInst && chartInst.dispose(); donutInst && donutInst.dispose()
})
</script>

<style scoped>
.km-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; }
.km-spark { width: 120px; }
</style>
