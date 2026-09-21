<template>
  <el-card shadow="never">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
      <el-button size="small" @click="$router.back()"><el-icon><Back /></el-icon>&nbsp;返回</el-button>
      <div class="km-title" style="margin:0">攻击事件详情 · <span class="km-mono">{{ traceID }}</span></div>
    </div>

    <el-alert v-if="notFound" type="warning" :closable="false" show-icon
              title="事件已滚出内存环或不存在" description="历史事件请通过攻击日志页的过滤条件检索。" />
    <template v-else-if="detail">
      <div class="km-detail-grid">
        <div class="km-dtl"><span class="k">时间（本地）</span><span class="v">{{ fmtTime(detail.ts) }}</span></div>
        <div class="km-dtl"><span class="k">动作</span>
          <span class="v"><el-tag size="small" :type="tagType(detail.action)" effect="dark" class="km-tag">{{ detail.action }}</el-tag></span></div>
        <div class="km-dtl"><span class="k">攻击类型</span>
          <span class="v"><el-tag v-if="detail.attack_type" size="small" effect="dark" class="km-tag">{{ detail.attack_type }}</el-tag><span v-else class="km-dim">-</span></span></div>
        <div class="km-dtl"><span class="k">站点</span><span class="v km-mono">{{ detail.site || '-' }}</span></div>
        <div class="km-dtl"><span class="k">来源 IP</span><span class="v km-mono">{{ detail.client_ip || '-' }}</span></div>
        <div class="km-dtl"><span class="k">请求</span>
          <span class="v km-mono">{{ (detail.method || '-') + ' ' + (detail.url || detail.path || '-') }}</span></div>
        <div class="km-dtl"><span class="k">响应状态</span><span class="v">{{ detail.status || '-' }}</span></div>
        <div class="km-dtl"><span class="k">命中规则</span><span class="v km-mono">{{ detail.rule || '-' }}</span></div>
        <div class="km-dtl"><span class="k">原因</span><span class="v">{{ detail.reason || '-' }}</span></div>
        <div class="km-dtl" v-if="detail.bot_class"><span class="k">BOT 分类</span>
          <span class="v">{{ detail.bot_class }}<template v-if="detail.bot_name"> · {{ detail.bot_name }}</template><template v-if="detail.bot_score"> · 评分 {{ detail.bot_score }}</template></span></div>
        <div class="km-dtl" v-if="detail.user_agent"><span class="k">User-Agent</span><span class="v km-mono" style="word-break:break-all">{{ detail.user_agent }}</span></div>
        <div class="km-dtl" v-if="detail.body_bytes"><span class="k">Body 大小</span><span class="v">{{ detail.body_bytes }} B</span></div>
        <div class="km-dtl"><span class="k">Trace ID</span><span class="v km-mono">{{ detail.trace_id || '-' }}</span></div>
      </div>

      <template v-if="detail.headers && Object.keys(detail.headers).length">
        <div class="km-title" style="margin-top:16px">请求头快照（已脱敏）</div>
        <pre class="km-mono km-snap">{{ Object.entries(detail.headers).map(([k, v]) => k + ': ' + v).join('\n') }}</pre>
      </template>
      <template v-if="detail.body">
        <div class="km-title" style="margin-top:16px">请求体快照（已脱敏）</div>
        <pre class="km-mono km-snap">{{ detail.body }}</pre>
      </template>

      <el-collapse style="margin-top:16px">
        <el-collapse-item title="原始 JSON" name="raw">
          <pre class="km-mono" style="font-size:12px;white-space:pre-wrap;word-break:break-all;margin:0">{{ JSON.stringify(detail, null, 2) }}</pre>
        </el-collapse-item>
      </el-collapse>
    </template>
    <el-skeleton v-else :rows="6" animated style="margin-top:20px" />
  </el-card>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { fmtTime } from '../timefmt'

const route = useRoute()
const traceID = computed(() => decodeURIComponent(route.params.traceId || ''))
const detail = ref(null)
const notFound = ref(false)
let timer = null

function tagType(a) {
  return { blocked: 'danger', challenged: 'warning', monitor: 'info', redirected: 'primary' }[a] || 'info'
}

async function load() {
  if (detail.value) return
  try {
    const evs = await api('/api/logs?limit=1000')
    const hit = evs.find(e => (e.trace_id || '') === traceID.value)
    if (hit) detail.value = hit
    else if (evs.length >= 0 && !evs.some(e => (e.trace_id || '') === traceID.value)) {
      // 环里没有：SQLite 全量检索兜底
      try {
        const q = await api('/api/logs?limit=1&q=' + encodeURIComponent('trace:' + traceID.value))
        if (Array.isArray(q) && q.length) detail.value = q[0]
      } catch (e) { /* query unsupported */ }
    }
    if (!detail.value && evs.length >= 0) notFound.value = false // keep polling briefly
  } catch (e) { /* 401 handled globally */ }
}

onMounted(() => {
  load()
  timer = setInterval(load, 5000)
  setTimeout(() => { if (!detail.value) notFound.value = true; clearInterval(timer) }, 20000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.km-detail-grid { display: grid; grid-template-columns: 1fr; gap: 8px; }
.km-dtl { display: flex; gap: 12px; font-size: 13px; align-items: baseline; }
.km-dtl .k { flex: 0 0 84px; color: var(--km-dim, #94a3b8); font-size: 12px; }
.km-dtl .v { word-break: break-all; }
.km-snap {
  font-size: 12px; white-space: pre-wrap; word-break: break-all; margin: 0;
  padding: 10px 12px; border-radius: 8px;
  background: rgba(255, 255, 255, .04); border: 1px solid rgba(56, 189, 248, .12);
  max-height: 320px; overflow: auto;
}
</style>
