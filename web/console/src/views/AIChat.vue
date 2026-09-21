<template>
  <div style="height:100%;display:flex;flex-direction:column">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <div class="km-title" style="margin:0">AI 安全分析师</div>
      <el-tag size="small" effect="plain" type="warning" class="km-tag">只读</el-tag>
      <div style="flex:1"></div>
      <el-tag size="small" effect="plain" type="info" class="km-tag km-mono" style="cursor:pointer" title="模型设置" @click="openModelDlg">{{ model || '未配置模型' }}</el-tag>
      <el-tag size="small" effect="plain" class="km-tag">SSE 流式</el-tag>
    </div>
    <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px">
      <el-select v-model="activeSession" size="small" style="flex:1" placeholder="历史会话" clearable @change="loadSession">
        <el-option v-for="s in sessions" :key="s.id" :value="s.id" :label="s.title || s.id" />
      </el-select>
      <el-button size="small" @click="newSession" title="开启新会话"><el-icon><Plus /></el-icon></el-button>
      <el-button size="small" :disabled="!activeSession" @click="delSession" title="删除当前会话"><el-icon><Delete /></el-icon></el-button>
    </div>

    <!-- 模型设置弹窗(不离开当前页) -->
    <el-dialog v-model="modelDlg" title="AI 模型设置" width="480px" :append-to-body="true">
      <el-form label-width="110px" label-position="left">
        <el-form-item label="当前模型">
          <el-input v-model="md.model" placeholder="如 deepseek-chat" class="km-mono" :disabled="!canOperator" />
        </el-form-item>
        <el-form-item label="常用模型">
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <div v-for="m in modelPresets" :key="m" class="km-chip" style="padding:2px 10px;font-size:11px" @click="canOperator && (md.model = m)">{{ m }}</div>
          </div>
        </el-form-item>
        <el-form-item label="温度">
          <el-slider v-model="md.temperature" :min="0" :max="2" :step="0.1" show-input style="width:260px" :disabled="!canOperator" />
        </el-form-item>
        <el-form-item label="超时（秒）">
          <el-input-number v-model="md.timeout" :min="10" :max="600" :disabled="!canOperator" />
        </el-form-item>
        <el-alert v-if="!canOperator" type="info" :closable="false" show-icon
                  title="当前角色只读，如需修改请联系管理员（系统设置 → AI 助手）" />
      </el-form>
      <template #footer>
        <el-button @click="modelDlg = false">取消</el-button>
        <el-button v-if="canOperator" type="primary" :loading="savingModel" @click="saveModel">保存并发布</el-button>
      </template>
    </el-dialog>
    <el-alert v-if="!enabled" type="info" :closable="false" show-icon
              title="AI 助手未启用" description="在「系统设置 → AI 助手」中启用，并保存 API Key（加密存于本机配置库）。" style="margin-bottom:10px" />
    <el-alert v-if="enabled && keyMissing" type="warning" :closable="false" show-icon
              title="API Key 未配置" description="打开「系统设置 → AI 助手」，在 API Key 输入框粘贴密钥并点「保存 Key」（加密入库，优先于环境变量；也支持在服务端配置文件中设置 api_key_env 后发布）。" style="margin-bottom:10px" />
    <div v-if="!embedded" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px">
      <div v-for="q in quickQs" :key="q" class="km-chip" @click="quickAsk(q)">{{ q }}</div>
    </div>
    <div ref="feed" style="flex:1;overflow:auto;padding:6px 2px">
      <div v-for="(m, i) in msgs" :key="i" :style="{ textAlign: m.role === 'user' ? 'right' : 'left', margin: '10px 0' }">
        <div :style="bubbleStyle(m.role)" :class="m.role === 'user' ? '' : 'md-body'">
          <div v-if="m.imgs && m.imgs.length" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px">
            <img v-for="(u, j) in m.imgs" :key="j" :src="u"
                 style="max-width:180px;max-height:120px;border-radius:8px;border:1px solid var(--km-line);display:block" />
          </div>
          <div v-if="m.role === 'user'">{{ m.raw }}</div>
          <div v-else v-html="mdToHtml(m.raw)"></div>
        </div>
      </div>
      <div v-if="streaming" class="km-dim" style="margin:8px 0">AI 正在思考…</div>
    </div>
    <div v-if="images.length" style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 0">
      <div v-for="(im, i) in images" :key="i" style="position:relative;width:64px;height:64px">
        <img :src="im.url" style="width:64px;height:64px;object-fit:cover;border-radius:6px;border:1px solid var(--km-line);display:block" />
        <el-button link type="danger" size="small" @click="images.splice(i,1)"
                   style="position:absolute;top:-8px;right:-8px;background:rgba(0,0,0,.5);border-radius:50%">✕</el-button>
      </div>
    </div>
    <div style="display:flex;gap:10px;margin-top:10px;align-items:center">
      <input ref="fileInput" type="file" accept="image/png,image/jpeg,image/webp,image/gif" multiple style="display:none" @change="onFiles" />
      <el-button :disabled="!enabled || streaming || images.length >= 4" @click="fileInput && fileInput.click()" title="截图提问（≤4 张）">
        <el-icon><Camera /></el-icon>
      </el-button>
      <el-input v-model="input" :placeholder="embedded ? '向 AI 提问…（Enter 发送）' : '例如：今天被拦截最多的攻击类型是什么？'" @keydown.enter="send" :disabled="!enabled || streaming" />
      <el-button type="primary" :disabled="!enabled || streaming" @click="send">发送</el-button>
    </div>
  </div>
</template>

<script setup>
import { nextTick, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, can, post } from '../api'
import { mdToHtml } from '../md'

const props = defineProps({ inline: { type: Boolean, default: false }, embedded: { type: Boolean, default: false } })
const embedded = props.embedded || props.inline

const enabled = ref(true)
const model = ref('')
const msgs = ref([])
const input = ref('')
const streaming = ref(false)
const keyMissing = ref(false)
const feed = ref(null)
const fileInput = ref(null)
const images = ref([])
const canOperator = can('operator')

// 模型设置弹窗(页面内完成,不切换标签页)
const modelDlg = ref(false)
const savingModel = ref(false)
const md = reactive({ model: '', temperature: 0.2, timeout: 120 })
const modelPresets = ['deepseek-chat', 'gpt-4o-mini', 'qwen-plus', 'glm-4-flash', 'kimi-k2']

function openModelDlg() {
  md.model = model.value
  modelDlg.value = true
  api('/api/ai/config').then(c => {
    if (typeof c.temperature === 'number' && c.temperature > 0) md.temperature = c.temperature
    if (c.timeout_sec) md.timeout = c.timeout_sec
  }).catch(() => {})
}

async function saveModel() {
  if (!md.model.trim()) return ElMessage.error('请填写模型名称')
  savingModel.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.ai = { ...(cfg.ai || {}), enabled: true }
    cfg.ai.provider = { ...(cfg.ai?.provider || {}), model: md.model.trim(), temperature: Number(md.temperature) || 0.2, timeout_sec: md.timeout }
    const r = await post('/api/config/publish', { note: 'ai model change from chat', config: cfg })
    ElMessage.success('模型已更新并热生效（版本 ' + r.revision + '）')
    model.value = md.model.trim()
    modelDlg.value = false
  } catch (e) {
    ElMessage.error('保存失败：' + e.message)
  } finally {
    savingModel.value = false
  }
}

const quickQs = ['总结过去 24h 的攻击态势', '当前哪些站点是 monitor 模式？', '哪些风险项需要优先处理？', '生成今日安全摘要']

// ---- 历史会话:持久化在服务端 ai.db,切页后自动恢复最新会话 ----
const sessions = ref([])
const activeSession = ref('')

async function loadSessions() {
  try {
    const d = await api('/api/ai/sessions')
    sessions.value = Array.isArray(d) ? d : (d.sessions || [])
  } catch (e) { sessions.value = [] }
}

async function loadSession(id) {
  if (!id) { msgs.value = []; activeSession.value = ''; return }
  try {
    const rows = await api('/api/ai/sessions/' + encodeURIComponent(id) + '/messages')
    msgs.value = (rows || []).filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => ({ role: m.role, raw: m.content || '' }))
    activeSession.value = id
    scroll()
  } catch (e) { ElMessage.error('历史加载失败：' + e.message) }
}

function newSession() {
  activeSession.value = ''
  msgs.value = []
}

async function delSession() {
  if (!activeSession.value) return
  try {
    await api('/api/ai/sessions/' + encodeURIComponent(activeSession.value), { method: 'DELETE' })
    activeSession.value = ''
    msgs.value = []
    loadSessions()
    ElMessage.success('会话已删除')
  } catch (e) { ElMessage.error(e.message) }
}


const MAX_IMAGES = 4
const MAX_IMAGE_BYTES = 4 * 1024 * 1024

function bubbleStyle(role) {
  const user = role === 'user'
  return {
    display: 'inline-block',
    maxWidth: '86%',
    padding: '10px 14px',
    borderRadius: user ? '12px 12px 3px 12px' : '12px 12px 12px 3px',
    background: user ? 'var(--km-nav-grad)' : 'var(--km-panel-2)',
    border: '1px solid var(--km-line)',
    fontSize: '13px',
    whiteSpace: user ? 'pre-wrap' : 'normal',
    wordBreak: 'break-word',
    textAlign: 'left'
  }
}
function esc(s) { return (s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) }
function scroll() { nextTick(() => { if (feed.value) feed.value.scrollTop = feed.value.scrollHeight }) }

function onFiles(ev) {
  const files = Array.from(ev.target.files || [])
  ev.target.value = ''
  for (const f of files) {
    if (images.value.length >= MAX_IMAGES) { break }
    if (!/^image\/(png|jpeg|webp|gif)$/.test(f.type)) { continue }
    if (f.size > MAX_IMAGE_BYTES) { continue }
    const reader = new FileReader()
    reader.onload = () => { images.value.push({ name: f.name, url: reader.result }) }
    reader.readAsDataURL(f)
  }
}

onMounted(async () => {
  try {
    const c = await api('/api/ai/config')
    enabled.value = !!c.enabled
    model.value = c.model || ''
    keyMissing.value = c.enabled && c.api_key_set === false
  } catch (e) { enabled.value = false }
  loadSessions()
  try {
    const list = await api('/api/ai/sessions')
    const arr = Array.isArray(list) ? list : (list.sessions || [])
    if (arr.length) await loadSession(arr[0].id)
  } catch (e) { /* first run */ }
  // 一键问 AI:日志页携带的上下文种子自动发送
  const seed = sessionStorage.getItem('km-ai-seed')
  if (seed && enabled.value) {
    sessionStorage.removeItem('km-ai-seed')
    input.value = seed
    send()
  }
})

function quickAsk(q) {
  if (streaming.value || !enabled.value) return
  input.value = q
  send()
}

async function send() {
  const q = input.value.trim()
  if (!q && !images.value.length) return
  if (streaming.value) return
  const imgs = images.value.map(x => x.url)
  input.value = ''
  images.value = []
  msgs.value.push({ role: 'user', raw: q, imgs })
  const reply = { role: 'assistant', raw: '' }
  msgs.value.push(reply)
  streaming.value = true
  scroll()
  try {
    // SSE stream: POST /api/ai/chat returns text/event-stream
    const resp = await fetch('/api/ai/chat', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(activeSession.value
        ? (imgs.length ? { message: q, images: imgs, session_id: activeSession.value } : { message: q, session_id: activeSession.value })
        : (imgs.length ? { message: q, images: imgs } : { message: q }))
    })
    if (!resp.ok || !resp.body) {
      const t = await resp.text().catch(() => '')
      throw new Error(t || ('HTTP ' + resp.status))
    }
    const reader = resp.body.getReader()
    const dec = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, idx); buf = buf.slice(idx + 2)
        const line = frame.split('\n').find(l => l.startsWith('data:'))
        if (!line) continue
        const payload = line.slice(5).trim()
        if (payload === '[DONE]') continue
        try {
          const j = JSON.parse(payload)
          if (j.delta || j.content || j.text) {
            reply.raw += (j.delta || j.content || j.text)
            scroll()
          }
          if (j.session_id) { activeSession.value = j.session_id; loadSessions() }
        } catch (e) { /* ignore partial frames */ }
      }
    }
  } catch (e) {
    reply.raw += '\n[错误] ' + e.message
  } finally {
    streaming.value = false
    scroll()
  }
}
</script>
