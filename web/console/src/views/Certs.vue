<template>
  <div>
    <div class="km-toolbar">
      <el-button v-if="can('operator')" type="primary" @click="dlg = true">
        <el-icon><Upload /></el-icon>&nbsp;上传 PEM 证书
      </el-button>
      <el-button v-if="can('operator')" @click="openCA">
        <el-icon><Stamp /></el-icon>&nbsp;本地 CA
      </el-button>
      <el-button v-if="can('operator')" type="primary" plain @click="openAcmeRequest">
        <el-icon><MagicStick /></el-icon>&nbsp;申请证书
      </el-button>
      <el-tag effect="plain" type="info" class="km-tag">站点开启 ACME 后自动申请并续签（TLS-ALPN-01 / HTTP-01）</el-tag>
      <el-input v-model="acmeEmail" placeholder="ops@example.com" class="km-mono" style="width:300px;margin-left:8px" size="small">
        <template #prepend>ACME 邮箱</template>
      </el-input>
      <el-button size="small" type="primary" :loading="acmeSaving" @click="saveAcme">保存邮箱</el-button>
      <div class="grow"></div>
    </div>

    <!-- 管理控制台证书（独立控制台部署时显示） -->
    <el-card v-if="consoleTls" shadow="never" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <div class="km-title" style="margin:0">管理控制台证书</div>
        <el-tag size="small" effect="plain" type="info" class="km-tag">HTTPS {{ consoleTls.listen }}</el-tag>
        <el-tag v-if="consoleTls.source === 'self-signed'" size="small" type="warning" effect="plain" class="km-tag">自签名</el-tag>
        <div class="grow"></div>
      </div>
      <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:10px">
        <span class="km-mono" style="font-size:12px;color:var(--km-txt)">绑定 {{ consoleTls.cert_name }}</span>
        <span style="font-size:12px;color:var(--km-txt-2)">主体 {{ consoleTls.subject || '-' }}</span>
        <span style="font-size:12px;color:var(--km-txt-2)">有效期至 {{ consoleTls.not_after ? fmt(consoleTls.not_after) : '-' }}</span>
        <span class="km-mono" style="font-size:12px;color:var(--km-txt-3)">指纹 {{ consoleTls.fingerprint }}</span>
      </div>
      <div v-if="can('admin')" style="display:flex;gap:8px;align-items:center;margin-top:12px">
        <el-select v-model="consoleCertPick" size="small" style="width:260px" placeholder="从证书库选择新证书">
          <el-option v-for="u in uploads" :key="u.name" :label="u.name" :value="u.name" />
        </el-select>
        <el-button size="small" type="primary" :loading="consoleSwitching" @click="applyConsoleCert">应用并热生效</el-button>
        <span class="km-dim" style="font-size:12px">立即生效，无需重启管理平面</span>
      </div>
    </el-card>

    <!-- 证书库与站点证书（表格视图） -->
    <el-card shadow="never" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="km-title" style="margin:0">TLS 证书库</div>
      </div>
        <el-table :data="pagedUploads" size="small" style="margin-top:12px">
          <el-table-column prop="name" label="名称" width="160" />
          <el-table-column prop="subject" label="主体" show-overflow-tooltip />
          <el-table-column label="域名/SAN" show-overflow-tooltip>
            <template #default="{ row }">{{ (row.domains || []).join(', ') }}</template>
          </el-table-column>
          <el-table-column label="引用站点" min-width="150">
            <template #default="{ row }">
              <template v-if="(row.sites || []).length">
                <el-tag v-for="d in row.sites" :key="d" size="small" effect="plain" type="primary" class="km-tag"
                        style="margin-right:6px;cursor:pointer" @click="goSite(d)">{{ d }}</el-tag>
              </template>
              <span v-else class="km-muted" style="font-size:12px">未引用</span>
            </template>
          </el-table-column>
          <el-table-column label="到期时间" width="170">
            <template #default="{ row }">
              <span>{{ fmt(row.not_after) }}</span>
              <el-tag v-if="expiring(row.not_after)" size="small" type="warning" effect="dark" class="km-tag" style="margin-left:8px">即将到期</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="引用路径" class-name="km-mono" show-overflow-tooltip>
            <template #default="{ row }">{{ row.cert_path }}</template>
          </el-table-column>
          <el-table-column label="操作" width="110">
            <template #default="{ row }">
              <el-button v-if="can('operator')" link type="danger" size="small" @click="removeCert(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div v-if="uploads.length > upPageSize" style="display:flex;justify-content:flex-end;gap:10px;align-items:center;padding:10px 0 0">
          <span class="km-dim" style="font-size:12px">每页</span>
          <el-select v-model="upPageSize" size="small" style="width:84px"
                     @change="() => { const max = Math.max(1, Math.ceil(uploads.length / upPageSize)); if (upPage > max) upPage = max }">
            <el-option v-for="n in [10, 20, 50, 100]" :key="n" :label="n + ' 条'" :value="n" />
          </el-select>
          <el-pagination layout="prev, pager, next" small background :total="uploads.length"
                         :page-size="upPageSize" :current-page="upPage"
                         @current-change="p => upPage = p" />
        </div>
        <el-alert type="info" :closable="false" style="margin-top:10px"
                  title="站点编辑器中「证书来源 = 已上传证书」选择名称即可引用；被站点或管理控制台引用的条目不可删除" />
      </el-card>

    <!-- ACME 托管证书（证书库在线申请的证书实时列表，到期前 30 天内自动续签） -->
    <el-card shadow="never" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="km-title" style="margin:0">ACME 托管证书</div>
        <el-tag size="small" effect="plain" type="info" class="km-tag">Let's Encrypt 在线签发，到期前 30 天内自动续签</el-tag>
        <div style="flex:1"></div>
        <el-button size="small" :loading="acmeEntriesLoading" @click="loadAcmeEntries(true)">刷新</el-button>
      </div>
      <el-table :data="acmeEntries" size="small" style="margin-top:12px"
                empty-text="暂无 ACME 托管证书，点击上方「申请证书」在线签发">
        <el-table-column prop="domain" label="域名" min-width="200" class-name="km-mono" show-overflow-tooltip />
        <el-table-column label="类型" width="130">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" :type="row.staging ? 'warning' : 'success'">{{ row.staging ? '测试（staging）' : '生产' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="issuer" label="颁发者" min-width="170" show-overflow-tooltip />
        <el-table-column label="有效期" min-width="250">
          <template #default="{ row }">
            <div class="km-mono" style="font-size:12px">{{ fmt(row.not_before) }} ~ {{ fmt(row.not_after) }}</div>
            <div style="font-size:11.5px;margin-top:2px" :style="{ color: acmeExpiry(row).color }">{{ acmeExpiry(row).text }}</div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.status === 'valid' ? 'success' : 'warning'" :effect="row.status === 'valid' ? 'plain' : 'dark'">
              {{ row.status === 'valid' ? '有效' : '即将到期' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="caDlg" title="本地 CA · 自签证书" width="520px" destroy-on-close>
      <template v-if="!caInfo.exists">
        <el-alert type="info" :closable="false" style="margin-bottom:14px"
                  title="尚未创建本地 CA"
                  description="创建后即可用该 CA 签发自签名证书，签发的证书直接进入证书库，可在站点编辑器中选择使用。" />
        <el-form label-width="90px" label-position="left">
          <el-form-item label="CA 名称">
            <el-input v-model="caForm.common_name" placeholder="KingMoat Local CA" />
          </el-form-item>
          <el-form-item label="有效期">
            <el-input-number v-model="caForm.days" :min="30" :max="7300" style="width:160px" />
            <span class="km-dim" style="margin-left:8px;font-size:12px">天（默认 3650）</span>
          </el-form-item>
        </el-form>
      </template>
      <template v-else>
        <el-descriptions :column="1" size="small" border style="margin-bottom:14px">
          <el-descriptions-item label="CA 主体">{{ caInfo.subject }}</el-descriptions-item>
          <el-descriptions-item label="有效期至">{{ fmt(caInfo.not_after) }}</el-descriptions-item>
        </el-descriptions>
        <el-form label-width="90px" label-position="left">
          <el-form-item label="证书名称">
            <el-input v-model="signForm.name" placeholder="留空按主体域名自动生成" />
          </el-form-item>
          <el-form-item label="主体域名">
            <el-input v-model="signForm.common_name" placeholder="如 demo.example.com" />
          </el-form-item>
          <el-form-item label="SAN 列表">
            <el-select v-model="signForm.sans" multiple filterable allow-create default-first-option
                       placeholder="附加域名/IP，回车确认，可多个" style="width:100%" />
          </el-form-item>
          <el-form-item label="有效期">
            <el-input-number v-model="signForm.days" :min="7" :max="3650" style="width:160px" />
            <span class="km-dim" style="margin-left:8px;font-size:12px">天（默认 825）</span>
          </el-form-item>
        </el-form>
      </template>
      <template #footer>
        <el-button @click="caDlg = false">{{ caInfo.exists ? '关闭' : '取消' }}</el-button>
        <el-button v-if="!caInfo.exists" type="primary" :loading="caBusy" @click="createCA">创建本地 CA</el-button>
        <el-button v-else type="primary" :loading="caBusy" @click="signCert">签发证书</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="dlg" title="上传证书" width="480px">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="证书名称">
          <el-input v-model="up.name" placeholder="如 shop-example-com" />
        </el-form-item>
        <el-form-item label="上传方式">
          <el-radio-group v-model="up.mode">
            <el-radio-button value="files">证书 + 私钥</el-radio-button>
            <el-radio-button value="zip">ZIP 压缩包</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <template v-if="up.mode === 'files'">
          <el-form-item label="证书文件">
            <input type="file" accept=".pem,.crt,.cer" @change="e => (up.certFile = e.target.files[0])" />
          </el-form-item>
          <el-form-item label="私钥文件">
            <input type="file" accept=".key,.pem" @change="e => (up.keyFile = e.target.files[0])" />
          </el-form-item>
        </template>
        <el-form-item v-else label="ZIP 包">
          <input type="file" accept=".zip" @change="e => (up.zipFile = e.target.files[0])" />
          <div class="km-dim" style="font-size:12px;margin-top:4px">
            支持 zip/tar.gz 最多 5 层嵌套；全包内容识别证书与私钥（PEM/DER，任意扩展名），多候选自动公钥配对（≤20MB）
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlg = false">取消</el-button>
        <el-button type="primary" :loading="uploading" @click="upload">上传</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="acmeDlg" title="在线申请证书（ACME · Let's Encrypt）" width="560px" :close-on-click-modal="false">
      <template v-if="acmePhase === 'form'">
        <el-form label-width="90px" label-position="left">
          <el-form-item label="域名" required>
            <el-input v-model="acmeForm.domain" class="km-mono" placeholder="如 demo.example.com（不支持通配符）" @keyup.enter="submitAcme" />
          </el-form-item>
          <el-form-item label="邮箱">
            <el-input v-model="acmeForm.email" placeholder="留空则使用页面上方设置的 ACME 邮箱" />
          </el-form-item>
          <el-form-item label="测试签发">
            <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px">
              <el-switch v-model="acmeForm.staging" />
              <span class="km-dim" style="font-size:12px">使用 Let's Encrypt 测试环境，证书不受信任，不占用正式签发配额</span>
            </div>
          </el-form-item>
        </el-form>
        <el-alert type="info" :closable="false"
                  title="申请前请确认：域名已解析到本机，且已在站点页配置全局 HTTP/HTTPS 监听（HTTP-01 验证需 80 端口可从公网访问）" />
      </template>
      <div v-else-if="acmePhase === 'issuing' && acmeTask" style="text-align:center;padding:14px 0 4px">
        <el-icon class="km-acme-spin" style="font-size:36px;color:var(--km-cyan)"><Loading /></el-icon>
        <div style="font-size:15px;font-weight:600;margin-top:12px">
          正在为 <span class="km-mono">{{ acmeTask.domain }}</span> 签发{{ acmeTask.staging ? '测试环境' : '' }}证书…
        </div>
        <div class="km-dim" style="font-size:12.5px;margin-top:6px">Let's Encrypt 签发通常需要 20–90 秒；可关闭弹窗后台等待，完成后自动刷新列表</div>
        <el-progress :percentage="acmeProgress" :show-text="false" :stroke-width="8" style="margin-top:16px" />
        <div class="km-muted" style="font-size:12px;margin-top:8px">
          已等待 {{ acmeElapsed }} 秒 / 最长 120 秒 · 任务状态：{{ acmeStatusText }}
        </div>
      </div>
      <el-result v-else-if="acmePhase === 'success'" icon="success" title="证书签发成功">
        <template #sub-title>
          <div style="font-size:13px;color:var(--km-txt-2);line-height:1.9">
            <span class="km-mono">{{ acmeTask?.domain }}</span>{{ acmeTask?.staging ? '（测试环境证书，不受信任）' : '' }}
            <template v-if="acmeTask?.not_after"> · 有效期至 {{ fmt(acmeTask.not_after) }}</template>
            <div v-if="acmeTask?.reused" class="km-muted" style="font-size:12px">该域名已有有效证书，本次直接复用缓存，未重复签发</div>
            <div v-else class="km-muted" style="font-size:12px">证书已进入「ACME 托管证书」列表，站点编辑器中可直接引用</div>
          </div>
        </template>
      </el-result>
      <el-result v-else-if="acmePhase === 'failed'" icon="error" title="证书签发失败">
        <template #sub-title>
          <div class="km-acme-err">{{ acmeTask?.error || '未知错误' }}</div>
        </template>
      </el-result>
      <el-result v-else icon="warning" title="签发耗时超过 2 分钟，已停止进度跟踪">
        <template #sub-title>
          <div style="font-size:13px;color:var(--km-txt-2)">任务仍在后台执行，稍后可点击列表「刷新」查看结果</div>
        </template>
      </el-result>
      <template #footer>
        <template v-if="acmePhase === 'form'">
          <el-button @click="acmeDlg = false">取消</el-button>
          <el-button type="primary" :loading="acmeBusy" @click="submitAcme">提交申请</el-button>
        </template>
        <el-button v-else-if="acmePhase === 'issuing'" @click="acmeDlg = false">后台运行</el-button>
        <el-button v-else-if="acmePhase === 'success'" type="primary" @click="acmeDlg = false">完成</el-button>
        <template v-else-if="acmePhase === 'failed'">
          <el-button @click="acmeDlg = false">关闭</el-button>
          <el-button type="primary" @click="acmePhase = 'form'">返回修改</el-button>
        </template>
        <template v-else>
          <el-button @click="acmeDlg = false">关闭</el-button>
          <el-button type="primary" @click="acmeDlg = false; loadAcmeEntries(true)">刷新列表</el-button>
        </template>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, can, post } from '../api'
import { fmtTime } from '../timefmt'

const router = useRouter()

// ACME 全局邮箱（从系统设置迁移至此）
const acmeEmail = ref('')
const acmeSaving = ref(false)
async function loadAcme() {
  try {
    const d = await api('/api/config')
    acmeEmail.value = d.config?.acme_email || ''
  } catch (e) { /* silent */ }
}
async function saveAcme() {
  acmeSaving.value = true
  try {
    const d = await api('/api/config')
    const cfg = d.config
    cfg.acme_email = acmeEmail.value.trim()
    const r = await post('/api/config/publish', { note: 'acme email update', config: cfg })
    ElMessage.success('ACME 邮箱已发布并热生效（版本 ' + r.revision + '）')
  } catch (e) {
    ElMessage.error('保存失败：' + e.message)
  } finally {
    acmeSaving.value = false
  }
}
const uploads = ref([])
const dlg = ref(false)
const uploading = ref(false)
const up = reactive({ name: '', mode: 'files', certFile: null, keyFile: null, zipFile: null })
let timer = null

// 证书库列表分页：默认每页 10 条，可选 10/20/50/100（与站点列表分页一致）
const upPage = ref(1)
const upPageSize = ref(10)
const pagedUploads = computed(() => {
  const start = (upPage.value - 1) * upPageSize.value
  return uploads.value.slice(start, start + upPageSize.value)
})

// 点击引用站点域名 → 站点防护页自动筛选
function goSite(domain) {
  router.push('/sites?site=' + encodeURIComponent(domain))
}

// 管理控制台证书（后端挂载 /api/console/tls 时显示，未挂载时自动隐藏）
const consoleTls = ref(null)
const consoleCertPick = ref('')
const consoleSwitching = ref(false)
async function loadConsoleTls() {
  try { consoleTls.value = await api('/api/console/tls') } catch (e) { consoleTls.value = null }
}
async function applyConsoleCert() {
  if (!consoleCertPick.value) return ElMessage.error('请选择证书库中的证书')
  consoleSwitching.value = true
  try {
    const r = await post('/api/console/tls', { cert_name: consoleCertPick.value })
    consoleTls.value = r.tls
    ElMessage.success('管理控制台证书已切换并热生效（' + r.tls.cert_name + '）')
  } catch (e) {
    ElMessage.error('切换失败：' + e.message)
  } finally { consoleSwitching.value = false }
}

// 本地 CA（创建 + 签发自签名证书）
const caDlg = ref(false)
const caBusy = ref(false)
const caInfo = ref({ exists: false })
const caForm = reactive({ common_name: 'KingMoat Local CA', days: 3650 })
const signForm = reactive({ name: '', common_name: '', sans: [], days: 825 })

async function openCA() {
  caDlg.value = true
  try { caInfo.value = await api('/api/certificates/ca') } catch (e) { caInfo.value = { exists: false } }
  if (!caInfo.value.exists) { caInfo.value = { exists: false } }
}
async function createCA() {
  caBusy.value = true
  try {
    const r = await post('/api/certificates/ca', { common_name: caForm.common_name.trim() || 'KingMoat Local CA', days: caForm.days })
    ElMessage.success('本地 CA 已创建（' + r.subject + '）')
    caInfo.value = { exists: true, subject: r.subject, not_after: r.not_after }
  } catch (e) {
    ElMessage.error(e.message)
  } finally { caBusy.value = false }
}
async function signCert() {
  if (!signForm.common_name.trim()) return ElMessage.error('请填写主体域名')
  caBusy.value = true
  try {
    const r = await post('/api/certificates/ca/sign', {
      name: signForm.name.trim(),
      common_name: signForm.common_name.trim(),
      sans: signForm.sans.map(s => String(s).trim()).filter(Boolean),
      days: signForm.days,
    })
    ElMessage.success('证书已签发：' + r.name + '（已进入证书库）')
    signForm.name = ''; signForm.common_name = ''; signForm.sans = []
    caDlg.value = false
    load()
  } catch (e) {
    ElMessage.error(e.message)
  } finally { caBusy.value = false }
}

// ===== ACME 在线申请（证书库 · 异步任务 + 轮询）=====
const acmeDlg = ref(false)
const acmePhase = ref('form') // form | issuing | success | failed | timeout
const acmeBusy = ref(false)
const acmeForm = reactive({ domain: '', email: '', staging: false })
const acmeTask = ref(null)
const acmeElapsed = ref(0) // 已等待秒数
const ACME_POLL_MS = 2000
const ACME_POLL_MAX_MS = 120000
let acmePollTimer = null

const acmeStatusText = computed(() => ({ pending: '排队中', running: '签发中' }[acmeTask.value?.status] || acmeTask.value?.status || '-'))
const acmeProgress = computed(() => Math.min(95, Math.round((acmeElapsed.value / 120) * 100)))

function openAcmeRequest() {
  // 签发进行中重新打开时恢复进度态，不重置（弹窗可随时关闭后台等待）
  if (acmePhase.value !== 'issuing') {
    stopAcmePoll()
    acmePhase.value = 'form'
    acmeForm.domain = ''
    acmeForm.email = acmeEmail.value.trim()
    acmeForm.staging = false
    acmeTask.value = null
    acmeElapsed.value = 0
  }
  acmeDlg.value = true
}

// 前端先行校验域名格式（后端有同名校验，这里给即时反馈）：拒绝通配符/非法字符/超长
function acmeDomainError(d) {
  if (!d) return '请填写域名'
  if (d.includes('*')) return '不支持通配符域名：HTTP-01 验证无法签发通配符，请申请单个域名'
  if (d.length > 253) return '域名长度不能超过 253 字符'
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) {
    return '域名格式无效：仅支持小写字母、数字与连字符，如 demo.example.com'
  }
  return ''
}

async function submitAcme() {
  const domain = acmeForm.domain.trim().toLowerCase()
  const derr = acmeDomainError(domain)
  if (derr) return ElMessage.error(derr)
  acmeBusy.value = true
  try {
    const t = await post('/api/certs/acme/request', { domain, email: acmeForm.email.trim(), staging: acmeForm.staging })
    acmeTask.value = t
    if (t.status === 'success') {
      acmePhase.value = 'success' // 缓存命中：已有有效证书直接复用，未重复签发
      loadAcmeEntries()
    } else {
      acmeElapsed.value = 0
      acmePhase.value = 'issuing'
      pollAcmeTask(t.id)
    }
  } catch (e) {
    ElMessage.error(e.message) // 400/429：后端返回的中文指引直接展示
  } finally { acmeBusy.value = false }
}

// 轮询签发任务：2s 间隔、最长 120s，success/failed 终止；弹窗关闭后继续跟踪，
// 完成时全局提示并刷新列表；组件卸载时由 onBeforeUnmount 清理定时器
function pollAcmeTask(id) {
  stopAcmePoll()
  const start = Date.now()
  const deadline = start + ACME_POLL_MAX_MS
  const tick = async () => {
    try {
      const t = await api('/api/certs/acme/request?id=' + encodeURIComponent(id))
      acmeTask.value = t
      if (t.status === 'success') {
        acmePhase.value = 'success'
        loadAcmeEntries()
        if (!acmeDlg.value) ElMessage.success('ACME 证书签发成功：' + t.domain)
        return
      }
      if (t.status === 'failed') {
        acmePhase.value = 'failed'
        if (!acmeDlg.value) ElMessage.error('ACME 证书签发失败：' + (t.error || '未知错误'))
        return
      }
    } catch (e) {
      acmeTask.value = acmeTask.value ? { ...acmeTask.value, error: e.message } : { id, error: e.message }
      acmePhase.value = 'failed'
      return
    }
    if (Date.now() >= deadline) { acmePhase.value = 'timeout'; return }
    acmeElapsed.value = Math.min(120, Math.round((Date.now() - start) / 1000))
    acmePollTimer = setTimeout(tick, ACME_POLL_MS)
  }
  tick()
}

function stopAcmePoll() {
  if (acmePollTimer) { clearTimeout(acmePollTimer); acmePollTimer = null }
}

// ===== ACME 托管证书条目（实时读缓存列表）=====
const acmeEntries = ref([])
const acmeEntriesLoading = ref(false)

async function loadAcmeEntries(showLoading = false) {
  if (showLoading) acmeEntriesLoading.value = true
  try { acmeEntries.value = await api('/api/certs/acme/entries') } catch (e) { acmeEntries.value = [] }
  finally { acmeEntriesLoading.value = false }
}

// 剩余有效天数文案与颜色
function acmeExpiry(row) {
  if (!row.not_after) return { text: '-', color: 'var(--km-txt-3)' }
  const d = Math.ceil((new Date(row.not_after).getTime() - Date.now()) / 86400000)
  if (d <= 0) return { text: '已过期', color: 'var(--km-soft-red)' }
  return { text: '剩余 ' + d + ' 天', color: row.status === 'expiring' ? 'var(--km-soft-amber)' : 'var(--km-txt-3)' }
}

function fmt(ts) { return fmtTime(ts) }
function expiring(ts) { return ts && new Date(ts) - Date.now() < 14 * 86400 * 1000 }

async function load() {
  try { uploads.value = await api('/api/certificates/uploads') } catch (e) { uploads.value = [] }
  const max = Math.max(1, Math.ceil(uploads.value.length / upPageSize.value))
  if (upPage.value > max) upPage.value = max
}

// 删除证书库条目（被站点/管理控制台引用时后端拒绝，并返回原因）
async function removeCert(row) {
  try {
    await ElMessageBox.confirm(
      `确认删除证书库条目「${row.name}」？该操作不可恢复（站点/控制台仍引用时会被拒绝）。`,
      '删除证书', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' }
    )
  } catch (e) { return }
  try {
    const r = await fetch('/api/certificates/uploads/' + encodeURIComponent(row.name), { method: 'DELETE', credentials: 'same-origin' })
    if (!r.ok) throw new Error((await r.json()).error || '删除失败')
    ElMessage.success('证书已删除：' + row.name)
    load()
  } catch (e) {
    ElMessage.error('删除失败：' + e.message)
  }
}

async function upload() {
  if (!up.name.trim()) return ElMessage.error('请填写证书名称')
  const fd = new FormData()
  fd.append('name', up.name.trim())
  if (up.mode === 'zip') {
    if (!up.zipFile) return ElMessage.error('请选择 ZIP 包')
    fd.append('zip', up.zipFile)
  } else {
    if (!up.certFile || !up.keyFile) return ElMessage.error('请选择证书与私钥文件')
    fd.append('cert', up.certFile)
    fd.append('key', up.keyFile)
  }
  uploading.value = true
  try {
    const r = await fetch('/api/certificates/upload', { method: 'POST', body: fd, credentials: 'same-origin' })
    if (r.status === 401) throw new Error('未登录')
    if (!r.ok) throw new Error((await r.json()).error || '上传失败')
    ElMessage.success('证书已上传并校验通过')
    dlg.value = false
    up.name = ''; up.certFile = null; up.keyFile = null; up.zipFile = null
    load()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    uploading.value = false
  }
}

onMounted(() => { load(); loadAcme(); loadConsoleTls(); loadAcmeEntries(); timer = setInterval(() => { load(); loadAcmeEntries() }, 30000) })
onBeforeUnmount(() => { clearInterval(timer); stopAcmePoll() })
</script>

<style scoped>
.km-acme-spin { animation: km-acme-rotate 1.2s linear infinite; }
@keyframes km-acme-rotate { to { transform: rotate(360deg); } }
.km-acme-err {
  text-align: left; font-size: 12.5px; line-height: 1.7; color: var(--km-soft-red);
  background: var(--km-panel-2); border: 1px solid var(--km-line); border-radius: 8px;
  padding: 10px 12px; max-height: 180px; overflow: auto; white-space: pre-wrap; word-break: break-all;
}
</style>
