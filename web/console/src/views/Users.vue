<template>
  <div>
<el-card shadow="never" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="km-title" style="margin:0">控制台用户（RBAC）</div>
        <div style="flex:1"></div>
        <el-button type="primary" size="small" @click="openCreate"><el-icon><Plus /></el-icon>&nbsp;新增用户</el-button>
      </div>
    </el-card>

    <el-card shadow="never">
      <el-table :data="users" size="small">
        <el-table-column prop="username" label="用户名" width="150" />
        <el-table-column label="角色" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="{ admin: 'danger', operator: 'primary', auditor: 'info' }[row.role]" effect="dark" class="km-tag">
              {{ { admin: '管理员', operator: '运维', auditor: '审计' }[row.role] || row.role }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <span class="km-dot" :class="row.disabled ? 'bad' : 'ok'"></span>{{ row.disabled ? '已禁用' : '启用' }}
          </template>
        </el-table-column>
        <el-table-column label="MFA" width="90">
          <template #default="{ row }">
            <span class="km-dot" :class="row.totp_enabled ? 'ok' : ''"></span>{{ row.totp_enabled ? '已开启' : '未开启' }}
          </template>
        </el-table-column>
        <el-table-column label="API Key" width="150">
          <template #default="{ row }">
            <span v-if="row.api_key_id" class="km-key-id">{{ row.api_key_id }}</span>
            <span v-else style="opacity:.45">-</span>
          </template>
        </el-table-column>
        <el-table-column label="Key 最近使用" width="170">
          <template #default="{ row }">
            {{ row.api_key_last_used ? fmtTime(row.api_key_last_used) : (row.api_key_id ? '未使用' : '-') }}
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="170">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column min-width="300">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="genApiKey(row)">生成 Key</el-button>
            <el-button v-if="row.api_key_id" link type="warning" size="small" @click="revokeApiKey(row)">撤销 Key</el-button>
            <el-button v-if="!row.totp_enabled" link type="primary" size="small" @click="mfaSetup(row)">启用 MFA</el-button>
            <el-button v-else link type="warning" size="small" @click="mfaDisable(row)">关闭 MFA</el-button>
            <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dlg" :title="editing ? '编辑用户 · ' + edit.username : '新增用户'" width="440px">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="用户名" v-if="!editing">
          <el-input v-model="edit.username" placeholder="登录用户名" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="edit.role" style="width:100%">
            <el-option label="管理员（全部权限）" value="admin" />
            <el-option label="运维（发布配置/回滚）" value="operator" />
            <el-option label="审计（只读）" value="auditor" />
          </el-select>
        </el-form-item>
        <el-form-item :label="editing ? '新密码' : '密码'">
          <el-input v-model="edit.password" type="password" show-password :placeholder="editing ? '留空则不修改' : '至少 8 位'" />
        </el-form-item>
        <el-form-item label="禁用" v-if="editing">
          <el-switch v-model="edit.disabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlg = false">取消</el-button>
        <el-button type="primary" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="keyDlg" title="API Key 已生成" width="560px" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" show-icon
        title="请立即保存：此密钥仅显示一次，关闭后无法再次查看；重新生成会使旧密钥立即失效。" />
      <div class="km-key-box">{{ generatedKey }}</div>
      <template #footer>
        <el-button @click="copyKey">复制密钥</el-button>
        <el-button type="primary" @click="keyDlg = false">我已保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="mfaDlg" :title="'启用 MFA · ' + mfaUser" width="420px" :close-on-click-modal="false">
      <ol class="km-mfa-steps">
        <li>用认证器 App（Google Authenticator / 1Password 等）扫描二维码；</li>
        <li>输入 App 显示的 6 位动态码完成确认，确认后该账号登录需要动态码。</li>
      </ol>
      <img v-if="mfaQr" :src="'data:image/png;base64,' + mfaQr" class="km-qr" alt="TOTP 二维码" />
      <div class="km-key-box">{{ mfaSecret }}</div>
      <el-input v-model="mfaCode" placeholder="输入 6 位动态码确认" size="large" style="margin-top:10px" @keydown.enter="mfaConfirm" />
      <template #footer>
        <el-button @click="mfaDlg = false">取消</el-button>
        <el-button type="primary" @click="mfaConfirm">确认启用</el-button>
      </template>
    </el-dialog>

    <el-card shadow="never" style="margin-top:16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div class="km-title" style="margin:0;font-size:14px">变更记录</div>
        <div style="flex:1"></div>
        <el-button size="small" text @click="loadAudit">刷新</el-button>
      </div>
      <el-table :data="audit" size="small" max-height="320">
        <el-table-column label="时间" width="170">
          <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="actor" label="操作者" width="120" />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" class="km-tag">{{ actionLabel(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="target" label="对象" width="140" />
        <el-table-column prop="detail" label="详情" min-width="220" show-overflow-tooltip />
      </el-table>
    </el-card>
    <!-- RBAC 权限矩阵(静态展示,与服务端强制一致) -->
    <el-card shadow="never" style="margin-bottom:16px">
      <div class="km-title">角色权限矩阵（RBAC）</div>
      <el-table :data="rbac" size="small">
        <el-table-column prop="perm" label="权限" />
        <el-table-column label="admin" width="130" align="center">
          <template #default="{ row }"><el-tag size="small" :type="row.admin ? 'success' : 'info'" effect="plain" class="km-tag">{{ row.admin ? '✓' : '—' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="operator" width="130" align="center">
          <template #default="{ row }"><el-tag size="small" :type="row.operator ? 'success' : 'info'" effect="plain" class="km-tag">{{ row.operator ? (row.opNote || '✓') : '—' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="auditor" width="130" align="center">
          <template #default="{ row }"><el-tag size="small" :type="row.auditor ? 'success' : 'info'" effect="plain" class="km-tag">{{ row.auditor ? (row.audNote || '✓') : '—' }}</el-tag></template>
        </el-table-column>
      </el-table>
      <div class="km-dim" style="font-size:12px;margin-top:8px">
        权限在服务端强制执行；密码策略、会话超时与管理面板访问限制在「系统设置 → 安全设置」配置
      </div>
    </el-card>

    
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, del, patch, post } from '../api'
import { fmtTime } from '../timefmt'

const users = ref([])
const audit = ref([])
const dlg = ref(false)
const editing = ref(false)
const edit = reactive({ username: '', password: '', role: 'operator', disabled: false })

const rbac = [
  { perm: '查看仪表盘 / 日志 / 报表', admin: true, operator: true, auditor: true },
  { perm: '站点防护配置（保存并发布）', admin: true, operator: true, auditor: false },
  { perm: '策略管理（规则 / 名单 / IP 组 / SecLang）', admin: true, operator: true, auditor: false },
  { perm: '攻击日志一键加白', admin: true, operator: true, auditor: false },
  { perm: '证书上传 / 站点证书管理', admin: true, operator: true, auditor: false },
  { perm: '系统设置 / 用户管理', admin: true, operator: false, auditor: false },
  { perm: 'AI 助手（只读分析）', admin: true, operator: true, auditor: true, opNote: '只读', audNote: '只读' },
]

const actionLabels = {
  'user.create': '新建用户', 'user.update': '修改用户', 'user.delete': '删除用户',
  'apikey.create': '签发 API Key', 'apikey.revoke': '撤销 API Key',
  'mfa.enable': '启用 MFA', 'mfa.disable': '关闭 MFA'
}
const actionLabel = a => actionLabels[a] || a

const keyDlg = ref(false)
const generatedKey = ref('')
const mfaDlg = ref(false)
const mfaUser = ref('')
const mfaQr = ref('')
const mfaSecret = ref('')
const mfaCode = ref('')

async function loadAudit() {
  try { audit.value = await api('/api/audit/changes?limit=100') } catch (e) { /* 非管理员静默 */ }
}

async function load() {
  users.value = await api('/api/users')
  loadAudit()
}
function openCreate() {
  editing.value = false
  Object.assign(edit, { username: '', password: '', role: 'operator', disabled: false })
  dlg.value = true
}
function openEdit(row) {
  editing.value = true
  Object.assign(edit, { username: row.username, password: '', role: row.role, disabled: row.disabled })
  dlg.value = true
}
async function save() {
  try {
    if (editing.value) {
      const body = { role: edit.role }
      if (edit.password) body.password = edit.password
      body.disabled = edit.disabled
      await patch('/api/users/' + encodeURIComponent(edit.username), body)
    } else {
      await post('/api/users', { username: edit.username, password: edit.password, role: edit.role })
    }
    ElMessage.success('已保存')
    dlg.value = false
    load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}
function remove(row) {
  ElMessageBox.confirm('删除用户 ' + row.username + '？', '确认', { type: 'warning' })
    .then(async () => { await del('/api/users/' + encodeURIComponent(row.username)); load() })
    .catch(() => {})
}

async function genApiKey(row) {
  try {
    await ElMessageBox.confirm(
      '为 ' + row.username + ' 生成新的 API Key？' + (row.api_key_id ? '旧 Key 将立即失效。' : ''),
      '生成 API Key', { type: 'info' })
  } catch (e) { return }
  try {
    const d = await post('/api/users/' + encodeURIComponent(row.username) + '/apikey')
    generatedKey.value = d.api_key
    keyDlg.value = true
    load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}
function copyKey() {
  navigator.clipboard.writeText(generatedKey.value)
    .then(() => ElMessage.success('已复制到剪贴板'))
    .catch(() => ElMessage.warning('复制失败，请手动选择密钥文本复制'))
}
function revokeApiKey(row) {
  ElMessageBox.confirm(
    '撤销 ' + row.username + ' 的 API Key？使用该 Key 的脚本 / Prometheus 采集将立即失去访问权限。',
    '撤销 API Key', { type: 'warning' })
    .then(async () => { await del('/api/users/' + encodeURIComponent(row.username) + '/apikey'); ElMessage.success('已撤销'); load() })
    .catch(() => {})
}

async function mfaSetup(row) {
  try {
    const d = await post('/api/users/' + encodeURIComponent(row.username) + '/mfa/setup')
    mfaUser.value = row.username
    mfaQr.value = d.qr_png
    mfaSecret.value = d.secret
    mfaCode.value = ''
    mfaDlg.value = true
  } catch (e) {
    ElMessage.error(e.message)
  }
}
async function mfaConfirm() {
  try {
    await post('/api/users/' + encodeURIComponent(mfaUser.value) + '/mfa/confirm', { code: mfaCode.value.trim() })
    ElMessage.success('MFA 已启用')
    mfaDlg.value = false
    load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}
function mfaDisable(row) {
  ElMessageBox.confirm(
    '关闭 ' + row.username + ' 的 MFA？该账号登录将只需密码。',
    '关闭 MFA', { type: 'warning' })
    .then(async () => { await del('/api/users/' + encodeURIComponent(row.username) + '/mfa'); ElMessage.success('已关闭'); load() })
    .catch(() => {})
}

onMounted(load)
</script>

<style scoped>
.km-key-id {
  font-family: ui-monospace, monospace;
  font-size: 12px;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(255, 255, 255, .08);
}
.km-key-box {
  font-family: ui-monospace, monospace;
  font-size: 13px;
  word-break: break-all;
  padding: 10px 12px;
  border-radius: 8px;
  background: rgba(255, 255, 255, .06);
  border: 1px solid rgba(255, 255, 255, .1);
  margin-top: 10px;
  user-select: all;
}
.km-qr {
  display: block;
  margin: 12px auto;
  width: 180px;
  height: 180px;
  border-radius: 8px;
  background: #fff;
  padding: 6px;
}
.km-mfa-steps {
  margin: 0 0 4px 18px;
  padding: 0;
  font-size: 13px;
  opacity: .85;
  line-height: 1.8;
}
</style>
