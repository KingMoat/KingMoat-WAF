<template>
  <el-dialog v-model="dlg" title="我的账号" width="520px" @open="load">
    <el-descriptions :column="2" size="small" border style="margin-bottom:14px">
      <el-descriptions-item label="用户名">{{ me.username || '-' }}</el-descriptions-item>
      <el-descriptions-item label="角色">
        <el-tag size="small" effect="dark" class="km-tag">{{ roleLabel }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="MFA">{{ me.totp_enabled ? '已开启' : '未开启' }}</el-descriptions-item>
      <el-descriptions-item label="API Key">{{ me.api_key_id || '未签发' }}</el-descriptions-item>
    </el-descriptions>

    <el-divider content-position="left">API Key</el-divider>
    <div style="display:flex;gap:8px;align-items:center">
      <el-button size="small" type="primary" @click="genKey">{{ me.api_key_id ? '重新生成（旧 Key 立即失效）' : '生成 API Key' }}</el-button>
      <el-button v-if="me.api_key_id" size="small" @click="revokeKey">撤销</el-button>
      <span v-if="me.api_key_last_used" style="font-size:12px;opacity:.6">最近使用：{{ fmt(me.api_key_last_used) }}</span>
    </div>

    <el-divider content-position="left">MFA 两步验证（TOTP）</el-divider>
    <div style="display:flex;gap:8px;align-items:center">
      <el-button v-if="!me.totp_enabled" size="small" type="primary" @click="mfaSetup">启用 MFA</el-button>
      <el-button v-else size="small" @click="mfaDisable">关闭 MFA</el-button>
      <span style="font-size:12px;opacity:.6">开启后登录需要认证器 6 位动态码</span>
    </div>

    <el-divider content-position="left">修改密码</el-divider>
    <el-form label-width="92px" label-position="left" @submit.prevent>
      <el-form-item label="当前密码">
        <el-input v-model="pw.old" type="password" show-password size="small" autocomplete="current-password" />
      </el-form-item>
      <el-form-item label="新密码">
        <el-input v-model="pw.new" type="password" show-password size="small" placeholder="符合安全策略（用户管理 → 安全设置）" autocomplete="new-password" />
      </el-form-item>
      <el-form-item label="确认新密码">
        <el-input v-model="pw.confirm" type="password" show-password size="small" @keydown.enter="changePw" />
      </el-form-item>
      <div style="display:flex;justify-content:flex-end">
        <el-button size="small" type="primary" :loading="pwBusy" @click="changePw">修改密码</el-button>
      </div>
    </el-form>

    <el-dialog v-model="keyDlg" title="API Key 已生成" width="480px" append-to-body :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" show-icon
        title="请立即保存：此密钥仅显示一次，关闭后无法再次查看。" />
      <div class="km-me-key">{{ generatedKey }}</div>
      <template #footer>
        <el-button size="small" @click="copyKey">复制密钥</el-button>
        <el-button size="small" type="primary" @click="keyDlg = false">我已保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="mfaDlg" title="启用 MFA" width="400px" append-to-body :close-on-click-modal="false">
      <img v-if="mfaQr" :src="'data:image/png;base64,' + mfaQr" class="km-me-qr" alt="TOTP 二维码" />
      <div class="km-me-key">{{ mfaSecret }}</div>
      <el-input v-model="mfaCode" placeholder="输入 6 位动态码确认" style="margin-top:10px" @keydown.enter="mfaConfirm" />
      <template #footer>
        <el-button size="small" @click="mfaDlg = false">取消</el-button>
        <el-button size="small" type="primary" @click="mfaConfirm">确认启用</el-button>
      </template>
    </el-dialog>
  </el-dialog>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, del, post, role } from '../api'
import { fmtTime } from '../timefmt'

const dlg = defineModel({ type: Boolean, default: false })

const me = reactive({ username: '', role: '', api_key_id: '', api_key_last_used: '', totp_enabled: false })
const roleLabel = computed(() => ({ admin: '管理员', operator: '运维', auditor: '审计' }[me.role] || me.role || role()))

const keyDlg = ref(false)
const generatedKey = ref('')

// 修改密码(自身账号;新密码须符合安全策略,后端校验)
const pwBusy = ref(false)
const pw = reactive({ old: '', new: '', confirm: '' })
async function changePw() {
  if (!pw.old || !pw.new) return ElMessage.warning('请填写当前密码与新密码')
  if (pw.new !== pw.confirm) return ElMessage.error('两次输入的新密码不一致')
  pwBusy.value = true
  try {
    await post('/api/me/password', { old_password: pw.old, new_password: pw.new })
    ElMessage.success('密码已修改,下次登录使用新密码')
    pw.old = ''; pw.new = ''; pw.confirm = ''
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    pwBusy.value = false
  }
}
const mfaDlg = ref(false)
const mfaQr = ref('')
const mfaSecret = ref('')
const mfaCode = ref('')

async function load() {
  try {
    const d = await api('/api/me')
    Object.assign(me, d)
  } catch (e) {
    ElMessage.error(e.message)
  }
}
const fmt = fmtTime

async function genKey() {
  try {
    await ElMessageBox.confirm(
      me.api_key_id ? '重新生成会使旧 Key 立即失效，确定？' : '为当前账号生成 API Key？',
      '生成 API Key', { type: 'info' })
  } catch (e) { return }
  try {
    const d = await post('/api/me/apikey')
    generatedKey.value = d.api_key
    keyDlg.value = true
    load()
  } catch (e) { ElMessage.error(e.message) }
}
function copyKey() {
  navigator.clipboard.writeText(generatedKey.value)
    .then(() => ElMessage.success('已复制到剪贴板'))
    .catch(() => ElMessage.warning('复制失败，请手动选择密钥文本复制'))
}
function revokeKey() {
  ElMessageBox.confirm('撤销当前 API Key？使用它的脚本将立即失去访问权限。', '撤销 API Key', { type: 'warning' })
    .then(async () => { await del('/api/me/apikey'); ElMessage.success('已撤销'); load() })
    .catch(() => {})
}

async function mfaSetup() {
  try {
    const d = await post('/api/me/mfa/setup')
    mfaQr.value = d.qr_png
    mfaSecret.value = d.secret
    mfaCode.value = ''
    mfaDlg.value = true
  } catch (e) { ElMessage.error(e.message) }
}
async function mfaConfirm() {
  try {
    await post('/api/me/mfa/confirm', { code: mfaCode.value.trim() })
    ElMessage.success('MFA 已启用')
    mfaDlg.value = false
    load()
  } catch (e) { ElMessage.error(e.message) }
}
function mfaDisable() {
  ElMessageBox.confirm('关闭 MFA 后登录只需密码，确定？', '关闭 MFA', { type: 'warning' })
    .then(async () => { await del('/api/me/mfa'); ElMessage.success('已关闭'); load() })
    .catch(() => {})
}
</script>

<style scoped>
.km-me-key {
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
.km-me-qr {
  display: block;
  margin: 10px auto;
  width: 170px;
  height: 170px;
  border-radius: 8px;
  background: #fff;
  padding: 6px;
}
</style>
