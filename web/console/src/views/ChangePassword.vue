<template>
  <div class="km-cp-wrap">
    <div class="km-cp-card">
      <div class="km-cp-title">首次登录 · 请修改初始密码</div>
      <div class="km-cp-sub">检测到该账户仍在使用初始密码。为保障控制台安全，修改密码后才能继续使用。</div>
      <el-form label-position="top" @submit.prevent="doChange">
        <el-form-item label="当前密码">
          <el-input v-model="form.oldPassword" type="password" show-password size="large" autocomplete="current-password" @keydown.enter="doChange" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="form.newPassword" type="password" show-password size="large" placeholder="至少 8 位" @keydown.enter="doChange" />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="form.confirm" type="password" show-password size="large" @keydown.enter="doChange" />
        </el-form-item>
        <div v-if="msg" class="km-cp-err">{{ msg }}</div>
        <el-button type="primary" size="large" style="width:100%" :loading="busy" @click="doChange">修改密码并进入控制台</el-button>
        <el-button link style="width:100%;margin-top:8px" @click="logout">退出登录</el-button>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { post, clearSession } from '../api'

const router = useRouter()
const form = reactive({ oldPassword: '', newPassword: '', confirm: '' })
const busy = ref(false)
const msg = ref('')

onMounted(() => {
  const u = sessionStorage.getItem('km_pending_change')
  if (!u) router.replace('/login')
})

async function doChange() {
  msg.value = ''
  if (!form.newPassword || form.newPassword.length < 8) { msg.value = '新密码至少 8 位'; return }
  if (form.newPassword !== form.confirm) { msg.value = '两次输入的新密码不一致'; return }
  busy.value = true
  try {
    await post('/api/me/password', { old_password: form.oldPassword, new_password: form.newPassword })
    sessionStorage.removeItem('km_pending_change')
    await post('/api/logout')
    clearSession()
    // 改密成功后回到登录页，用新密码正式进入控制台。
    router.replace('/login')
  } catch (e) {
    msg.value = e.message
  } finally {
    busy.value = false
  }
}

async function logout() {
  try { await post('/api/logout') } catch (e) { /* session may already be gone */ }
  sessionStorage.removeItem('km_pending_change')
  clearSession()
  router.replace('/login')
}
</script>

<style scoped>
.km-cp-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--km-bg-1, #f6f7f9), var(--km-bg-2, #eef1f5)); }
.km-cp-card { width: 420px; padding: 36px 40px; border-radius: 14px; background: var(--km-card-bg, #fff);
  box-shadow: 0 6px 28px rgba(15, 23, 42, .1); }
.km-cp-title { font-size: 19px; font-weight: 700; margin-bottom: 8px; }
.km-cp-sub { font-size: 13px; color: var(--km-txt-3, #8f959e); margin-bottom: 20px; line-height: 1.6; }
.km-cp-err { color: var(--km-red, #d4380d); font-size: 13px; margin-bottom: 10px; }
</style>
