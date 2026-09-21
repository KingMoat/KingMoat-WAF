<template>
  <div class="km-login-wrap">
    <!-- 左侧:品牌区 -->
    <div class="km-login-left">
      <div>
        <div class="lg-name" style="margin-top:16px">KingMoat WAF</div>
        <div class="lg-slogan">固若金汤 · 御攻于无形</div>
        <div class="lg-slogan-en">KingMoat · Fortress for Every Request</div>
      </div>
      <ul class="lg-feats">
        <li><i>1</i><span>真开源，不限量：QPS 并发与站点数均不设上限（木兰宽松许可证 MulanPSL-2.0）</span></li>
        <li><i>2</i><span>Coraza + OWASP CRS 双引擎语义检测，libinjection 精准识别 SQLi / XSS</span></li>
        <li><i>3</i><span>站点防护图形化配置：签名 / 语义 / CC / GeoIP / 动态防护逐项开关</span></li>
        <li><i>4</i><span>攻击日志全量溯源，命中规则 ID 可一键提交 AI 安全分析师解读</span></li>
        <li><i>5</i><span>审计日志可外发 Elasticsearch / Loki / ClickHouse / S3 / Syslog</span></li>
      </ul>
      <div class="lg-foot">© KingMoat WAF · 固若金汤，御攻于无形<br />开源许可 <a href="https://opensource.org/license/mulanpsl-2-0" target="_blank" style="color:var(--km-cyan);text-decoration:none">MulanPSL-2.0</a></div>
    </div>
    <!-- 右侧:从登录位开始向右的渐变毛玻璃 + 登录卡(无边框) -->
    <div class="km-login-right">
      <div class="km-login-card">
        <div class="lg-title">登录控制台</div>
        <div class="lg-desc">请输入管理员账号与密码继续。</div>
        <el-form @submit.prevent="doLogin">
          <el-form-item>
            <el-input v-model="form.username" placeholder="用户名" size="large" autocomplete="username">
              <template #prefix><el-icon><User /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-form-item>
            <el-input v-model="form.password" type="password" placeholder="密码" size="large" show-password autocomplete="current-password" @keydown.enter="doLogin">
              <template #prefix><el-icon><Lock /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-form-item v-if="needTotp">
            <el-input v-model="form.totp" placeholder="两步验证码（6 位动态码）" size="large" @keydown.enter="doLogin">
              <template #prefix><el-icon><Key /></el-icon></template>
            </el-input>
          </el-form-item>
          <el-button type="primary" size="large" style="width:100%" :loading="busy" @click="doLogin">
            登 录
          </el-button>
          <div class="km-dim" style="margin-top:14px;font-size:12px;text-align:center;min-height:16px">{{ msg }}</div>
        </el-form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { reactive, ref } from 'vue'
import { post, setSession } from '../api'

const router = useRouter()
const form = reactive({ username: '', password: '', totp: '' })
const busy = ref(false)
const needTotp = ref(false)
const msg = ref('')

async function doLogin() {
  busy.value = true
  msg.value = ''
  try {
    const r = await post('/api/login', { username: form.username, password: form.password, totp: form.totp })
    setSession(r.role || 'admin', form.username || 'admin')
    // 初始密码账户：先进入强制改密页，改完才能进控制台。
    if (r.must_change) {
      sessionStorage.setItem('km_pending_change', form.username || 'admin')
      router.push('/change-password')
      return
    }
    router.push('/')
  } catch (e) {
    msg.value = e.message
    if (String(e.message).includes('两步') || String(e.message).includes('totp')) needTotp.value = true
  } finally {
    busy.value = false
  }
}
</script>
