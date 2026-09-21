<template>
  <el-container style="height:100vh">
    <el-aside width="224px" class="km-side">
      <div class="brand" @click="$router.push('/')">
        <div>
          <div class="name">King<span>Moat</span> WAF</div>
          <div class="slogan">固若金汤 · 御攻于无形</div>
        </div>
      </div>
      <div class="km-nav">
        <div class="km-menu-group">总览</div>
        <div class="km-nav-item" :class="{ active: $route.path === '/' }" @click="$router.push('/')">
          <el-icon><Odometer /></el-icon>防护总览
        </div>
        <template v-if="can('operator')">
          <div class="km-menu-group">防护</div>
          <div class="km-nav-item" :class="{ active: $route.path === '/sites' }" @click="$router.push('/sites')">
            <el-icon><Umbrella /></el-icon>站点防护
          </div>
          <div class="km-nav-item" :class="{ active: $route.path === '/policy' }" @click="$router.push('/policy')">
            <el-icon><Aim /></el-icon>策略管理
          </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/logs' }" @click="$router.push('/logs')">
          <el-icon><Document /></el-icon>攻击日志
          <span v-if="badge.blocked > 0" class="km-nav-badge">{{ blockedLabel }}</span>
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/access-logs' }" @click="$router.push('/access-logs')">
          <el-icon><Notebook /></el-icon>访问日志
        </div>
        </template>
        <div class="km-menu-group">资产与证书</div>
        <div class="km-nav-item" :class="{ active: $route.path === '/certs' }" @click="$router.push('/certs')">
          <el-icon><Postcard /></el-icon>证书管理
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/assets' }" @click="$router.push('/assets')">
          <el-icon><Grid /></el-icon>API 资产
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/risks' }" @click="$router.push('/risks')">
          <el-icon><Warning /></el-icon>风险中心
          <span v-if="badge.risks > 0" class="km-nav-badge">{{ badge.risks }}</span>
        </div>
        <div class="km-menu-group">系统</div>
        <div v-if="can('operator')" class="km-nav-item" :class="{ active: $route.path === '/settings' }" @click="$router.push('/settings')">
          <el-icon><Tools /></el-icon>系统设置
        </div>
        <div v-if="role() === 'admin'" class="km-nav-item" :class="{ active: $route.path === '/users' }" @click="$router.push('/users')">
          <el-icon><UserFilled /></el-icon>用户管理
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/ai' }" @click="$router.push('/ai')">
          <el-icon><ChatDotRound /></el-icon>AI 助手
          <span class="km-nav-badge plain">只读</span>
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/docs' }" @click="$router.push('/docs')">
          <el-icon><Tickets /></el-icon>API 文档
        </div>
        <div class="km-nav-item" :class="{ active: $route.path === '/about' }" @click="$router.push('/about')">
          <el-icon><InfoFilled /></el-icon>关于KingMoat
        </div>
      </div>
      <div class="km-side-slogan">Fortress for Every Request</div>
      <div class="km-side-foot">
        <div class="km-foot-row">
          <el-tooltip :content="themeLabel" placement="top">
            <el-button circle text @click="onToggleTheme">
              <el-icon><Sunny v-if="isDark" /><Moon v-else /></el-icon>
            </el-button>
          </el-tooltip>
          <el-tag size="small" effect="dark" class="km-tag" type="info">{{ roleLabel }}</el-tag>
          <div style="flex:1"></div>
          <el-dropdown trigger="click">
            <div class="km-avatar">{{ (user() || '?').slice(0, 1).toUpperCase() }}</div>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item disabled>
                  <span style="font-weight:600">{{ user() }}</span>
                </el-dropdown-item>
                <el-dropdown-item divided @click="account = true"><el-icon><User /></el-icon>我的账号</el-dropdown-item>
                <el-dropdown-item @click="logout"><el-icon><SwitchButton /></el-icon>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
    </el-aside>
    <el-container>
      <el-header class="km-head" height="56px">
        <div class="page-title">{{ pageTitle }}</div>
        <div class="spacer"></div>
      </el-header>
      <el-main class="km-main">
        <router-view />
      </el-main>
    </el-container>
    <MyAccount v-model="account" />

    <!-- AI 悬浮球:悬浮于任意页面,可拖动(位置记忆),点击打开抽屉 -->
    <div class="km-ai-fab-float" :style="{ left: fab.x + 'px', top: fab.y + 'px' }"
         title="AI 安全助手（可拖动）" @mousedown.prevent="fabDown" @click="onFabClick">
      <el-icon><ChatDotRound /></el-icon>
    </div>

    <!-- destroy-on-close: AIChat 每次打开抽屉重新挂载，重新拉取 /api/ai/config，
         避免抽屉复用旧实例导致「未启用/旧模型」陈旧展示（发布新配置后不刷新） -->
    <el-drawer v-model="aiDrawer" title="AI 安全助手" size="440px" :append-to-body="true" destroy-on-close>
      <AIChat inline />
    </el-drawer>
  </el-container>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, can, clearSession, role, user } from '../api'
import { applyTheme, getTheme } from '../theme'
import AIChat from '../views/AIChat.vue'
import MyAccount from './MyAccount.vue'

const aiDrawer = ref(false)
const account = ref(false)
const isDark = ref(getTheme() === 'dark')
const badge = reactive({ blocked: 0, risks: 0 })
let badgeTimer = null

const route = useRoute()
const router = useRouter()
const roleLabel = computed(() => ({ admin: '管理员', operator: '运维', auditor: '审计' }[role()] || role()))
const themeLabel = computed(() => (isDark.value ? '切换到浅色 · 量子青' : '切换到深色 · 暗域'))
const blockedLabel = computed(() => (badge.blocked > 999 ? '999+' : String(badge.blocked)))
const pageTitle = computed(() => ({
  '/': '防护总览',
  '/sites': '站点防护',
  '/policy': '策略管理',
  '/logs': '攻击日志',
  '/log': '日志详情',
  '/access-logs': '访问日志',
  '/certs': '证书管理',
  '/assets': 'API 资产',
  '/risks': '风险中心',
  '/ai': 'AI 助手',
  '/settings': '系统设置',
  '/users': '用户管理',
  '/docs': 'API 文档',
  '/about': '关于KingMoat',
}[route.path.startsWith('/log/') ? '/log' : route.path] || 'KingMoat Console'))

// AI 悬浮球:拖动(位置记忆)+ 点击与拖拽区分
const fab = reactive({ x: window.innerWidth - 84, y: window.innerHeight - 120, dragging: false, moved: false, dx: 0, dy: 0 })
try {
  const saved = JSON.parse(localStorage.getItem('km-ai-fab') || 'null')
  if (saved && typeof saved.x === 'number' && typeof saved.y === 'number') { fab.x = saved.x; fab.y = saved.y }
} catch (e) { /* default position */ }
function fabDown(ev) {
  fab.dragging = true
  fab.moved = false
  fab.dx = ev.clientX - fab.x
  fab.dy = ev.clientY - fab.y
  document.addEventListener('mousemove', fabMove)
  document.addEventListener('mouseup', fabUp)
}
function fabMove(ev) {
  if (!fab.dragging) return
  const nx = Math.min(Math.max(8, ev.clientX - fab.dx), window.innerWidth - 60)
  const ny = Math.min(Math.max(8, ev.clientY - fab.dy), window.innerHeight - 60)
  if (Math.abs(nx - fab.x) > 2 || Math.abs(ny - fab.y) > 2) fab.moved = true
  fab.x = nx
  fab.y = ny
}
function fabUp() {
  fab.dragging = false
  document.removeEventListener('mousemove', fabMove)
  document.removeEventListener('mouseup', fabUp)
  localStorage.setItem('km-ai-fab', JSON.stringify({ x: fab.x, y: fab.y }))
}
function onFabClick() {
  if (fab.moved) { fab.moved = false; return }
  aiDrawer.value = true
}

async function loadBadge() {
  try {
    const [st, risks] = await Promise.all([
      api('/api/stats'),
      api('/api/risks').catch(() => null),
    ])
    badge.blocked = st.blocked_today || 0
    badge.risks = Array.isArray(risks) ? risks.filter(r => !r.status || r.status === 'open' || r.status === 'pending').length : 0
  } catch (e) { /* silent: badge is cosmetic */ }
}
function onToggleTheme() {
  isDark.value = !isDark.value
  applyTheme(isDark.value ? 'dark' : 'light')
  window.dispatchEvent(new CustomEvent('km-theme-changed'))
}

function logout() {
  api('/api/logout', { method: 'POST' }).catch(() => {}).finally(() => {
    clearSession()
    router.push('/login')
  })
}

onMounted(() => {
  loadBadge()
  badgeTimer = setInterval(loadBadge, 30000)
})
onBeforeUnmount(() => { if (badgeTimer) clearInterval(badgeTimer) })
</script>
