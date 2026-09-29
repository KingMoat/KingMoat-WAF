// Console API client: fetch wrapper with session handling + role store.
import { ElMessage } from 'element-plus'

const state = { role: localStorage.getItem('km_role') || '', user: localStorage.getItem('km_user') || '' }

export function setSession(role, user) {
  state.role = role
  state.user = user
  localStorage.setItem('km_role', role)
  localStorage.setItem('km_user', user)
}
export function clearSession() {
  state.role = ''
  state.user = ''
  localStorage.removeItem('km_role')
  localStorage.removeItem('km_user')
}
export function role() { return state.role }
export function user() { return state.user }
export function can(level) {
  const order = { auditor: 1, operator: 2, admin: 3 }
  return (order[state.role] || 0) >= (order[level] || 99)
}

export async function api(path, opts = {}) {
  const { raw401, ...init } = opts
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...init
  })
  if (r.status === 401 && !raw401) {
    clearSession()
    location.hash = '#/login'
    throw new Error('未登录或会话已过期')
  }
  if (r.status === 401) {
    let code = '', msg = r.statusText
    try { const j = await r.json(); code = j.error || ''; msg = j.message || j.error || msg } catch (e) { /* keep */ }
    const err = new Error(msg)
    err.status = 401
    err.code = code
    throw err
  }
  if (r.status === 403) {
    let m403 = r.statusText
    try { m403 = (await r.clone().json()).error || m403 } catch (e) { /* keep */ }
    // 初始密码未改：任何被拒的请求都把浏览器引导到强制改密页。
    if (String(m403).includes('password_change_required') && !location.hash.startsWith('#/change-password')) {
      sessionStorage.setItem('km_pending_change', localStorage.getItem('km_user') || '')
      location.hash = '#/change-password'
      throw new Error('请先修改初始密码')
    }
    const err = new Error(m403)
    err.status = 403
    throw err
  }
  if (!r.ok) {
    let code = '', msg = r.statusText
    try { const j = await r.json(); code = j.error || ''; msg = j.message || j.error || msg } catch (e) { /* keep */ }
    const err = new Error(msg)
    err.status = r.status
    err.code = code
    throw err
  }
  return r.json()
}

export async function post(path, body) {
  return api(path, { method: 'POST', body: JSON.stringify(body ?? {}) })
}
export async function patch(path, body) {
  return api(path, { method: 'PATCH', body: JSON.stringify(body ?? {}) })
}
export async function del(path) {
  return api(path, { method: 'DELETE' })
}

// 发布/回滚响应的 apply 三态统一提示（T-03 发布真实性契约）：applied = 引擎
// 已加载新修订；failed = 修订已落库但引擎加载失败（fail-static 保留旧配置），
// 必须如实报错而非宣称“已热生效”；pending = 同步等待超时，引擎应用结果待
// 确认，由 Layout 对 /api/status 的轮询收敛；旧后端响应无 apply 字段时退化
// 为普通成功提示。返回是否可按成功处理。
export function applyNotice(r, okMsg) {
  const st = r && r.apply && r.apply.status
  if (st === 'failed') {
    ElMessage.error('配置已保存（版本 ' + (r.revision ?? '-') + '）但引擎应用失败，旧配置继续生效：' + (r.apply.error || '未知原因'))
    return false
  }
  if (st === 'pending') {
    ElMessage.warning('引擎应用中，结果将自动刷新')
    return false
  }
  ElMessage.success(okMsg)
  return true
}
