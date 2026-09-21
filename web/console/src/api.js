// Console API client: fetch wrapper with session handling + role store.
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
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts
  })
  if (r.status === 401) {
    clearSession()
    location.hash = '#/login'
    throw new Error('未登录或会话已过期')
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
