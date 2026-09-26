// 全局监听地址解析（站点防护页前置校验与系统设置「数据面监听」共用）。
// 解析监听地址，支持「:80」（全部接口）、「0.0.0.0:80」、「[::]:443」（IPv6）、「主机名:端口」；
// 空值合法（HTTP 可关，HTTPS 有站点级前置条件），返回 { ok, empty, port, msg }
export function parseListenAddr(v) {
  const s = String(v ?? '').trim()
  if (!s) return { ok: true, empty: true }
  let host, portStr
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    if (end < 0) return { ok: false, msg: 'IPv6 地址需用方括号包裹，如 [::]:443' }
    host = s.slice(1, end)
    if (!host || !host.includes(':') || !/^[0-9a-fA-F:.]+$/.test(host)) return { ok: false, msg: '方括号内应为 IPv6 地址，如 [::]' }
    const rest = s.slice(end + 1)
    if (!rest.startsWith(':')) return { ok: false, msg: '格式应为 [IPv6地址]:端口，如 [::]:443' }
    portStr = rest.slice(1)
  } else {
    const i = s.lastIndexOf(':')
    if (i <= 0) {
      if (i === 0) { host = ''; portStr = s.slice(1) }
      else return { ok: false, msg: '格式应为 host:端口，如 0.0.0.0:80 或 :80' }
    } else {
      host = s.slice(0, i)
      portStr = s.slice(i + 1)
    }
  }
  if (!/^\d{1,5}$/.test(portStr)) return { ok: false, msg: '端口须为 1-65535 的数字' }
  const port = Number(portStr)
  if (port < 1 || port > 65535) return { ok: false, msg: '端口须在 1-65535 范围内' }
  // 含冒号的 host 只可能来自方括号分支（已按 IPv6 字符集校验过），此处只校验 IPv4/主机名；
  // 修复：原实现把 [::]:443 的 host「::」误判为非法（假拒绝，与提示文案矛盾）
  if (host && !host.includes(':') && !/^[0-9a-zA-Z._-]+$/.test(host)) return { ok: false, msg: '地址仅支持 IP 或主机名' }
  return { ok: true, empty: false, port }
}
