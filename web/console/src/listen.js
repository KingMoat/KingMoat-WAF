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
    if (!host || !host.includes(':') || /:::/.test(host) || (host.match(/::/g) || []).length > 1 || !/^[0-9a-fA-F:.]+$/.test(host)) return { ok: false, msg: '方括号内应为 IPv6 地址，如 [::]' }
    // IPv6 组结构校验（与 net.ParseIP 规则对齐，防 typo 持久化后数据面 net.Listen
    // 失败 os.Exit(1)）：每组 1-4 位 hex；无 :: 时必须正好 8 组（[1:2] 非法）；
    // 有 :: 时有效组数 ≤ 7（[1:2:3:4:5:6:7:8::] 超长非法）；空组仅允许来自
    // :: 两侧（开头/结尾 1 个、单独 :: 为 2 个）
    const groups = host.split(':')
    if (groups.some(g => g && !/^[0-9a-fA-F]{1,4}$/.test(g))) return { ok: false, msg: '方括号内应为 IPv6 地址，如 [::]（每组 1-4 位十六进制）' }
    const nEmpty = groups.filter(g => g === '').length
    if (host.includes('::')) {
      const nValid = groups.length - nEmpty
      // split(':') 空段语义：'::X'/'X::' 切出 2 空、'::' 自身切出 3 空、
      // 'X::Y' 切出 1 空；有效组数（:: 展开后）不得超过 7（[1:2:3:4:5:6:7:8::] 非法）
      const wellFormed = nEmpty === 3 ? host === '::' : nEmpty === 1 || nEmpty === 2
      if (!wellFormed || (nEmpty < 3 && nValid > 7)) {
        return { ok: false, msg: '方括号内应为 IPv6 地址，如 [::]（:: 压缩段仅一处）' }
      }
    } else if (nEmpty !== 0 || groups.length !== 8) {
      return { ok: false, msg: '方括号内应为完整 IPv6 地址（8 组，如 [fe80::1] 请写作 [fe80:0:0:0:0:0:0:1] 或含 :: 压缩）' }
    }
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
    // 非括号分支按 lastIndexOf(':') 切分，`::80`/`abc::80` 一类多冒号输入切出的 host
    // 必含 ':'，一律拒绝；IPv6 必须走上方 [::]:端口 括号形式，否则数据面 net.Listen 失败
    if (host.includes(':')) return { ok: false, msg: 'IPv6 地址需用方括号包裹，如 [::]:443' }
  }
  if (!/^\d{1,5}$/.test(portStr)) return { ok: false, msg: '端口须为 1-65535 的数字' }
  const port = Number(portStr)
  if (port < 1 || port > 65535) return { ok: false, msg: '端口须在 1-65535 范围内' }
  // 至此 host 只可能为：空（:80 形式）、方括号内 IPv6（已按字符集与压缩段校验）、
  // 或非括号分支切出的 IPv4/主机名（多冒号输入已在分支内拒绝）——此处只校验 IPv4/主机名字符集；
  // 勿对含冒号 host 加豁免：那会重新放行非括号形式的多冒号输入（如 ::80，回归）
  if (host && !host.includes(':') && !/^[0-9a-zA-Z._-]+$/.test(host)) return { ok: false, msg: '地址仅支持 IP 或主机名' }
  return { ok: true, empty: false, port }
}
