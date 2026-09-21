// Shared timestamp helpers: stores keep RFC3339 UTC strings; the console
// renders them in the browser's local timezone.
function pad(n) { return String(n).padStart(2, '0') }

export function fmtTime(ts) {
  if (!ts) return '-'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return String(ts)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

// fmtRFC3339 renders a Date as RFC3339 with the local offset, accepted by
// the Go time.Parse(time.RFC3339, ...) on the server (no fractional seconds).
export function fmtRFC3339(d) {
  const off = -d.getTimezoneOffset()
  const sign = off >= 0 ? '+' : '-'
  const ah = pad(Math.floor(Math.abs(off) / 60))
  const am = pad(Math.abs(off) % 60)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${sign}${ah}:${am}`
}

export function fmtShort(ts) {
  if (!ts) return '-'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return String(ts)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}
