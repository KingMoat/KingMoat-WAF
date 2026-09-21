// Minimal safe-by-construction markdown renderer for chat bubbles.
// Escapes ALL HTML first, then converts the escaped text to a small set of
// block/inline elements (headings, bold, inline code, fenced code, lists,
// links). Because escaping happens before any transformation, injected tags
// can never survive — safe for AI output derived from attacker-controlled
// log data.

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

function inline(s) {
  return s
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/`([^`]+)`/g, '<code class="md-inline">$1</code>')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener" class="md-link">$1</a>')
}

export function mdToHtml(src) {
  const lines = esc(src || '').split('\n')
  let html = ''
  let inCode = false
  let codeLines = []
  let listOpen = null
  const closeList = () => {
    if (listOpen) {
      html += '</' + listOpen + '>'
      listOpen = null
    }
  }
  for (const rawLine of lines) {
    const line = rawLine
    if (/^```/.test(line.trim())) {
      if (inCode) {
        html += '<pre class="md-code">' + codeLines.join('\n') + '</pre>'
        inCode = false
        codeLines = []
      } else {
        closeList()
        inCode = true
        codeLines = []
      }
      continue
    }
    if (inCode) {
      codeLines.push(line)
      continue
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/)
    if (h) {
      closeList()
      const lv = Math.min(h[1].length + 2, 6)
      html += '<div class="md-h md-h' + lv + '">' + inline(h[2]) + '</div>'
      continue
    }
    const ul = line.match(/^\s*[-*]\s+(.*)$/)
    if (ul) {
      if (listOpen !== 'ul') {
        closeList()
        html += '<ul class="md-list">'
        listOpen = 'ul'
      }
      html += '<li>' + inline(ul[1]) + '</li>'
      continue
    }
    const ol = line.match(/^\s*\d+[.、)]\s+(.*)$/)
    if (ol) {
      if (listOpen !== 'ol') {
        closeList()
        html += '<ol class="md-list">'
        listOpen = 'ol'
      }
      html += '<li>' + inline(ol[1]) + '</li>'
      continue
    }
    closeList()
    if (line.trim() === '') continue
    html += '<p class="md-p">' + inline(line) + '</p>'
  }
  if (inCode) html += '<pre class="md-code">' + codeLines.join('\n') + '</pre>'
  closeList()
  return html
}
