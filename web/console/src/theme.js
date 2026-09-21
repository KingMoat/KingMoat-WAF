// Theme system: dual-theme support aligned with the UI 2.0 prototype.
// "light" (量子青 Quantum Teal, default) and "dark" (暗域 Dark Matter).
// Element Plus dark css-vars react to the `dark` class on <html>; our own
// design tokens react to the `data-theme` attribute.
const KEY = 'km-theme'

export function getTheme() {
  const v = localStorage.getItem(KEY)
  return v === 'dark' ? 'dark' : 'light'
}

export function applyTheme(t) {
  const theme = t === 'dark' ? 'dark' : 'light'
  localStorage.setItem(KEY, theme)
  const el = document.documentElement
  el.setAttribute('data-theme', theme)
  el.classList.toggle('dark', theme === 'dark')
}

export function toggleTheme() {
  const next = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}

// applyThemeBoot runs before Vue mounts (index.html inline script already
// handles first paint; this keeps element-plus class in sync on load).
export function initTheme() {
  applyTheme(getTheme())
}

// ECharts theme objects, one per theme. Pages re-setOption on theme change.
export function chartPalette(theme) {
  if (theme === 'dark') {
    return {
      textColor: '#e6edf7',
      subText: '#8b9bb4',
      axisLine: '#1b2942',
      splitLine: '#16223a',
      tooltipBg: '#111b30',
      tooltipBorder: '#2a3d63',
      series: ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#22d3ee', '#f87171', '#34d399'],
      areaOpacity: 0.18,
      donutLabel: '#8b9bb4',
    }
  }
  return {
    textColor: '#1b2a38',
    subText: '#5e6f82',
    axisLine: '#e3e9ef',
    splitLine: '#eaeff4',
    tooltipBg: '#ffffff',
    tooltipBorder: '#e3e9ef',
    series: ['#0fae8e', '#dc2626', '#0a9e6b', '#d97706', '#7c3aed', '#0d9488', '#f87171', '#34d399'],
    areaOpacity: 0.14,
    donutLabel: '#5e6f82',
  }
}
