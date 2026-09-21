import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev/preview API target. Defaults to a local backend; point it at a real
// console to iterate the UI against live data:
//   KINGMOAT_API_PROXY=https://console.example.com:8443 npm run preview
const apiTarget = process.env.KINGMOAT_API_PROXY || 'http://127.0.0.1:8081'
const proxy = { '/api': { target: apiTarget, changeOrigin: true, secure: false }, '/mcp': { target: apiTarget, changeOrigin: true, secure: false } }

export default defineConfig({
  plugins: [vue()],
  base: './',
  server: {
    port: 5174,
    proxy
  },
  preview: {
    port: 4173,
    proxy
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1500
  }
})
