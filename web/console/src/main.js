import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import * as Icons from '@element-plus/icons-vue'
import App from './App.vue'
import router from './router'
import './styles.css'
import { initTheme } from './theme'

initTheme()

const app = createApp(App)
for (const [name, comp] of Object.entries(Icons)) app.component(name, comp)
app.use(ElementPlus)
app.use(router)
app.mount('#app')
