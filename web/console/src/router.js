import { createRouter, createWebHashHistory } from 'vue-router'
import { role } from './api'

const routes = [
  { path: '/login', component: () => import('./views/Login.vue'), meta: { public: true } },
  { path: '/change-password', component: () => import('./views/ChangePassword.vue') },
  {
    path: '/',
    component: () => import('./components/Layout.vue'),
    children: [
      { path: '', component: () => import('./views/Dashboard.vue') },
      { path: 'sites', component: () => import('./views/Sites.vue'), meta: { perm: 'operator' } },
      { path: 'logs', component: () => import('./views/Logs.vue') },
      { path: 'log/:traceId', component: () => import('./views/LogDetail.vue') },
      { path: 'access-logs', component: () => import('./views/AccessLogs.vue') },
      { path: 'certs', component: () => import('./views/Certs.vue') },
      { path: 'assets', component: () => import('./views/Assets.vue') },
      { path: 'risks', component: () => import('./views/Risks.vue') },
      { path: 'ai', component: () => import('./views/AIChat.vue') },
      { path: 'docs', component: () => import('./views/APIDocs.vue') },
      { path: 'about', component: () => import('./views/About.vue') },
      { path: 'policy', component: () => import('./views/Policy.vue'), meta: { perm: 'operator' } },
      { path: 'settings', component: () => import('./views/Settings.vue'), meta: { perm: 'operator' } },
      { path: 'users', component: () => import('./views/Users.vue'), meta: { perm: 'admin' } }
    ]
  }
]

const router = createRouter({ history: createWebHashHistory(), routes })

router.beforeEach((to) => {
  if (to.meta.public) return true
  if (!localStorage.getItem('km_role')) return '/login'
  if (to.meta.perm === 'admin' && role() !== 'admin') return '/'
  if (to.meta.perm === 'operator' && role() === 'auditor') return '/'
  return true
})

export default router
