import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/sites/:site/login-protection',
      name: 'site-login',
      component: () => import('@/pages/login/SiteLoginPage.vue'),
      meta: { titleKey: 'login.title', permission: 'config:read' },
    },
  ],
  nav: [],
} satisfies AreaModule
