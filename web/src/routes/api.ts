import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/sites/:site/api',
      name: 'site-api',
      component: () => import('@/pages/api/SiteApiPage.vue'),
      meta: { titleKey: 'api.tab', permission: 'config:read' },
    },
  ],
  nav: [],
} satisfies AreaModule
