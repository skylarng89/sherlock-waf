import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/sites/:site/data-protection',
      name: 'site-dlp',
      component: () => import('@/pages/dlp/SiteDlpPage.vue'),
      meta: { titleKey: 'dlp.title', permission: 'config:read' },
    },
  ],
  nav: [],
} satisfies AreaModule
