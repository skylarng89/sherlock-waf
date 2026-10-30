import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/bans',
      name: 'bans',
      component: () => import('@/pages/bans/BansPage.vue'),
      meta: { titleKey: 'bans.title', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'bans',
      to: '/bans',
      labelKey: 'bans.nav',
      icon: 'ti ti-ban',
      order: 36,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
