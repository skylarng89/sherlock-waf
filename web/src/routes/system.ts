import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/system',
      name: 'system',
      component: () => import('@/pages/system/SystemPage.vue'),
      meta: { titleKey: 'system.title', permission: 'system:read' },
    },
  ],
  nav: [
    {
      id: 'system',
      to: '/system',
      labelKey: 'nav.system',
      icon: 'ti ti-server-cog',
      order: 85,
      permission: 'system:read',
    },
  ],
} satisfies AreaModule
