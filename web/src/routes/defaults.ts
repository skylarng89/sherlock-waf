import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/defaults',
      name: 'defaults',
      component: () => import('@/pages/defaults/DefaultsPage.vue'),
      meta: { titleKey: 'defaults.title', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'defaults',
      to: '/defaults',
      labelKey: 'nav.defaults',
      icon: 'ti ti-adjustments',
      order: 30,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
