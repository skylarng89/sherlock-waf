import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/reports/would-block',
      name: 'would-block',
      component: () => import('@/pages/reports/WouldBlockPage.vue'),
      meta: { titleKey: 'reports.title', permission: 'events:read' },
    },
  ],
  nav: [
    {
      id: 'would-block',
      to: '/reports/would-block',
      labelKey: 'nav.wouldBlock',
      icon: 'ti ti-report-analytics',
      order: 46,
      permission: 'events:read',
    },
  ],
} satisfies AreaModule
