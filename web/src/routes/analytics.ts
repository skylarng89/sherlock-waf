import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/analytics',
      name: 'analytics',
      component: () => import('@/pages/analytics/AnalyticsPage.vue'),
      meta: { titleKey: 'analytics.title', permission: 'events:read' },
    },
  ],
  nav: [
    {
      id: 'analytics',
      to: '/analytics',
      labelKey: 'nav.analytics',
      icon: 'ti ti-chart-bar',
      order: 44,
      permission: 'events:read',
    },
  ],
} satisfies AreaModule
