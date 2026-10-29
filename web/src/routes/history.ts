import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/history',
      name: 'history',
      component: () => import('@/pages/history/HistoryPage.vue'),
      meta: { titleKey: 'history.title', permission: 'config:read' },
    },
    {
      path: '/history/:id',
      name: 'history-detail',
      component: () => import('@/pages/history/HistoryDetailPage.vue'),
      meta: { titleKey: 'history.detailTitle', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'history',
      to: '/history',
      labelKey: 'nav.history',
      icon: 'ti ti-history',
      order: 50,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
