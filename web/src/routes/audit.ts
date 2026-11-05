import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/audit',
      name: 'audit',
      component: () => import('@/pages/audit/AuditPage.vue'),
      meta: { titleKey: 'audit.title', permission: 'audit:read' },
    },
  ],
  nav: [
    {
      id: 'audit',
      to: '/audit',
      labelKey: 'nav.audit',
      icon: 'ti ti-list-search',
      order: 60,
      permission: 'audit:read',
    },
  ],
} satisfies AreaModule
