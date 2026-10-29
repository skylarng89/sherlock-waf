import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/',
      name: 'overview',
      component: () => import('@/pages/overview/OverviewPage.vue'),
      meta: { titleKey: 'overview.title' },
    },
  ],
  nav: [
    {
      id: 'overview',
      to: '/',
      labelKey: 'nav.overview',
      icon: 'ti ti-layout-dashboard',
      order: 10,
    },
  ],
} satisfies AreaModule
