import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/tokens',
      name: 'tokens',
      component: () => import('@/pages/tokens/TokensPage.vue'),
      meta: { titleKey: 'tokens.title', permission: 'tokens:own' },
    },
  ],
  nav: [
    {
      id: 'tokens',
      to: '/tokens',
      labelKey: 'nav.tokens',
      icon: 'ti ti-key',
      order: 80,
      permission: 'tokens:own',
    },
  ],
} satisfies AreaModule
