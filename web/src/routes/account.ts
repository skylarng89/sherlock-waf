import type { AreaModule } from './types'

// Reachable from the account menu, not the sidebar. Partial (pre-MFA) sessions
// never see the menu entry, and the API refuses them anyway.
export default {
  routes: [
    {
      path: '/account',
      name: 'account',
      component: () => import('@/pages/account/AccountPage.vue'),
      meta: { titleKey: 'account.title' },
    },
  ],
  nav: [],
} satisfies AreaModule
