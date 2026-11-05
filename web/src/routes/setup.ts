import type { AreaModule } from './types'

// No nav item: the wizard is only reachable while no users exist (the guard enforces it).
export default {
  routes: [
    {
      path: '/setup',
      name: 'setup',
      component: () => import('@/pages/setup/SetupPage.vue'),
      meta: { layout: 'auth', public: true, wide: true, titleKey: 'setup.title' },
    },
    {
      // The guard closes /setup once an admin exists, so steps 2-4 live here; the sign-in
      // flow returns to it (`?redirect=/welcome`). Not under /setup: safeRedirect refuses that.
      path: '/welcome',
      name: 'setup-continue',
      component: () => import('@/pages/setup/SetupContinuePage.vue'),
      meta: { layout: 'auth', wide: true, titleKey: 'setup.title', permission: 'config:write' },
    },
  ],
  nav: [],
} satisfies AreaModule
