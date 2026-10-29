import type { AreaModule } from './types'

// Owned by the foundation. Sign-in is a three-step flow; the guard keeps users on the right step.
export default {
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/pages/auth/LoginPage.vue'),
      meta: { layout: 'auth', public: true, titleKey: 'auth.login.title' },
    },
    {
      path: '/login/mfa',
      name: 'login-mfa',
      component: () => import('@/pages/auth/LoginMfaPage.vue'),
      meta: { layout: 'auth', public: true, titleKey: 'auth.mfa.title' },
    },
    {
      path: '/login/enrol',
      name: 'login-enrol',
      component: () => import('@/pages/auth/LoginEnrolPage.vue'),
      meta: { layout: 'auth', public: true, titleKey: 'auth.enrol.title' },
    },
  ],
  nav: [],
} satisfies AreaModule
