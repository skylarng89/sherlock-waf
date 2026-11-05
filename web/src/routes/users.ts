import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/users',
      name: 'users',
      component: () => import('@/pages/users/UsersPage.vue'),
      meta: { titleKey: 'users.title', permission: 'users:manage' },
    },
  ],
  nav: [
    {
      id: 'users',
      to: '/users',
      labelKey: 'nav.users',
      icon: 'ti ti-users',
      order: 70,
      permission: 'users:manage',
    },
  ],
} satisfies AreaModule
