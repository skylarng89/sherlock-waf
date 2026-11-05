import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/access',
      name: 'access',
      component: () => import('@/pages/access/AccessPage.vue'),
      meta: { titleKey: 'access.title', permission: 'config:read' },
    },
    {
      path: '/sites/:site/acl',
      name: 'site-acl',
      component: () => import('@/pages/access/SiteAccessPage.vue'),
      props: { section: 'acl' },
      meta: { titleKey: 'access.site.aclTitle', permission: 'config:read' },
    },
    {
      path: '/sites/:site/rate-limits',
      name: 'site-rate-limits',
      component: () => import('@/pages/access/SiteAccessPage.vue'),
      props: { section: 'rate-limits' },
      meta: { titleKey: 'access.site.rateLimitsTitle', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'access',
      to: '/access',
      labelKey: 'access.nav',
      icon: 'ti ti-shield-lock',
      order: 35,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
