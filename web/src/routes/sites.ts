import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/sites',
      name: 'sites',
      component: () => import('@/pages/sites/SitesPage.vue'),
      meta: { titleKey: 'sites.title', permission: 'config:read' },
    },
    {
      path: '/sites/new',
      name: 'site-new',
      component: () => import('@/pages/sites/SiteCreatePage.vue'),
      meta: { titleKey: 'sites.newTitle', permission: 'config:write' },
    },
    {
      path: '/sites/:site',
      name: 'site-detail',
      component: () => import('@/pages/sites/SiteSettingsPage.vue'),
      meta: { titleKey: 'sites.detailTitle', permission: 'config:read' },
    },
    {
      path: '/sites/:site/endpoints',
      name: 'site-endpoints',
      component: () => import('@/pages/sites/SiteEndpointsPage.vue'),
      meta: { titleKey: 'sites.endpoints.title', permission: 'config:read' },
    },
    {
      path: '/sites/:site/endpoints/new',
      name: 'endpoint-new',
      component: () => import('@/pages/sites/EndpointFormPage.vue'),
      meta: { titleKey: 'sites.endpoints.newTitle', permission: 'config:write' },
    },
    {
      path: '/sites/:site/endpoints/:endpoint',
      name: 'endpoint-detail',
      component: () => import('@/pages/sites/EndpointFormPage.vue'),
      meta: { titleKey: 'sites.endpoints.editTitle', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'sites',
      to: '/sites',
      labelKey: 'nav.sites',
      icon: 'ti ti-world',
      order: 20,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
