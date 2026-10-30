import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/sites/:site/tuning',
      name: 'site-tuning',
      component: () => import('@/pages/tuning/SiteTuningPage.vue'),
      meta: { titleKey: 'tuning.tuning.title', permission: 'config:read' },
    },
    {
      path: '/sites/:site/custom-rules',
      name: 'site-custom-rules',
      component: () => import('@/pages/tuning/CustomRulesPage.vue'),
      meta: { titleKey: 'tuning.customRules.title', permission: 'config:read' },
    },
    {
      path: '/crs-rules',
      name: 'crs-rules',
      component: () => import('@/pages/tuning/CrsRulesPage.vue'),
      meta: { titleKey: 'tuning.crs.title', permission: 'config:read' },
    },
    {
      path: '/virtual-patches',
      name: 'virtual-patches',
      component: () => import('@/pages/tuning/VirtualPatchesPage.vue'),
      meta: { titleKey: 'tuning.vp.title', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'crs-rules',
      to: '/crs-rules',
      labelKey: 'nav.crsRules',
      icon: 'ti ti-list-search',
      order: 43,
      permission: 'config:read',
    },
    {
      id: 'virtual-patches',
      to: '/virtual-patches',
      labelKey: 'nav.virtualPatches',
      icon: 'ti ti-shield-bolt',
      order: 47,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
