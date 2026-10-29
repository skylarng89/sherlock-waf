import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/certificates',
      name: 'certificates',
      component: () => import('@/pages/certificates/CertificatesPage.vue'),
      meta: { titleKey: 'certificates.title', permission: 'config:read' },
    },
    {
      path: '/certificates/block-pages',
      name: 'block-pages',
      component: () => import('@/pages/certificates/BlockPagesPage.vue'),
      meta: { titleKey: 'certificates.blockPages.title', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'certificates',
      to: '/certificates',
      labelKey: 'nav.certificates',
      icon: 'ti ti-certificate',
      order: 40,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
