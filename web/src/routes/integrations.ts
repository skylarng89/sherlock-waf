import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/integrations/exporters',
      name: 'exporters',
      component: () => import('@/pages/integrations/ExportersPage.vue'),
      meta: { titleKey: 'integrations.exporters.title', permission: 'config:read' },
    },
    {
      path: '/integrations/channels',
      name: 'channels',
      component: () => import('@/pages/integrations/ChannelsPage.vue'),
      meta: { titleKey: 'integrations.channels.title', permission: 'config:read' },
    },
    {
      path: '/integrations/alerts',
      name: 'alerts',
      component: () => import('@/pages/integrations/AlertsPage.vue'),
      meta: { titleKey: 'integrations.alerts.title', permission: 'config:read' },
    },
  ],
  nav: [
    {
      id: 'exporters',
      to: '/integrations/exporters',
      labelKey: 'integrations.exporters.nav',
      icon: 'ti ti-send',
      order: 52,
      permission: 'config:read',
    },
    {
      id: 'channels',
      to: '/integrations/channels',
      labelKey: 'integrations.channels.nav',
      icon: 'ti ti-message-circle',
      order: 54,
      permission: 'config:read',
    },
    {
      id: 'alerts',
      to: '/integrations/alerts',
      labelKey: 'integrations.alerts.nav',
      icon: 'ti ti-bell-ringing',
      order: 56,
      permission: 'config:read',
    },
  ],
} satisfies AreaModule
