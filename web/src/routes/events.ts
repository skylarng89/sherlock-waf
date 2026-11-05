import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/events',
      name: 'events',
      component: () => import('@/pages/events/EventsPage.vue'),
      meta: { titleKey: 'events.title', permission: 'events:read' },
    },
    {
      path: '/events/:id',
      name: 'event-detail',
      component: () => import('@/pages/events/EventDetailPage.vue'),
      meta: { titleKey: 'events.detailTitle', permission: 'events:read' },
    },
  ],
  nav: [
    {
      id: 'events',
      to: '/events',
      labelKey: 'nav.events',
      icon: 'ti ti-radar-2',
      order: 42,
      permission: 'events:read',
    },
  ],
} satisfies AreaModule
