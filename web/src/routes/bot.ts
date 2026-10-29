import type { AreaModule } from './types'

export default {
  routes: [
    {
      path: '/sites/:site/bot',
      name: 'site-bot',
      component: () => import('@/pages/bot/SiteBotPage.vue'),
      meta: { titleKey: 'bot.title', permission: 'config:read' },
    },
  ],
  nav: [],
} satisfies AreaModule
