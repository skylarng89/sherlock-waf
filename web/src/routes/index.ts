import type { RouteRecordRaw } from 'vue-router'
import access from './access'
import analytics from './analytics'
import api from './api'
import audit from './audit'
import auth from './auth'
import bans from './bans'
import bot from './bot'
import certificates from './certificates'
import defaults from './defaults'
import events from './events'
import history from './history'
import overview from './overview'
import reports from './reports'
import setup from './setup'
import sites from './sites'
import system from './system'
import tokens from './tokens'
import tuning from './tuning'
import type { AreaModule, NavItem } from './types'
import users from './users'

/** One module per area; a new area adds one import and one array entry here. */
const areas: AreaModule[] = [
  auth,
  overview,
  sites,
  defaults,
  certificates,
  history,
  audit,
  users,
  tokens,
  setup,
  access,
  bans,
  bot,
  api,
  events,
  tuning,
  analytics,
  reports,
  system,
]

const shared: RouteRecordRaw[] = [
  {
    path: '/403',
    name: 'forbidden',
    component: () => import('@/pages/system/ForbiddenPage.vue'),
    meta: { titleKey: 'common.forbiddenPage.title' },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/pages/system/NotFoundPage.vue'),
    meta: { titleKey: 'common.notFoundPage.title' },
  },
]

export const builtinRoutes: RouteRecordRaw[] = [...areas.flatMap((a) => a.routes), ...shared]
export const builtinNav: NavItem[] = areas.flatMap((a) => a.nav)
