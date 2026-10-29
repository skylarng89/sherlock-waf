// Merges the per-area message files. Each area owns exactly one file so parallel
// authors never edit the same one. Adding an area means adding one import here.
import access from './en/access'
import analytics from './en/analytics'
import audit from './en/audit'
import auth from './en/auth'
import bans from './en/bans'
import bot from './en/bot'
import certificates from './en/certificates'
import common from './en/common'
import defaults from './en/defaults'
import events from './en/events'
import history from './en/history'
import nav from './en/nav'
import overview from './en/overview'
import reports from './en/reports'
import setup from './en/setup'
import sites from './en/sites'
import system from './en/system'
import tokens from './en/tokens'
import users from './en/users'

export const en = {
  access,
  analytics,
  audit,
  auth,
  bans,
  bot,
  certificates,
  common,
  defaults,
  events,
  history,
  nav,
  overview,
  reports,
  setup,
  sites,
  system,
  tokens,
  users,
}

export const messages = { en }
