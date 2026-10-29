// Merges the per-area message files. Each area owns exactly one file so parallel
// authors never edit the same one. Adding an area means adding one import here.
import access from './en/access'
import audit from './en/audit'
import auth from './en/auth'
import bans from './en/bans'
import certificates from './en/certificates'
import common from './en/common'
import defaults from './en/defaults'
import history from './en/history'
import nav from './en/nav'
import overview from './en/overview'
import setup from './en/setup'
import sites from './en/sites'
import tokens from './en/tokens'
import users from './en/users'

export const en = {
  access,
  audit,
  auth,
  bans,
  certificates,
  common,
  defaults,
  history,
  nav,
  overview,
  setup,
  sites,
  tokens,
  users,
}

export const messages = { en }
