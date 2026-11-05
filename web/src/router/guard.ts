import type { RouteLocationNormalized, RouteLocationRaw, Router } from 'vue-router'
import { setUnauthorizedHandler } from '@/api/client'
import { i18n } from '@/i18n'
import { useSessionStore } from '@/stores/session'

/** Accepts only same-origin absolute paths, so `?redirect=` cannot bounce users off-site. */
export function safeRedirect(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return undefined
  if (/^\/(login|setup)(\/|\?|$)/.test(value)) return undefined
  return value
}

const MFA_ROUTES = new Set(['login-mfa', 'login-enrol'])

async function decide(to: RouteLocationNormalized): Promise<RouteLocationRaw | true> {
  const session = useSessionStore()
  if (session.status === 'unknown') await session.fetchMe()
  if (session.status === 'anonymous' && session.setupRequired === null) {
    await session.fetchSetupStatus()
  }

  if (session.status === 'anonymous' && session.setupRequired) {
    return to.name === 'setup' ? true : { name: 'setup' }
  }
  if (to.name === 'setup' && session.setupRequired !== true) {
    return session.status === 'authenticated' ? { name: 'overview' } : { name: 'login' }
  }

  if (session.status === 'partial') {
    if (MFA_ROUTES.has(String(to.name))) return true
    return { name: session.mfaStep === 'enrol' ? 'login-enrol' : 'login-mfa' }
  }

  if (session.status === 'anonymous') {
    if (to.meta.public && !MFA_ROUTES.has(String(to.name))) return true
    if (to.name === 'login-mfa' || to.name === 'login-enrol') return { name: 'login' }
    const redirect = safeRedirect(to.fullPath)
    return { name: 'login', query: redirect ? { redirect } : {} }
  }

  // Authenticated.
  if (to.meta.public) {
    return { path: safeRedirect(to.query.redirect) ?? '/' }
  }
  if (!session.can(to.meta.permission)) {
    return { name: 'forbidden', query: { from: to.fullPath } }
  }
  return true
}

export function installGuards(router: Router): void {
  router.beforeEach((to) => decide(to))
  router.afterEach((to) => {
    const key = to.meta.titleKey
    const name = i18n.global.t('common.appName')
    document.title = key ? `${i18n.global.t(key)} - ${name}` : name
  })
}

/**
 * Any 401 outside the sign-in flow means the session ended: clear it and send the
 * user to /login with a notice and the page they were on.
 */
export function installSessionExpiry(router: Router): void {
  setUnauthorizedHandler(() => {
    const session = useSessionStore()
    if (session.status === 'anonymous' && router.currentRoute.value.name === 'login') return
    session.expire()
    const redirect = safeRedirect(router.currentRoute.value.fullPath)
    void router.replace({
      name: 'login',
      query: { expired: '1', ...(redirect ? { redirect } : {}) },
    })
  })
}
