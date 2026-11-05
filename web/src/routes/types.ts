import type { RouteRecordRaw } from 'vue-router'

declare module 'vue-router' {
  interface RouteMeta {
    /** `app` (default): sidebar shell. `auth`: centred card used by sign-in and setup. */
    layout?: 'app' | 'auth'
    /** Reachable without a session (login, setup). */
    public?: boolean
    /** Permission from `x-sherlock-permission` (e.g. `config:write`) required to enter. */
    permission?: string
    /** i18n key for the document title and the skip-link focus target. */
    titleKey?: string
    /** Auth layout only: use the wide card (setup wizard). */
    wide?: boolean
  }
}

export interface NavItem {
  id: string
  /** Router path the item links to. */
  to: string
  /** i18n key; extensions without translations may use `label` instead. */
  labelKey?: string
  label?: string
  /** Tabler icon classes, e.g. `ti ti-world`. */
  icon: string
  /** Hidden from users who lack it. */
  permission?: string
  /** Sort order within the sidebar (lower first). */
  order?: number
}

/** What one area exports from `src/routes/<area>.ts`. */
export interface AreaModule {
  routes: RouteRecordRaw[]
  nav: NavItem[]
}
