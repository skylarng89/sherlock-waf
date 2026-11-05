import { shallowRef, type Component } from 'vue'
import type { Router, RouteRecordRaw } from 'vue-router'
import type { NavItem } from '@/routes/types'

/**
 * Extension registry: how Enterprise (or any plug-in bundle) adds pages without
 * forking. Call the register functions before `app.mount`, from the entry point
 * that composes the bundle. Open-source code never imports Enterprise code.
 */

export interface SettingsPanel {
  id: string
  /** i18n key or literal text. */
  label: string
  component: Component | (() => Promise<Component>)
  permission?: string
  order?: number
}

const routes = shallowRef<RouteRecordRaw[]>([])
const navItems = shallowRef<NavItem[]>([])
const settingsPanels = shallowRef<SettingsPanel[]>([])
let boundRouter: Router | undefined

function assertUnique(kind: string, id: string, existing: readonly { id: string }[]) {
  if (existing.some((e) => e.id === id))
    throw new Error(`extension ${kind} "${id}" is already registered`)
}

/** Adds a page. Routes need a unique `name`; set `meta.permission` to gate them. */
export function registerRoute(route: RouteRecordRaw): void {
  if (!route.name) throw new Error('extension routes must have a name')
  if (routes.value.some((r) => r.name === route.name)) {
    throw new Error(`extension route "${String(route.name)}" is already registered`)
  }
  routes.value = [...routes.value, route]
  boundRouter?.addRoute(route)
}

export function registerNavItem(item: NavItem): void {
  assertUnique('nav item', item.id, navItems.value)
  navItems.value = [...navItems.value, item]
}

export function registerSettingsPanel(panel: SettingsPanel): void {
  assertUnique('settings panel', panel.id, settingsPanels.value)
  settingsPanels.value = [...settingsPanels.value, panel]
}

export const extensionRoutes = () => routes.value
export const extensionNavItems = navItems
export const extensionSettingsPanels = settingsPanels

/** Router creation calls this so routes registered earlier or later both land. */
export function bindRouter(router: Router): void {
  boundRouter = router
  for (const route of routes.value) router.addRoute(route)
}

/** Test-only reset. */
export function resetExtensions(): void {
  routes.value = []
  navItems.value = []
  settingsPanels.value = []
  boundRouter = undefined
}
