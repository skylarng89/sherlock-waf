import { createMemoryHistory, createRouter } from 'vue-router'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  bindRouter,
  extensionNavItems,
  extensionRoutes,
  extensionSettingsPanels,
  registerNavItem,
  registerRoute,
  registerSettingsPanel,
  resetExtensions,
} from './extensions'

const Page = { template: '<div />' }

describe('extensions registry', () => {
  beforeEach(resetExtensions)

  it('adds a route to a bound router, whether registered before or after binding', () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [] })
    registerRoute({ path: '/early', name: 'early', component: Page })
    bindRouter(router)
    registerRoute({ path: '/late', name: 'late', component: Page })
    expect(router.hasRoute('early')).toBe(true)
    expect(router.hasRoute('late')).toBe(true)
    expect(extensionRoutes()).toHaveLength(2)
  })

  it('requires named, unique routes', () => {
    expect(() => registerRoute({ path: '/x', component: Page })).toThrow(/name/)
    registerRoute({ path: '/x', name: 'x', component: Page })
    expect(() => registerRoute({ path: '/y', name: 'x', component: Page })).toThrow(/already/)
  })

  it('registers nav items and settings panels with unique ids', () => {
    registerNavItem({
      id: 'sso',
      to: '/sso',
      label: 'SSO',
      icon: 'ti ti-key',
      permission: 'users:manage',
    })
    expect(extensionNavItems.value.map((n) => n.id)).toEqual(['sso'])
    expect(() => registerNavItem({ id: 'sso', to: '/', icon: 'ti' })).toThrow(/already/)

    registerSettingsPanel({ id: 'siem', label: 'SIEM', component: Page })
    expect(extensionSettingsPanels.value).toHaveLength(1)
    expect(() => registerSettingsPanel({ id: 'siem', label: 'again', component: Page })).toThrow(
      /already/,
    )
  })
})
