// Shared Vitest helpers. Import only from *.test.ts.
import { flushPromises, mount, type ComponentMountingOptions } from '@vue/test-utils'
import OpenVue from 'openvue/config'
import { createPinia, setActivePinia } from 'pinia'
import { afterEach } from 'vitest'
import type { Component } from 'vue'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { i18n } from '@/i18n'
import { SherlockPreset } from '@/openvue-theme'
import { createAppRouter } from '@/router'
import { builtinRoutes } from '@/routes'
import { useSessionStore, type Me } from '@/stores/session'

export const adminMe: Me = {
  id: 'u1',
  username: 'ada',
  role: 'admin',
  permissions: [
    'config:read',
    'config:write',
    'events:read',
    'audit:read',
    'users:manage',
    'tokens:own',
    'system:read',
  ],
  mfa_enabled: true,
}

export const viewerMe: Me = {
  id: 'u2',
  username: 'vic',
  role: 'viewer',
  permissions: ['config:read', 'events:read', 'tokens:own'],
  mfa_enabled: true,
}

const mounted: { unmount(): void }[] = []
// Unmount after every test so focus, document listeners and open dialogs never leak between tests.
afterEach(() => {
  mounted.splice(0).forEach((w) => w.unmount())
  document.body.innerHTML = ''
})

/** A fresh pinia plus the app router on memory history; call in beforeEach. */
export function freshApp(): Router {
  setActivePinia(createPinia())
  return createAppRouter(createMemoryHistory())
}

/** A router with the real route table but no guards: component tests do not need sign-in. */
export function plainRouter(): Router {
  return createRouter({ history: createMemoryHistory(), routes: builtinRoutes })
}

/**
 * Mounts a component with pinia, i18n, router and OpenVue; optionally signs in `me` first. */
export async function renderWithApp<T extends Component>(
  component: T,
  options: {
    router?: Router
    me?: Me
    props?: Record<string, unknown>
    slots?: ComponentMountingOptions<T>['slots']
    route?: string
  } = {},
) {
  if (!options.router) setActivePinia(createPinia())
  const router = options.router ?? plainRouter()
  if (options.me) useSessionStore().setMe(options.me)
  await router.push(options.route ?? '/')
  const wrapper = mount(component as Component, {
    props: options.props,
    slots: options.slots as never,
    attachTo: document.body,
    global: {
      plugins: [i18n, router, [OpenVue, { theme: { preset: SherlockPreset } }]],
    },
  })
  mounted.push(wrapper)
  await flushPromises()
  return { wrapper, router }
}
