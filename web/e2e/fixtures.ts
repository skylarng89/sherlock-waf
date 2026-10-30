import { test as base, type BrowserContext, type Page } from '@playwright/test'
import { ApiClient } from './lib/api'
import { CONTEXT_OPTIONS } from './lib/context'
import { readState, type E2EState } from './lib/state'

interface Fixtures {
  state: E2EState
  /** A page signed in as the bootstrapped administrator of the shared node. */
  adminPage: Page
  adminContext: BrowserContext
  /** An unauthenticated context on the shared node. */
  anonPage: Page
}

export const test = base.extend<Fixtures>({
  // eslint-disable-next-line no-empty-pattern
  state: async ({}, use) => use(readState()),
  baseURL: async ({ state }, use) => use(state.main.baseURL),
  adminContext: async ({ browser, state }, use) => {
    const context = await browser.newContext({
      ...CONTEXT_OPTIONS,
      baseURL: state.main.baseURL,
      storageState: state.main.storageState,
    })
    await use(context)
    await context.close()
  },
  adminPage: async ({ adminContext }, use) => use(await adminContext.newPage()),
  anonPage: async ({ browser, state }, use) => {
    const context = await browser.newContext({ ...CONTEXT_OPTIONS, baseURL: state.main.baseURL })
    await use(await context.newPage())
    await context.close()
  },
})

export { expect } from '@playwright/test'

/** Authenticated API client for the shared node, reusing the admin session cookies. */
export function adminApi(state: E2EState): Promise<ApiClient> {
  return ApiClient.create(state.main.baseURL, state.main.storageState)
}
