import { expect, test } from './fixtures'
import { observe } from './lib/guards'
import { Shell } from './pages/shell'

const PAGES = [
  '/',
  '/sites',
  '/sites/new',
  '/sites/demo',
  '/sites/demo/endpoints',
  '/defaults',
  '/certificates',
  '/certificates/block-pages',
  '/history',
  '/audit',
  '/users',
  '/tokens',
  '/sites/demo/bot',
  '/events',
  '/analytics',
  '/reports/would-block',
  '/system',
]

test.describe('CSP and network isolation @smoke', () => {
  test('signed-in pages load only same-origin, under default-src self, without violations', async ({
    adminPage,
    state,
  }) => {
    const origin = new URL(state.main.baseURL).origin
    const seen = await observe(adminPage, origin)
    const shell = new Shell(adminPage)
    for (const path of PAGES) {
      await shell.goto(path)
    }
    // Light and dark exercise different stylesheets and chart palettes.
    await shell.setTheme('dark')
    await shell.goto('/')

    expect.soft(seen.foreignRequests, 'requests to other origins').toEqual([])
    expect.soft(seen.missingCsp, 'responses without default-src self').toEqual([])
    expect.soft(seen.consoleProblems, 'console errors / CSP violations').toEqual([])
    expect.soft(seen.pageErrors, 'uncaught page errors').toEqual([])
  })

  test('the CSP header has no unsafe script sources', async ({ adminPage }) => {
    const res = await adminPage.request.get('/')
    const csp = res.headers()['content-security-policy'] ?? ''
    expect(csp).toContain("default-src 'self'")
    const scriptSrc = csp.split(';').find((d) => d.trim().startsWith('script-src')) ?? ''
    expect(scriptSrc).not.toContain('unsafe-inline')
    expect(scriptSrc).not.toContain('unsafe-eval')
    expect(csp).not.toMatch(/default-src[^;]*unsafe-/)
  })
})
