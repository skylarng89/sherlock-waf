import { adminApi, expect, test } from './fixtures'
import { dataPlaneGet } from './lib/api'
import { expectAccessible } from './lib/axe'
import { CONTEXT_OPTIONS } from './lib/context'

const HOST = 'bot.e2e.test'
const PROTECTED = '/protected/area'

// The browser reaches the data plane by hostname, so the site's Host header is real.
test.use({ launchOptions: { args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1`] } })

test.describe.configure({ mode: 'serial' })

test.describe('bot defence: proof-of-work challenge', () => {
  test.beforeAll(async ({ state }) => {
    const api = await adminApi(state)
    try {
      const sites = await api.get('/sites')
      const etag = sites.headers()['etag'] ?? ''
      const body = await api.json<{ items: { id: string }[] }>(sites)
      if (!body.items.some((s) => s.id === 'botshop')) {
        const created = await api.postWith(
          '/sites',
          {
            id: 'botshop',
            name: 'Bot shop',
            hosts: [HOST],
            tls: { mode: 'none' },
            upstreams: { targets: [`127.0.0.1:${state.upstreamPort}`] },
            policy: {
              mode: 'detect',
              bot: {
                enabled: true,
                challenge: 'pow',
                rules: [{ match: { paths: ['/protected/*'] }, action: 'challenge' }],
              },
            },
          },
          etag ? { 'If-Match': etag } : {},
        )
        expect(created.status(), await created.text()).toBe(201)
      }
    } finally {
      await api.dispose()
    }
    await expect
      .poll(async () => (await dataPlaneGet(state.main.httpPort, HOST, '/open')).body, {
        message: 'the bot site is live on the data plane',
        timeout: 30_000,
      })
      .toBe('origin')
  })

  test('a client without JavaScript is challenged and gets no clearance', async ({ state }) => {
    const res = await dataPlaneGet(state.main.httpPort, HOST, PROTECTED, { Accept: 'text/html' })
    expect(res.status).toBe(403)
    expect(res.body).toContain('JavaScript is required')
    expect(res.headers['set-cookie']).toBeUndefined()
    const api = await dataPlaneGet(state.main.httpPort, HOST, PROTECTED, {
      Accept: 'application/json',
    })
    expect(api.status).toBe(403)
    expect(api.body).not.toContain('<html')
  })

  test('a real browser solves the challenge quickly and is then let through', async ({
    browser,
    state,
  }) => {
    const context = await browser.newContext({ ...CONTEXT_OPTIONS })
    const page = await context.newPage()
    const url = `http://${HOST}:${state.main.httpPort}${PROTECTED}`
    const started = Date.now()
    await page.goto(url)
    await expect(page.locator('body')).toHaveText('origin', { timeout: 15_000 })
    const elapsed = Date.now() - started
    test.info().annotations.push({ type: 'pow-solve-ms', description: String(elapsed) })
    console.log(`[pow] solved and redirected in ${elapsed} ms`)
    // Acceptance criterion: under 2 s at the default difficulty.
    expect(elapsed).toBeLessThan(2_000)

    // The clearance cookie lets the next request straight through, without a new challenge.
    const again = await page.goto(url)
    expect(again?.status()).toBe(200)
    await expect(page.locator('body')).toHaveText('origin')

    // The same cookie sent by another client (a different user agent) is not accepted.
    const cookies = await context.cookies()
    const clearance = cookies.map((c) => `${c.name}=${c.value}`).join('; ')
    expect(clearance).not.toBe('')
    const other = await dataPlaneGet(state.main.httpPort, HOST, PROTECTED, {
      'User-Agent': 'curl/8',
      Accept: 'text/html',
      Cookie: clearance,
    })
    expect(other.status).toBe(403)
    await context.close()
  })

  test('the outcome is counted for the overview', async ({ state }) => {
    const api = await adminApi(state)
    try {
      await expect
        .poll(
          async () => {
            const to = new Date().toISOString()
            const from = new Date(Date.now() - 3_600_000).toISOString()
            const top = await api.json<{ items: { value: string; count: number }[] }>(
              await api.get(`/stats/top?dim=rule&limit=100&from=${from}&to=${to}`),
            )
            return top.items.find((i) => i.value === 'challenge-passed')?.count ?? 0
          },
          { timeout: 30_000 },
        )
        .toBeGreaterThan(0)
    } finally {
      await api.dispose()
    }
  })

  for (const scheme of ['light', 'dark'] as const) {
    test(`the challenge page passes axe, ${scheme} scheme`, async ({
      browser,
      state,
    }, testInfo) => {
      const url = `http://${HOST}:${state.main.httpPort}${PROTECTED}`
      // Script blocked: the page stays in its "working" state with the live status region.
      const working = await browser.newContext({ ...CONTEXT_OPTIONS, colorScheme: scheme })
      const page = await working.newPage()
      await page.route('**/.sherlock/challenge.js', (route) => route.abort())
      await page.goto(url)
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Checking your browser')
      const status = page.getByRole('status')
      await expect(status).toHaveText('Working on the check')
      await expect(status).toHaveAttribute('aria-live', 'polite')
      await expectAccessible(page, testInfo, `challenge-working-${scheme}`)
      await working.close()

      // JavaScript off: the explanation must be served.
      const bare = await browser.newContext({
        ...CONTEXT_OPTIONS,
        colorScheme: scheme,
        javaScriptEnabled: false,
      })
      const noJs = await bare.newPage()
      const res = await noJs.goto(url)
      // Playwright reports <noscript> content as empty text, so check the served markup.
      expect(await res?.text()).toContain('JavaScript is required')
      await expect(noJs.getByRole('heading', { level: 1 })).toHaveText('Checking your browser')
      // axe itself needs scripting, so the no-JS variant is checked for content only.
      await bare.close()
    })
  }
})
