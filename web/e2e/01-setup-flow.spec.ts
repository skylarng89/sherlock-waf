import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { dataPlaneGet } from './lib/api'
import { CONTEXT_OPTIONS } from './lib/context'
import { expectAccessible } from './lib/axe'
import { nextTotp } from './lib/mfa'
import { readState } from './lib/state'
import { EnrolPage } from './pages/auth'
import { Shell } from './pages/shell'
import { SetupPage, WizardPage } from './pages/wizard'

// The milestone's main flow, run against a node that has never been set up. Serial: each
// step depends on the previous one's state, and the node is touched by no other spec.
test.describe.configure({ mode: 'serial' })

test.describe('setup wizard to protected site @flow @slow', () => {
  const state = readState()
  let context: BrowserContext
  let page: Page

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ ...CONTEXT_OPTIONS, baseURL: state.flow.baseURL })
    page = await context.newPage()
  })

  test.afterAll(async () => {
    await context.close()
  })

  test('the first-run page is accessible in both themes', async ({ browserName }, testInfo) => {
    await page.goto('/')
    await expect(page).toHaveURL(/\/setup$/)
    const shell = new Shell(page)
    await shell.ready('First-run setup')
    expect(browserName).toBe('chromium')
    for (const theme of ['light', 'dark'] as const) {
      await shell.setTheme(theme)
      await expectAccessible(page, testInfo, `setup-${theme}`)
    }
    await shell.setTheme('light')
  })

  test('a wrong token is rejected next to the token field', async () => {
    const setup = new SetupPage(page)
    await setup.createAdmin('0'.repeat(32), 'e2e-owner', 'a very long passphrase 42')
    await expect(setup.token).toHaveAttribute('aria-invalid', 'true')
    await expect(page.getByText('That setup token is not correct.')).toBeVisible()
    await expect(page).toHaveURL(/\/setup$/)
  })

  test('first start to a blocking, protected site', async ({ browserName }, testInfo) => {
    expect(browserName).toBe('chromium')
    const started = Date.now()
    const username = 'e2e-owner'
    const password = 'a very long passphrase 42'

    await test.step('create the administrator with the one-time token', async () => {
      await new SetupPage(page).createAdmin(state.flow.setupToken, username, password)
      await expect(page).toHaveURL(/\/login\/enrol/)
    })

    let totpSecret = ''
    await test.step('enrol an authenticator (secret and QR are shown)', async () => {
      const enrol = new EnrolPage(page)
      totpSecret = await enrol.secret()
      await enrol.confirm(await nextTotp(state.root, totpSecret))
      await expect(page).toHaveURL(/\/welcome$/)
    })

    const wizard = new WizardPage(page)
    await test.step('skip the admin hostname', () => wizard.skipAdminHostname())

    await test.step('add the first site with a successful connectivity test', () =>
      wizard.addFirstSite({
        name: 'Flow shop',
        host: 'flow.e2e.test',
        target: `127.0.0.1:${state.upstreamPort}`,
      }))

    await test.step('open the site and switch it to block after confirming', async () => {
      await page.getByRole('link', { name: 'Go to sites' }).click()
      await page.getByRole('link', { name: 'Flow shop' }).click()
      const shell = new Shell(page)
      await shell.ready('Flow shop')
      await expect(page.getByRole('region', { name: 'Enforcement mode' })).toContainText('Detect')
      await page.getByLabel('Change mode').selectOption('block')
      const dialog = page.getByRole('dialog', { name: 'Switch Flow shop to block mode?' })
      await expect(dialog).toBeVisible()
      await dialog.getByRole('button', { name: 'Switch to block' }).click()
      await expect(shell.toast('Mode set to block.')).toBeVisible()
      await expect(page.getByRole('region', { name: 'Enforcement mode' })).toContainText('Block')
    })

    let eventId = ''
    await test.step('the data plane proxies benign and blocks SQL injection', async () => {
      await expect
        .poll(async () => (await dataPlaneGet(state.flow.httpPort, 'flow.e2e.test', '/')).body, {
          message: 'benign request reaches the origin',
          timeout: 30_000,
        })
        .toBe('origin')

      // The new mode is applied asynchronously: poll until the attack is refused.
      await expect
        .poll(
          async () => {
            const res = await dataPlaneGet(
              state.flow.httpPort,
              'flow.e2e.test',
              '/?id=1%27%20OR%20%271%27=%271',
            )
            eventId = res.headers['x-sherlock-event-id'] ?? ''
            return res.status
          },
          { message: 'SQL injection is blocked', timeout: 30_000 },
        )
        .toBe(403)
      expect(eventId).not.toBe('')
    })

    await test.step('the blocked event is visible through the authenticated API', async () => {
      await expect
        .poll(
          async () => {
            const res = await page.request.get('/api/v1/events?action=block&limit=50')
            if (!res.ok()) return `status ${res.status()}`
            const body = (await res.json()) as { items: { id: string }[] }
            return body.items.some((e) => e.id === eventId)
          },
          { message: `event ${eventId} listed`, timeout: 30_000 },
        )
        .toBe(true)
    })

    await test.step('the Overview chart gains data once rollups catch up', async () => {
      const shell = new Shell(page)
      const toggle = page.getByRole('button', { name: 'View as table' })
      // The toggle only exists once the chart is populated; reload until rollups land.
      await expect(async () => {
        await page.goto('/')
        await shell.ready('Overview')
        await expect(toggle).toBeVisible({ timeout: 3_000 })
      }).toPass({ timeout: 90_000, intervals: [1_000, 2_000, 5_000] })
      await toggle.click()
      const table = page.getByRole('table', { name: 'Requests by action per time bucket' })
      await expect(table.locator('tbody tr').first()).toBeVisible()
    })

    const elapsed = Math.round((Date.now() - started) / 1000)
    testInfo.annotations.push({ type: 'elapsed', description: `${elapsed}s` })
    console.log(`[e2e] setup wizard to blocked attack took ${elapsed}s (automated, informational)`)
  })
})
