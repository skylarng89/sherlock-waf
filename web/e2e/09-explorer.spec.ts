import { adminApi, expect, test } from './fixtures'
import { dataPlaneGet } from './lib/api'
import { expectAccessible } from './lib/axe'
import { Shell } from './pages/shell'

const MARKER = 'xssprobe9'
// Reaches the data plane URL-encoded so Node's HTTP client sends it; the dashboard must
// show whatever the server stored as text and never execute it.
const PAYLOAD_PATH = `/${MARKER}/%3Cimg%20src%3Dx%20onerror%3D%22window.__xss%3D1%22%3E`
const PAYLOAD_QUERY = `?q=%3Cscript%3Ewindow.__xss%3D2%3C%2Fscript%3E&sql=1%27%20OR%20%271%27%3D%271`
const PAYLOAD_UA = '<svg onload="window.__xss=3">'

interface EventsPage {
  items: { id: string }[]
}

async function seedHostileEvent(state: Parameters<typeof adminApi>[0]): Promise<string> {
  await dataPlaneGet(state.main.httpPort, state.main.siteHost, PAYLOAD_PATH + PAYLOAD_QUERY, {
    'User-Agent': PAYLOAD_UA,
  })
  const api = await adminApi(state)
  try {
    let id = ''
    await expect
      .poll(
        async () => {
          const page = await api.json<EventsPage>(await api.get(`/events?q=${MARKER}&limit=1`))
          id = page.items[0]?.id ?? ''
          return id
        },
        { message: 'the hostile event is stored', timeout: 30_000 },
      )
      .not.toBe('')
    return id
  } finally {
    await api.dispose()
  }
}

test.describe('attack explorer and event detail', () => {
  test('filters live in the URL and survive a reload', async ({ adminPage, state }) => {
    await seedHostileEvent(state)
    const shell = new Shell(adminPage)
    await shell.goto('/events', /^Attack explorer$/)
    await adminPage.getByLabel('Path or free text').fill(MARKER)
    await adminPage.getByLabel('Site').selectOption('demo')
    await adminPage.getByRole('button', { name: 'Apply filters' }).click()
    await expect(adminPage).toHaveURL(/q=xssprobe9/)
    await expect(adminPage).toHaveURL(/site=demo/)
    const table = adminPage.getByTestId('events-table')
    await expect(table.getByRole('row')).toHaveCount(2)

    await adminPage.reload()
    await shell.ready(/^Attack explorer$/)
    await expect(adminPage.getByLabel('Path or free text')).toHaveValue(MARKER)
    await expect(adminPage.getByTestId('events-table').getByRole('row')).toHaveCount(2)

    const pause = adminPage.getByRole('button', { name: 'Pause live updates' })
    await pause.click()
    await expect(adminPage.getByRole('button', { name: 'Resume live updates' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    await expect(adminPage.getByTestId('live-status')).toContainText('paused')
  })

  test('a hostile event is rendered as text and nothing executes', async ({ adminPage, state }) => {
    const id = await seedHostileEvent(state)
    const dialogs: string[] = []
    adminPage.on('dialog', (d) => {
      dialogs.push(d.message())
      void d.dismiss()
    })
    const shell = new Shell(adminPage)

    // The explorer table first, then the detail page.
    await shell.goto(`/events?q=${MARKER}`, /^Attack explorer$/)
    await expect(adminPage.getByTestId('events-table')).toContainText(MARKER)
    await shell.goto(`/events/${id}`, /^Event detail$/)
    const detail = adminPage.getByTestId('event-detail')
    await expect(detail).toBeVisible()
    await expect(detail.getByTestId('request-path')).toContainText('onerror')
    await expect(detail.getByTestId('request-header').filter({ hasText: 'onload' })).toHaveCount(1)

    expect(await detail.locator('img, svg[onload], script, [onerror], [onmouseover]').count()).toBe(
      0,
    )
    expect(await adminPage.evaluate(() => (window as { __xss?: unknown }).__xss)).toBeUndefined()
    expect(dialogs).toEqual([])
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`explorer, hostile detail and report pages pass axe, ${theme} theme`, async ({
      adminPage,
      state,
    }, testInfo) => {
      const id = await seedHostileEvent(state)
      const shell = new Shell(adminPage)
      await shell.goto('/events', /^Attack explorer$/)
      await shell.setTheme(theme)
      await expectAccessible(adminPage, testInfo, `explorer-filters-${theme}`)
      await shell.goto(`/events?q=${MARKER}`, /^Attack explorer$/)
      await expect(adminPage.getByTestId('events-table')).toBeVisible()
      await expectAccessible(adminPage, testInfo, `explorer-table-${theme}`)
      await shell.goto(`/events/${id}`, /^Event detail$/)
      await expect(adminPage.getByTestId('event-detail')).toBeVisible()
      await expectAccessible(adminPage, testInfo, `event-detail-${theme}`)
    })
  }
})

test.describe('analytics, would-block report and system', () => {
  test('analytics shows chart and table views', async ({ adminPage }, testInfo) => {
    const shell = new Shell(adminPage)
    await shell.goto('/analytics', /^Analytics$/)
    await expect(adminPage.getByTestId('top-rule')).toBeVisible()
    await adminPage
      .getByTestId('series-panel')
      .getByRole('button', { name: 'View as table' })
      .click()
    await expect(adminPage.getByTestId('series-panel').getByRole('table')).toBeVisible()
    await expectAccessible(adminPage, testInfo, 'analytics-table')
  })

  test('would-block report lists the detect-mode site and exports CSV', async ({
    adminPage,
    state,
  }) => {
    // One request the CRS flags; the demo site is in detect mode so it is only logged.
    await dataPlaneGet(state.main.httpPort, state.main.siteHost, '/?id=1%27%20OR%20%271%27=%271')
    const shell = new Shell(adminPage)
    await shell.goto('/reports/would-block', /^Would-block report$/)
    await expect(adminPage.getByLabel('Site')).toHaveValue('demo')
    await expect(adminPage.getByTestId('wb-total-count')).toBeVisible()
    const [download] = await Promise.all([
      adminPage.waitForEvent('download'),
      adminPage.getByRole('button', { name: 'Export CSV' }).click(),
    ])
    expect(download.suggestedFilename()).toMatch(/^would-block-demo-7d\.csv$/)
    // Do not click the real block switch: later specs rely on the demo site's mode.
    await expect(adminPage.getByRole('button', { name: 'Switch to block mode' })).toBeVisible()
  })

  test('system page shows version, storage and feeds', async ({ adminPage }) => {
    const shell = new Shell(adminPage)
    await shell.goto('/system', /^System$/)
    await expect(adminPage.getByTestId('sys-version')).not.toBeEmpty()
    await expect(adminPage.getByTestId('sys-disk')).not.toBeEmpty()
    await expect(adminPage.getByTestId('feeds-table')).toBeVisible()
  })
})
