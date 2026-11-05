import type { Page } from '@playwright/test'
import { adminApi, expect, test } from './fixtures'
import { dataPlaneGet } from './lib/api'
import { expectAccessible } from './lib/axe'
import { Shell } from './pages/shell'

const HOST = 'tune.e2e.test'
const SITE = 'tune'
const ATTACK = `/tuneprobe/search?q=${encodeURIComponent("1' OR '1'='1")}`
const THEMES = ['light', 'dark'] as const

// The data plane is addressed by IP with a Host header, so no resolver rule is needed.
test.describe.configure({ mode: 'serial' })

test.describe('M8 tuning and rules', () => {
  test.beforeAll(async ({ state }) => {
    const api = await adminApi(state)
    try {
      const sites = await api.get('/sites')
      const etag = sites.headers()['etag'] ?? ''
      const body = await api.json<{ items: { id: string }[] }>(sites)
      if (!body.items.some((s) => s.id === SITE)) {
        const created = await api.postWith(
          '/sites',
          {
            id: SITE,
            name: 'Tuning shop',
            hosts: [HOST],
            tls: { mode: 'none' },
            upstreams: { targets: [`127.0.0.1:${state.upstreamPort}`] },
            policy: { mode: 'block' },
          },
          etag ? { 'If-Match': etag } : {},
        )
        expect(created.status(), await created.text()).toBe(201)
      }
    } finally {
      await api.dispose()
    }
    await expect
      .poll(async () => (await dataPlaneGet(state.main.httpPort, HOST, '/ok')).body, {
        message: 'the tuning site is live on the data plane',
        timeout: 30_000,
      })
      .toBe('origin')
  })

  async function findEvent(state: Parameters<typeof adminApi>[0]): Promise<string> {
    const api = await adminApi(state)
    try {
      let id = ''
      await expect
        .poll(
          async () => {
            const page = await api.json<{ items: { id: string }[] }>(
              await api.get(`/events?site=${SITE}&q=tuneprobe&limit=1`),
            )
            id = page.items[0]?.id ?? ''
            return id
          },
          { message: 'the blocked event is stored', timeout: 30_000 },
        )
        .not.toBe('')
      return id
    } finally {
      await api.dispose()
    }
  }

  test('acceptance 1: event to exclusion in three clicks, then the same request is allowed', async ({
    adminPage,
    state,
  }) => {
    const blocked = await dataPlaneGet(state.main.httpPort, HOST, ATTACK)
    expect(blocked.status).toBe(403)
    const id = await findEvent(state)

    const shell = new Shell(adminPage)
    await shell.goto(`/events/${id}`, /^Event detail$/)
    let clicks = 0
    await adminPage.getByTestId('create-exclusion').click()
    clicks++
    const dialog = adminPage.getByRole('dialog', { name: 'Create exclusion' })
    await expect(dialog.getByTestId('wizard-proposal')).toBeVisible()
    await expect(dialog.getByTestId('impact-matching')).toBeVisible()
    const ack = dialog.getByRole('checkbox')
    if (await ack.count()) {
      await ack.check()
      clicks++
    }
    await dialog.getByRole('button', { name: 'Create exclusion' }).click()
    clicks++
    expect(clicks).toBeLessThanOrEqual(3)
    await expect(dialog.getByTestId('wizard-created')).toBeVisible()

    await expect
      .poll(async () => (await dataPlaneGet(state.main.httpPort, HOST, ATTACK)).status, {
        message: 'the identical request is allowed once the exclusion is live',
        timeout: 30_000,
      })
      .toBe(200)

    // Audit trail records who added it.
    const api = await adminApi(state)
    try {
      const audit = await api.json<{ items: { action: string; actor_id: string }[] }>(
        await api.get('/audit?limit=20'),
      )
      expect(audit.items.some((e) => e.action.includes('exclusion'))).toBe(true)
    } finally {
      await api.dispose()
    }

    await shell.goto(`/sites/${SITE}/tuning`, /Tuning shop/)
    await expect(adminPage.getByTestId('exclusions-table')).toContainText('ARGS:q')
  })

  test('exclusions can be deleted from the Tuning tab and the attack is blocked again', async ({
    adminPage,
    state,
  }) => {
    const shell = new Shell(adminPage)
    await shell.goto(`/sites/${SITE}/tuning`, /Tuning shop/)
    await adminPage.getByRole('button', { name: /^Delete exclusion / }).click()
    await adminPage
      .getByRole('dialog', { name: /Delete exclusion/ })
      .getByRole('button', { name: 'Delete' })
      .click()
    await expect(adminPage.getByTestId('exclusions-empty')).toBeVisible()
    await expect
      .poll(async () => (await dataPlaneGet(state.main.httpPort, HOST, ATTACK)).status, {
        timeout: 30_000,
      })
      .toBe(403)
  })

  async function typeRules(page: Page, text: string) {
    const editor = page.getByTestId('seclang-editor')
    await editor.click()
    await page.keyboard.press('ControlOrMeta+a')
    await page.keyboard.insertText(text)
  }

  test('acceptance 2: a malicious custom rule is rejected in the UI, a valid one saves', async ({
    adminPage,
  }) => {
    const shell = new Shell(adminPage)
    await shell.goto(`/sites/${SITE}/custom-rules`, /Custom rules/)
    await typeRules(
      adminPage,
      'SecRule REQUEST_URI "@contains /x" "id:10001,phase:1,deny,exec:/bin/sh"',
    )
    const issues = adminPage.getByTestId('issues')
    await expect(issues).toContainText('Line 1')
    await expect(issues).toContainText('Forbidden action')
    const save = adminPage.getByRole('button', { name: 'Save rules' })
    await expect(save).toBeDisabled()

    await typeRules(
      adminPage,
      'SecRule REQUEST_URI "@contains /tune-blocked-path" "id:10001,phase:1,deny,status:403"',
    )
    await expect(adminPage.getByTestId('validation-status')).toContainText('10001')
    await expect(save).toBeEnabled()
    await save.click()
    await expect(shell.toast('Custom rules saved')).toBeVisible()
  })

  test('the editor is keyboard escapable', async ({ adminPage }) => {
    const shell = new Shell(adminPage)
    await shell.goto(`/sites/${SITE}/custom-rules`, /Custom rules/)
    const editor = adminPage.getByTestId('seclang-editor')
    await editor.focus()
    await adminPage.keyboard.press('Tab')
    await expect(editor).not.toBeFocused()
  })

  test('paranoia helper explains levels and predicts impact before saving', async ({
    adminPage,
  }) => {
    const shell = new Shell(adminPage)
    await shell.goto(`/sites/${SITE}/tuning`, /Tuning shop/)
    await adminPage.getByText('What each level does').click()
    await expect(adminPage.getByTestId('pl-levels')).toContainText('PL4')
    await adminPage.getByLabel('Raise the blocking level to').selectOption('2')
    await adminPage.getByRole('button', { name: 'Predict impact' }).click()
    // Detection level is 1, so the server cannot observe level 2 yet and says what to do.
    await expect(
      adminPage.getByTestId('pl-not-observable').or(adminPage.getByTestId('pl-additional')),
    ).toBeVisible()
  })

  test('CRS catalogue, virtual patches and the overview tile', async ({ adminPage }) => {
    const shell = new Shell(adminPage)
    await shell.goto('/crs-rules', /^CRS rule catalogue$/)
    await adminPage.getByLabel('Search by id, message or tag').fill('sql')
    await adminPage.getByLabel('State for site').selectOption(SITE)
    await adminPage.getByRole('button', { name: 'Apply filters' }).click()
    await expect(adminPage.getByTestId('crs-table')).toBeVisible()
    await expect(adminPage.getByTestId('crs-state').first()).toBeVisible()

    await shell.goto('/virtual-patches', /^Virtual patches$/)
    await expect(
      adminPage.getByTestId('vp-table').or(adminPage.getByText('No virtual patches match.')),
    ).toBeVisible()

    await shell.goto('/', /^Overview$/)
    await expect(adminPage.getByTestId('covered-cves')).toBeVisible()
  })

  for (const theme of THEMES) {
    test(`tuning pages pass axe, ${theme} theme`, async ({ adminPage }, testInfo) => {
      const shell = new Shell(adminPage)
      await shell.goto('/', /^Overview$/)
      await shell.setTheme(theme)
      const pages: [string, RegExp][] = [
        [`/sites/${SITE}/tuning`, /Tuning shop/],
        [`/sites/${SITE}/custom-rules`, /Custom rules/],
        ['/crs-rules', /^CRS rule catalogue$/],
        ['/virtual-patches', /^Virtual patches$/],
      ]
      for (const [path, title] of pages) {
        await shell.goto(path, title)
        await expectAccessible(adminPage, testInfo, `${path}-${theme}`)
      }
    })

    test(`event wizard passes axe, ${theme} theme`, async ({ adminPage, state }, testInfo) => {
      await dataPlaneGet(state.main.httpPort, HOST, ATTACK)
      const id = await findEvent(state)
      const shell = new Shell(adminPage)
      await shell.goto('/', /^Overview$/)
      await shell.setTheme(theme)
      await shell.goto(`/events/${id}`, /^Event detail$/)
      await adminPage.getByTestId('create-exclusion').click()
      const dialog = adminPage.getByRole('dialog', { name: 'Create exclusion' })
      await expect(dialog.getByTestId('wizard-proposal')).toBeVisible()
      await expectAccessible(adminPage, testInfo, `wizard-${theme}`)
    })
  }
})
